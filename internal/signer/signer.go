package signer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	czertainlyissuerapi "github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/api/v1alpha1"
	"github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/internal/controllers"
	"github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/internal/signer/czertainly"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	corev1 "k8s.io/api/core/v1"
	"net/http"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"strings"
	"time"
)

type czertainlySigner struct {
	httpClient    *czertainly.APIClient
	apiUrl        string
	raProfileUuid string
	raProfileName string
}

func CzertainlyHealthCheckerFromIssuerAndSecretData(ctx context.Context, issuerSpec *czertainlyissuerapi.IssuerSpec, authSecret corev1.Secret, caBundleSecretData map[string][]byte) (controllers.HealthChecker, error) {
	// l := log.FromContext(ctx)
	czertainlySigner := czertainlySigner{}

	czertainlyConfig := czertainly.NewConfiguration()

	czertainlyConfig.Servers = czertainly.ServerConfigurations{
		{URL: issuerSpec.ApiUrl},
	}

	client, err := createHttpClient(ctx, issuerSpec, authSecret, caBundleSecretData)
	if err != nil {
		return nil, err
	}

	czertainlyConfig.HTTPClient = client

	czertainlySigner.httpClient = czertainly.NewAPIClient(czertainlyConfig)

	return &czertainlySigner, nil
}

func createHttpClient(ctx context.Context, issuerSpec *czertainlyissuerapi.IssuerSpec, authSecret corev1.Secret, caBundleSecretData map[string][]byte) (*http.Client, error) {
	tlsConfig := &tls.Config{}

	if len(caBundleSecretData) > 0 {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caBundleSecretData["ca.crt"])
		tlsConfig.RootCAs = caCertPool
	}

	switch authSecret.Type {
	case corev1.SecretTypeTLS:
		// mTLS client
		cert, err := tls.X509KeyPair(authSecret.Data["tls.crt"], authSecret.Data["tls.key"])
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		// Use the standard transport but inject our TLS configuration
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
			Timeout: time.Second * 10,
		}
		return client, nil

	case corev1.SecretTypeOpaque:
		// OAuth2 client credentials
		clientID := string(authSecret.Data["client_id"])
		clientSecret := string(authSecret.Data["client_secret"])
		tokenURL := string(authSecret.Data["token_url"])
		scopes := strings.Split(string(authSecret.Data["scopes"]), " ")

		clientCredentialsConfig := &clientcredentials.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     tokenURL,
			Scopes:       scopes,
		}

		tokenSource := clientCredentialsConfig.TokenSource(ctx)

		client := &http.Client{
			Transport: &oauth2.Transport{
				Base: &http.Transport{
					TLSClientConfig: tlsConfig,
				},
				Source: tokenSource,
			},
			Timeout: time.Second * 10,
		}
		return client, nil

	default:
		// Unsupported secret type
		return nil, errors.New("unknown authSecret type")
	}
}

func CzertainlySignerFromIssuerAndSecretData(ctx context.Context, issuerSpec *czertainlyissuerapi.IssuerSpec, authSecret corev1.Secret, caBundleSecretData map[string][]byte, annotations map[string]string) (controllers.Signer, error) {
	// l := log.FromContext(ctx)
	czertainlySigner := czertainlySigner{}

	czertainlyConfig := czertainly.NewConfiguration()

	czertainlyConfig.Servers = czertainly.ServerConfigurations{
		{URL: issuerSpec.ApiUrl},
	}

	client, err := createHttpClient(ctx, issuerSpec, authSecret, caBundleSecretData)
	if err != nil {
		return nil, err
	}

	czertainlyConfig.HTTPClient = client

	czertainlySigner.httpClient = czertainly.NewAPIClient(czertainlyConfig)

	if issuerSpec.RaProfileUuid == "" {
		return nil, errors.New("RA profile uuid is not set")
	}

	czertainlySigner.raProfileUuid = issuerSpec.RaProfileUuid

	return &czertainlySigner, nil
}

func (o *czertainlySigner) Check() error {
	// check if the server is running and we can connect to it
	_, _, err := o.httpClient.AuthenticationManagementAPI.Profile(context.Background()).Execute()
	if err != nil {
		return err
	}

	return nil
}

type RaProfileDetailResponse struct {
	AuthorityInstanceUuid string `json:"authorityInstanceUuid"`
}

type IssueCertRequest struct {
	Pkcs10     string   `json:"pkcs10"`
	Attributes []string `json:"attributes"`
}

type IssueCertResponse struct {
	Uuid string `json:"uuid"`
}

type CertDetailsResponse struct {
	State              string `json:"state"`
	CertificateContent string `json:"certificateContent"`
}

func (o *czertainlySigner) Sign(ctx context.Context, cr signer.CertificateRequestObject) ([]byte, error) {
	l := log.FromContext(ctx)

	_, _, csrBytes, err := cr.GetRequest()
	if err != nil {
		return nil, err
	}

	l.Info(fmt.Sprintf("Processing CSR: %s", string(csrBytes)))

	raProfileDto, _, err := o.httpClient.RAProfileManagementAPI.GetRaProfileWithoutAuthority(context.Background(), o.raProfileUuid).Execute()
	if err != nil {
		return nil, err
	}

	authorityUuid := raProfileDto.AuthorityInstanceUuid

	issueCertificateRequest := czertainly.ClientCertificateSignRequestDto{
		Request:    string(csrBytes),
		Attributes: []czertainly.RequestAttributeDto{},
	}

	l.Info(fmt.Sprintf("Issuing certificate: authorityUuid=%s, raProfileUuid=%s", authorityUuid, o.raProfileUuid))

	clientCertificateDataResponseDto, _, err := o.httpClient.ClientOperationsV2API.IssueCertificate(context.Background(), authorityUuid, o.raProfileUuid).ClientCertificateSignRequestDto(issueCertificateRequest).Execute()
	if err != nil {
		return nil, err
	}

	uuid := clientCertificateDataResponseDto.Uuid

	l.Info(fmt.Sprintf("Waiting for certificate request to be processed: uuid=%s", uuid))

	state := czertainly.CERTIFICATESTATE_REQUESTED
	cert := ""
	for {
		s, c, err := o.waitForCertificate(ctx, uuid)
		if err != nil {
			return nil, err
		}
		state = s
		if state == czertainly.CERTIFICATESTATE_ISSUED {
			l.Info(fmt.Sprintf("Certificate request processed sucessfully: uuid=%s", uuid))
			cert = c
			break
		} else if state == czertainly.CERTIFICATESTATE_FAILED {
			l.Info(fmt.Sprintf("Certificate request failed: uuid=%s", uuid))
			return nil, errors.New("certificate request failed")
		} else if state == czertainly.CERTIFICATESTATE_REJECTED {
			l.Info(fmt.Sprintf("Certificate request rejected: uuid=%s", uuid))
			return nil, errors.New("certificate request rejected")
		} else {
			// wait for 1 second and check again
			time.Sleep(1 * time.Second)
		}
	}

	// check that issued certificate is not empty
	if cert == "" {
		return nil, errors.New("issued certificate is empty")
	}

	decodedCert, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		l.Error(err, "Failed to decode certificate: %s", cert)
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: decodedCert,
	}), nil
}

func (o *czertainlySigner) waitForCertificate(ctx context.Context, uuid string) (czertainly.CertificateState, string, error) {
	certificateDetailDto, _, err := o.httpClient.CertificateInventoryAPI.GetCertificate(context.Background(), uuid).Execute()
	if err != nil {
		return "", "", err
	}

	state := certificateDetailDto.State
	cert := certificateDetailDto.CertificateContent

	if state == czertainly.CERTIFICATESTATE_ISSUED {
		return state, cert, nil
	} else {
		return state, "", nil
	}
}
