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
	"github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/internal/issuer/czertainly"
	"net/http"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"time"
)

type czertainlySigner struct {
	httpClient    *czertainly.APIClient
	serverUrl     string
	raProfileUuid string
	raProfileName string
}

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(context.Context, *czertainlyissuerapi.IssuerSpec, map[string][]byte, map[string][]byte) (HealthChecker, error)

type Signer interface {
	Sign(context.Context, []byte) ([]byte, error)
}

type SignerBuilder func(context.Context, *czertainlyissuerapi.IssuerSpec, map[string][]byte, map[string][]byte, map[string]string) (Signer, error)

func CzertainlyHealthCheckerFromIssuerAndSecretData(ctx context.Context, issuerSpec *czertainlyissuerapi.IssuerSpec, authSecretData map[string][]byte, caBundleSecretData map[string][]byte) (HealthChecker, error) {
	// l := log.FromContext(ctx)
	signer := czertainlySigner{}

	czertainlyConfig := czertainly.NewConfiguration()

	czertainlyConfig.Servers = czertainly.ServerConfigurations{
		{URL: issuerSpec.ServerUrl},
	}

	client, err := createHttpClient(ctx, issuerSpec, authSecretData, caBundleSecretData)
	if err != nil {
		return nil, err
	}

	czertainlyConfig.HTTPClient = client

	signer.httpClient = czertainly.NewAPIClient(czertainlyConfig)

	return &signer, nil
}

func createHttpClient(ctx context.Context, issuerSpec *czertainlyissuerapi.IssuerSpec, authSecretData map[string][]byte, caBundleSecretData map[string][]byte) (*http.Client, error) {
	tlsConfig := &tls.Config{}

	if len(caBundleSecretData) > 0 {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caBundleSecretData["ca.crt"])
		tlsConfig.RootCAs = caCertPool
	}

	cert, err := tls.X509KeyPair(authSecretData["tls.crt"], authSecretData["tls.key"])
	if err != nil {
		return nil, err
	}

	tlsConfig.Certificates = []tls.Certificate{cert}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: time.Second * 10,
	}

	return client, nil
}

func CzertainlySignerFromIssuerAndSecretData(ctx context.Context, issuerSpec *czertainlyissuerapi.IssuerSpec, authSecretData map[string][]byte, caBundleSecretData map[string][]byte, annotations map[string]string) (Signer, error) {
	// l := log.FromContext(ctx)
	signer := czertainlySigner{}

	czertainlyConfig := czertainly.NewConfiguration()

	czertainlyConfig.Servers = czertainly.ServerConfigurations{
		{URL: issuerSpec.ServerUrl},
	}

	client, err := createHttpClient(ctx, issuerSpec, authSecretData, caBundleSecretData)
	if err != nil {
		return nil, err
	}

	czertainlyConfig.HTTPClient = client

	signer.httpClient = czertainly.NewAPIClient(czertainlyConfig)

	if issuerSpec.RaProfileUuid == "" {
		return nil, errors.New("RA profile uuid is not set")
	}

	signer.raProfileUuid = issuerSpec.RaProfileUuid

	return &signer, nil
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

func (o *czertainlySigner) Sign(ctx context.Context, csrBytes []byte) ([]byte, error) {
	l := log.FromContext(ctx)

	l.Info(fmt.Sprintf("Processing CSR: %s", string(csrBytes)))

	getRaProfileDetails := o.serverUrl + "/api/v1/raProfiles/" + o.raProfileUuid

	l.Info(fmt.Sprintf("Getting RA profile details: url=%s", getRaProfileDetails))

	raProfileDto, _, err := o.httpClient.RAProfileManagementAPI.GetRaProfileWithoutAuthority(context.Background(), o.raProfileUuid).Execute()
	if err != nil {
		return nil, err
	}

	authorityUuid := raProfileDto.AuthorityInstanceUuid

	issueCertificateRequest := czertainly.ClientCertificateSignRequestDto{
		Pkcs10:     string(csrBytes),
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
		if state == czertainly.CERTIFICATESTATE_ISSUED || state == czertainly.CERTIFICATESTATE_FAILED || state == czertainly.CERTIFICATESTATE_REJECTED {
			cert = c
			break
		} else {
			// wait for 1 second and check again
			time.Sleep(1 * time.Second)
		}
	}

	decodedCert, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
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

	if state == "issued" {
		return state, cert, nil
	} else {
		return state, "", nil
	}
}
