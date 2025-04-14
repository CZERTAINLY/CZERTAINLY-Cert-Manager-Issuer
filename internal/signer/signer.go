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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"strings"
	"time"
)

type czertainlySigner struct {
	httpClient    *czertainly.APIClient
	apiUrl        string
	raProfileUuid string
	raProfileName string

	k8sClient client.Client
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

func CzertainlySignerFromIssuerAndSecretData(ctx context.Context, k8sClient client.Client, issuerSpec *czertainlyissuerapi.IssuerSpec, authSecret corev1.Secret, caBundleSecretData map[string][]byte, annotations map[string]string) (controllers.Signer, error) {
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

	czertainlySigner.k8sClient = k8sClient

	return &czertainlySigner, nil
}

func (o *czertainlySigner) Check(ctx context.Context) error {
	l := log.FromContext(ctx)

	// get information about the server
	coreInfoResponseDto, _, err := o.httpClient.InfoAPI.GetInfo(ctx).Execute()
	if err != nil {
		return err
	}

	l.Info(fmt.Sprintf("Successfully connected to server version: %s", coreInfoResponseDto.App.Version))

	// check if the server is running and we can connect to it
	userDetailDto, _, err := o.httpClient.AuthenticationManagementAPI.Profile(ctx).Execute()
	if err != nil {
		return err
	}

	l.Info(fmt.Sprintf("Authenticated with user details: username=%s", userDetailDto.Username))

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

	// get information about the server
	coreInfoResponseDto, _, err := o.httpClient.InfoAPI.GetInfo(ctx).Execute()
	if err != nil {
		return nil, err
	}

	l.Info(fmt.Sprintf("Connected to server version: %s", coreInfoResponseDto.App.Version))

	_, _, csrBytes, err := cr.GetRequest()
	if err != nil {
		return nil, err
	}

	l.Info(fmt.Sprintf("Processing CSR: %s", string(csrBytes)))

	raProfileDto, _, err := o.httpClient.RAProfileManagementAPI.GetRaProfileWithoutAuthority(ctx, o.raProfileUuid).Execute()
	if err != nil {
		return nil, err
	}

	authorityUuid := raProfileDto.AuthorityInstanceUuid

	// check if annotations contains czertainly-issuer.czertainly.com/certificate-uuid
	// if so, the request was already created and we need to use it instead of requesting new
	uuid := ""
	annotations := cr.GetAnnotations()
	if annotations != nil {
		uuid = annotations[certificateUuidAnnotation]
	}

	// request for new certificate only if czertainly-issuer.czertainly.com/certificate-uuid is not set
	if uuid == "" {
		issueCertificateRequest := czertainly.ClientCertificateSignRequestDto{
			Request:    string(csrBytes),
			Attributes: []czertainly.RequestAttributeDto{},
		}

		l.Info(fmt.Sprintf("Issuing certificate: authorityUuid=%s, raProfileUuid=%s", authorityUuid, o.raProfileUuid))

		clientCertificateDataResponseDto, _, err := o.httpClient.ClientOperationsV2API.IssueCertificate(ctx, *authorityUuid, o.raProfileUuid).ClientCertificateSignRequestDto(issueCertificateRequest).Execute()
		if err != nil {
			return nil, err
		}

		uuid = clientCertificateDataResponseDto.Uuid

		if err := patchCertificateRequestWithUUID(ctx, cr, o.k8sClient, uuid); err != nil {
			l.Error(err, "Failed to annotate certificate request with UUID")
			return nil, err
		}
	}

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
			// get the reason for the failure
			certificateEventHistoryDto, _, err := o.httpClient.CertificateInventoryAPI.GetCertificateEventHistory(ctx, uuid).Execute()
			if err != nil {
				return nil, err
			}

			// get the first failed "Issue Certificate" event that has status "FAILED"
			// it should be the last registered event that is failed from the history perspective
			for _, event := range certificateEventHistoryDto {
				if event.Event == "Issue Certificate" && event.Status == "FAILED" {
					l.Info(fmt.Sprintf("Certificate request failed: uuid=%s, reason=%s", uuid, event.Message))
					return nil, errors.New("certificate request failed with the message: " + event.Message)
				}
			}

			l.Info(fmt.Sprintf("Certificate request failed with unkown reason: uuid=%s", uuid))
			return nil, errors.New("certificate request failed with unknown reason")
		} else if state == czertainly.CERTIFICATESTATE_REJECTED {
			// get approvals for the certificate request
			approvalResponseDto, _, err := o.httpClient.CertificateInventoryAPI.ListCertificateApprovals(ctx, uuid).Execute()
			if err != nil {
				return nil, err
			}

			// get the first approval that has status "EXPIRED" or "REJECTED" with resource "certificates" and action "issue"
			for _, approval := range approvalResponseDto.Approvals {
				if approval.Resource == "certificates" && approval.ResourceAction == "issue" {
					if approval.Status == "EXPIRED" {
						l.Info(fmt.Sprintf("Certificate request rejected as expired: uuid=%s", uuid))
						return nil, errors.New("certificate request rejected as expired")
					} else if approval.Status == "REJECTED" {
						// get the reason for the rejection from the approval detail
						approvalDetailDto, _, err := o.httpClient.ApprovalInventoryAPI.GetApproval(ctx, approval.ApprovalUuid).Execute()
						if err != nil {
							return nil, err
						}

						// get the first rejected approval reason
						for _, approval := range approvalDetailDto.ApprovalSteps {
							for _, recipient := range approval.ApprovalStepRecipients {
								if recipient.Status == "REJECTED" {
									if recipient.Comment != nil {
										l.Info(fmt.Sprintf("Certificate request rejected: uuid=%s, reason=%s", uuid, *recipient.Comment))
										return nil, errors.New("certificate request rejected with the message: " + *recipient.Comment)
									} else {
										l.Info(fmt.Sprintf("Certificate request rejected without reson: uuid=%s", uuid))
										return nil, errors.New("certificate request rejected without reason")
									}
								}
							}
						}

						l.Info(fmt.Sprintf("Certificate request rejected with unknown reason: uuid=%s", uuid))
						return nil, errors.New("certificate request rejected with unknown reason")
					}
				}
			}

			l.Info(fmt.Sprintf("Certificate request rejected: uuid=%s", uuid))
			return nil, errors.New("certificate request rejected")
		} else if state == czertainly.CERTIFICATESTATE_PENDING_APPROVAL {
			l.Info(fmt.Sprintf("Certificate request is pending approval: uuid=%s", uuid))
			// wait for 30 second and check again
			time.Sleep(30 * time.Second)
		} else if state == czertainly.CERTIFICATESTATE_PENDING_ISSUE || state == czertainly.CERTIFICATESTATE_REQUESTED {
			l.Info(fmt.Sprintf("Certificate request is pending issue: uuid=%s", uuid))
			// wait for 30 second and check again
			time.Sleep(30 * time.Second)
		} else {
			l.Info(fmt.Sprintf("Certificate request is in unknown state: uuid=%s, state=%s", uuid, state))
			return nil, errors.New("certificate request is in unknown state")
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

	// check that the certificate match the csr public key
	if err := matchPublicKeysCsrCert(csrBytes, decodedCert); err != nil {
		l.Error(err, "Public key algorithm mismatch between CSR and certificate")
		return nil, err
	}

	// certificate is valid, write annotation to the certificate
	// we need to get the certificate object from the certificate request owner reference
	if err := patchOwningCertificateWithUUID(ctx, cr, o.k8sClient, uuid); err != nil {
		l.Error(err, "Failed to annotate owning Certificate with UUID")
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: decodedCert,
	}), nil
}

func (o *czertainlySigner) waitForCertificate(ctx context.Context, uuid string) (czertainly.CertificateState, string, error) {
	certificateDetailDto, _, err := o.httpClient.CertificateInventoryAPI.GetCertificate(ctx, uuid).Execute()
	if err != nil {
		return "", "", err
	}

	state := certificateDetailDto.State
	cert := certificateDetailDto.CertificateContent

	if state == czertainly.CERTIFICATESTATE_ISSUED {
		return state, *cert, nil
	} else {
		return state, "", nil
	}
}
