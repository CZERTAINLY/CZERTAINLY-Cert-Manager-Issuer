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
	cfg := czertainly.NewConfiguration()
	cfg.Servers = czertainly.ServerConfigurations{{URL: issuerSpec.ApiUrl}}

	httpClient, err := createHttpClient(ctx, issuerSpec, authSecret, caBundleSecretData)
	if err != nil {
		return nil, err
	}
	cfg.HTTPClient = httpClient

	return &czertainlySigner{
		httpClient: czertainly.NewAPIClient(cfg),
	}, nil
}

func CzertainlySignerFromIssuerAndSecretData(ctx context.Context, k8sClient client.Client, issuerSpec *czertainlyissuerapi.IssuerSpec, authSecret corev1.Secret, caBundleSecretData map[string][]byte, annotations map[string]string) (controllers.Signer, error) {
	if issuerSpec.RaProfileUuid == "" {
		return nil, errors.New("RA profile UUID is not set")
	}

	cfg := czertainly.NewConfiguration()
	cfg.Servers = czertainly.ServerConfigurations{{URL: issuerSpec.ApiUrl}}

	httpClient, err := createHttpClient(ctx, issuerSpec, authSecret, caBundleSecretData)
	if err != nil {
		return nil, err
	}
	cfg.HTTPClient = httpClient

	return &czertainlySigner{
		httpClient:    czertainly.NewAPIClient(cfg),
		raProfileUuid: issuerSpec.RaProfileUuid,
		k8sClient:     k8sClient,
	}, nil
}

func createHttpClient(ctx context.Context, issuerSpec *czertainlyissuerapi.IssuerSpec, authSecret corev1.Secret, caBundleSecretData map[string][]byte) (*http.Client, error) {
	tlsConfig, err := buildTLSConfig(caBundleSecretData["ca.crt"])
	if err != nil {
		return nil, err
	}

	switch authSecret.Type {
	case corev1.SecretTypeTLS:
		cert, err := tls.X509KeyPair(authSecret.Data["tls.crt"], authSecret.Data["tls.key"])
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		return &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
			Timeout:   10 * time.Second,
		}, nil

	case corev1.SecretTypeOpaque:
		config := &clientcredentials.Config{
			ClientID:     string(authSecret.Data["client_id"]),
			ClientSecret: string(authSecret.Data["client_secret"]),
			TokenURL:     string(authSecret.Data["token_url"]),
			Scopes:       strings.Split(string(authSecret.Data["scopes"]), " "),
		}

		return &http.Client{
			Transport: &oauth2.Transport{
				Base:   &http.Transport{TLSClientConfig: tlsConfig},
				Source: config.TokenSource(ctx),
			},
			Timeout: 10 * time.Second,
		}, nil

	default:
		return nil, errors.New("unknown authSecret type")
	}
}

func buildTLSConfig(caData []byte) (*tls.Config, error) {
	cfg := &tls.Config{}
	if len(caData) > 0 {
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(caData); !ok {
			return nil, errors.New("failed to append CA certificates")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

func (o *czertainlySigner) Check(ctx context.Context) error {
	l := log.FromContext(ctx)

	info, _, err := o.httpClient.InfoAPI.GetInfo(ctx).Execute()
	if err != nil {
		return err
	}
	l.Info("Connected to server", "version", info.App.Version)

	user, _, err := o.httpClient.AuthenticationManagementAPI.Profile(ctx).Execute()
	if err != nil {
		return err
	}
	l.Info("Authenticated user", "username", user.Username)

	return nil
}

func csrString(csr []byte) *string {
	s := string(csr)
	return &s
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
	// if so, the request was already created, and we need to use it instead of requesting new
	uuid := ""
	annotations := cr.GetAnnotations()
	if annotations != nil {
		uuid = annotations[certificateUuidAnnotation]
	}

	// request for new certificate only if czertainly-issuer.czertainly.com/certificate-uuid is not set
	if uuid == "" {
		l.Info(fmt.Sprintf("Issuing certificate: authorityUuid=%s, raProfileUuid=%s", *authorityUuid, o.raProfileUuid))
		uuid, err = o.issueCertificate(ctx, csrBytes, *authorityUuid)

		// changing the certificate request annotation will trigger the controller to update the certificate
		// which is undesired state, keeping commented for now
		//if err := patchCertificateRequestWithUUID(ctx, cr, o.k8sClient, uuid); err != nil {
		//	l.Error(err, "Failed to annotate certificate request with UUID")
		//	return nil, err
		//}
	} else {
		// we need to check if we should renew or rekey
		// renew if the associated secret of the certificates contains tls.crt and spec.privateKey.rotationPolicy!=Always
		// rekey if the associated secret of the certificates contains tls.crt and spec.privateKey.rotationPolicy=Always
		containsCrt, err := secretContainsCertificate(ctx, cr, o.k8sClient)
		if err != nil {
			return nil, err
		}

		keyRotated, err := privateKeyRotated(ctx, cr, o.k8sClient)
		if err != nil {
			return nil, err
		}

		if !containsCrt {
			// something went wrong when the uuid was set and the certificate was not issued
			l.Error(errors.New("certificate request is not issued"), "Certificate request is not issued")
			return nil, errors.New("certificate request is not issued")
		} else if !keyRotated {
			// we should renew the certificate
			l.Info(fmt.Sprintf("Renewing certificate: uuid=%s", uuid))
			uuid, err = o.renewCertificate(ctx, csrBytes, *authorityUuid, uuid)
		} else {
			// we should rekey the certificate
			// TODO: is it enough to assume that the certificate should be rekeyed if the rotation policy is set to Always?
			l.Info(fmt.Sprintf("Rekeying certificate: uuid=%s", uuid))
			uuid, err = o.rekeyCertificate(ctx, csrBytes, *authorityUuid, uuid)
		}
	}

	if err != nil {
		return nil, err
	}

	l.Info(fmt.Sprintf("Waiting for certificate request to be processed: uuid=%s", uuid))

	cert, err := o.pollForCertificate(ctx, uuid)
	if err != nil {
		return nil, err
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

func (o *czertainlySigner) issueCertificate(ctx context.Context, csrBytes []byte, authorityUuid string) (string, error) {
	request := czertainly.ClientCertificateSignRequestDto{
		Request:    string(csrBytes),
		Attributes: []czertainly.RequestAttributeDto{},
	}

	resp, _, err := o.httpClient.ClientOperationsV2API.IssueCertificate(ctx, authorityUuid, o.raProfileUuid).
		ClientCertificateSignRequestDto(request).Execute()
	if err != nil {
		return "", err
	}

	return resp.Uuid, nil
}

func (o *czertainlySigner) renewCertificate(ctx context.Context, csrBytes []byte, authorityUuid string, certificateUuid string) (string, error) {
	renewCertificateRequest := czertainly.ClientCertificateRenewRequestDto{
		Request: csrString(csrBytes),
	}

	resp, _, err := o.httpClient.ClientOperationsV2API.RenewCertificate(ctx, authorityUuid, o.raProfileUuid, certificateUuid).ClientCertificateRenewRequestDto(renewCertificateRequest).Execute()
	if err != nil {
		return "", err
	}

	return resp.Uuid, nil
}

func (o *czertainlySigner) rekeyCertificate(ctx context.Context, csrBytes []byte, authorityUuid string, certificateUuid string) (string, error) {
	rekeyCertificateRequest := czertainly.ClientCertificateRekeyRequestDto{
		Request: csrString(csrBytes),
	}

	resp, _, err := o.httpClient.ClientOperationsV2API.RekeyCertificate(ctx, authorityUuid, o.raProfileUuid, certificateUuid).ClientCertificateRekeyRequestDto(rekeyCertificateRequest).Execute()
	if err != nil {
		return "", err
	}

	return resp.Uuid, nil
}

func (o *czertainlySigner) getCertificate(ctx context.Context, uuid string) (czertainly.CertificateState, string, error) {
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

func (o *czertainlySigner) pollForCertificate(ctx context.Context, uuid string) (string, error) {
	l := log.FromContext(ctx)

	for {
		state, cert, err := o.getCertificate(ctx, uuid)
		if err != nil {
			return "", err
		}

		switch state {
		case czertainly.CERTIFICATESTATE_ISSUED:
			l.Info(fmt.Sprintf("Certificate request processed successfully: uuid=%s", uuid))
			return cert, nil

		case czertainly.CERTIFICATESTATE_FAILED:
			return o.handleFailedState(ctx, uuid)

		case czertainly.CERTIFICATESTATE_REJECTED:
			return o.handleRejectedState(ctx, uuid)

		case czertainly.CERTIFICATESTATE_PENDING_APPROVAL:
			l.Info(fmt.Sprintf("Certificate request is pending approval: uuid=%s", uuid))
			time.Sleep(waitForNextRequeueTime)

		case czertainly.CERTIFICATESTATE_PENDING_ISSUE, czertainly.CERTIFICATESTATE_REQUESTED:
			l.Info(fmt.Sprintf("Certificate request is pending issue: uuid=%s", uuid))
			time.Sleep(waitForNextRequeueTime)

		default:
			l.Info(fmt.Sprintf("Certificate request is in unknown state: uuid=%s, state=%s", uuid, state))
			return "", errors.New("certificate request is in unknown state")
		}
	}
}

func (o *czertainlySigner) handleFailedState(ctx context.Context, uuid string) (string, error) {
	l := log.FromContext(ctx)
	history, _, err := o.httpClient.CertificateInventoryAPI.GetCertificateEventHistory(ctx, uuid).Execute()
	if err != nil {
		return "", err
	}

	for _, event := range history {
		if event.Event == "Issue Certificate" && event.Status == "FAILED" {
			l.Info(fmt.Sprintf("Certificate request failed: uuid=%s, reason=%s", uuid, event.Message))
			return "", signer.PermanentError{
				Err: fmt.Errorf("certificate request failed: uuid=%s, reason=%s", uuid, event.Message),
			}
		}
	}

	l.Info(fmt.Sprintf("Certificate request failed with unknown reason: uuid=%s", uuid))
	return "", errors.New("certificate request failed with unknown reason")
}

func (o *czertainlySigner) handleRejectedState(ctx context.Context, uuid string) (string, error) {
	l := log.FromContext(ctx)
	approvals, _, err := o.httpClient.CertificateInventoryAPI.ListCertificateApprovals(ctx, uuid).Execute()
	if err != nil {
		return "", err
	}

	for _, approval := range approvals.Approvals {
		if approval.Resource == "certificates" && approval.ResourceAction == "issue" {
			switch approval.Status {
			case "EXPIRED":
				l.Info(fmt.Sprintf("Certificate request rejected as expired: uuid=%s", uuid))
				return "", signer.PermanentError{
					Err: fmt.Errorf("certificate request rejected as expired: uuid=%s", uuid),
				}

			case "REJECTED":
				return o.getRejectionReason(ctx, approval.ApprovalUuid, uuid)
			}
		}
	}

	l.Info(fmt.Sprintf("Certificate request rejected: uuid=%s", uuid))
	return "", signer.PermanentError{
		Err: fmt.Errorf("certificate request rejected: uuid=%s", uuid),
	}
}

func (o *czertainlySigner) getRejectionReason(ctx context.Context, approvalUUID, certUUID string) (string, error) {
	l := log.FromContext(ctx)
	details, _, err := o.httpClient.ApprovalInventoryAPI.GetApproval(ctx, approvalUUID).Execute()
	if err != nil {
		return "", err
	}

	for _, step := range details.ApprovalSteps {
		for _, recipient := range step.ApprovalStepRecipients {
			if recipient.Status == "REJECTED" {
				if recipient.Comment != nil {
					l.Info(fmt.Sprintf("Certificate request rejected: uuid=%s, reason=%s", certUUID, *recipient.Comment))
					return "", signer.PermanentError{
						Err: fmt.Errorf("certificate request rejected: uuid=%s, reason=%s", certUUID, *recipient.Comment),
					}
				}
				l.Info(fmt.Sprintf("Certificate request rejected without reason: uuid=%s", certUUID))
				return "", signer.PermanentError{
					Err: fmt.Errorf("certificate request rejected without reason: uuid=%s", certUUID),
				}
			}
		}
	}

	l.Info(fmt.Sprintf("Certificate request rejected with unknown reason: uuid=%s", certUUID))
	return "", signer.PermanentError{
		Err: fmt.Errorf("certificate request rejected with unknown reason: uuid=%s", certUUID),
	}
}
