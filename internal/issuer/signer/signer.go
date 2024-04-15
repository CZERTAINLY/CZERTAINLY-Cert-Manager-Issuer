package signer

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	czertainlyissuerapi "github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/api/v1alpha1"
	"io"
	"net/http"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"time"
)

type czertainlySigner struct {
	httpClient    *http.Client
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

	client, err := createHttpClient(ctx, issuerSpec, authSecretData, caBundleSecretData)
	if err != nil {
		return nil, err
	}

	signer.httpClient = client

	if issuerSpec.ServerUrl == "" {
		return nil, errors.New("server URL is not set")
	}

	signer.serverUrl = issuerSpec.ServerUrl

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

	client, err := createHttpClient(ctx, issuerSpec, authSecretData, caBundleSecretData)
	if err != nil {
		return nil, err
	}

	signer.httpClient = client

	if issuerSpec.ServerUrl == "" {
		return nil, errors.New("server URL is not set")
	}

	signer.serverUrl = issuerSpec.ServerUrl

	if issuerSpec.RaProfileUuid == "" {
		return nil, errors.New("RA profile uuid is not set")
	}

	signer.raProfileUuid = issuerSpec.RaProfileUuid

	return &signer, nil
}

func (o *czertainlySigner) Check() error {
	// check if the server is running and we can connect to it
	_, err := o.httpClient.Get(o.serverUrl + "/api/v1/auth/profile")
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

	response, err := o.httpClient.Get(getRaProfileDetails)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		l.Info(fmt.Sprintf("Failed to get RA profile details: status=%d", response.StatusCode))
		return nil, errors.New("failed to get RA profile details")
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(response.Body)

	// get authorityInstanceUuid from response
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var result RaProfileDetailResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	authorityUuid := result.AuthorityInstanceUuid

	issueCertRequest := IssueCertRequest{
		Pkcs10:     string(csrBytes),
		Attributes: []string{},
	}

	request, err := json.Marshal(issueCertRequest)

	l.Info(fmt.Sprintf("Issuing certificate: authorityUuid=%s, raProfileUuid=%s", authorityUuid, o.raProfileUuid))

	post, err := o.httpClient.Post(
		o.serverUrl+"/api/v2/operations/authorities/"+authorityUuid+"/raProfiles/"+o.raProfileUuid+"/certificates",
		"application/json", bytes.NewReader(request))
	if err != nil {
		return nil, err
	}

	if post.StatusCode != http.StatusOK {
		return nil, errors.New("failed to issue certificate")
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(post.Body)

	data, err = io.ReadAll(post.Body)
	if err != nil {
		return nil, err
	}

	var issueCertResponse IssueCertResponse
	if err := json.Unmarshal(data, &issueCertResponse); err != nil {
		return nil, err
	}

	uuid := issueCertResponse.Uuid

	l.Info(fmt.Sprintf("Waiting for certificate request to be processed: uuid=%s", uuid))

	state := "requested"
	cert := ""
	for {
		s, c, err := o.waitForCertificate(ctx, uuid)
		if err != nil {
			return nil, err
		}
		state = s
		if state == "issued" || state == "failed" || state == "rejected" {
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

func (o *czertainlySigner) waitForCertificate(ctx context.Context, uuid string) (string, string, error) {
	get, err := o.httpClient.Get(o.serverUrl + "/api/v1/certificates/" + uuid)
	if err != nil {
		return "", "", err
	}

	if get.StatusCode != http.StatusOK {
		return "", "", errors.New("failed to get certificate details")
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(get.Body)

	data, err := io.ReadAll(get.Body)
	if err != nil {
		return "", "", err
	}

	var certDetailsResponse CertDetailsResponse
	if err := json.Unmarshal(data, &certDetailsResponse); err != nil {
		return "", "", err
	}

	state := certDetailsResponse.State
	cert := certDetailsResponse.CertificateContent

	if state == "issued" {
		return state, cert, nil
	} else {
		return state, "", nil
	}
}
