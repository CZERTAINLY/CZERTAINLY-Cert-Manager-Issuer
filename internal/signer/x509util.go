package signer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"reflect"
)

func parseKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	// extract PEM from request object
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("PEM block type must be RSA PRIVATE KEY")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func parseCert(pemBytes []byte) (*x509.Certificate, error) {
	// extract PEM from request object
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("PEM block type must be CERTIFICATE")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	// extract PEM from request object
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("PEM block type must be CERTIFICATE REQUEST")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func matchPublicKeysCsrCert(csrPemBytes []byte, certByte []byte) error {
	certificate, err := x509.ParseCertificate(certByte)
	if err != nil {
		return err
	}
	csr, err := parseCSR(csrPemBytes)
	if err != nil {
		return err
	}

	return matchPublicKeys(csr, certificate)
}

func matchPublicKeys(csr *x509.CertificateRequest, cert *x509.Certificate) error {
	csrPubKeyInfo, err := getSubjectPublicKeyInfo(csr.PublicKey)
	if err != nil {
		return err
	}

	certPubKeyInfo, err := getSubjectPublicKeyInfo(cert.PublicKey)
	if err != nil {
		return err
	}

	// Compare the DER-encoded SubjectPublicKeyInfo structures
	if reflect.DeepEqual(csrPubKeyInfo, certPubKeyInfo) {
		return nil
	} else {
		return errors.New("public keys do not match")
	}
}

func getSubjectPublicKeyInfo(pub interface{}) ([]byte, error) {
	// Marshal the public key into DER-encoded SubjectPublicKeyInfo
	return x509.MarshalPKIXPublicKey(pub)
}
