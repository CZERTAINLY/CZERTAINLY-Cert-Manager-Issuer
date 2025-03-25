package controllers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	czertainlyissuerapi "github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/api/v1alpha1"
)

var (
	errGetAuthSecret        = errors.New("failed to get Secret containing Issuer credentials")
	errHealthCheckerBuilder = errors.New("failed to build the healthchecker")
	errHealthCheckerCheck   = errors.New("healthcheck failed")

	errIssuerRef      = errors.New("error interpreting issuerRef")
	errGetIssuer      = errors.New("error getting issuer")
	errIssuerNotReady = errors.New("issuer is not ready")
	errSignerBuilder  = errors.New("failed to build the signer")
	errSignerSign     = errors.New("failed to sign")
)

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(context.Context, *czertainlyissuerapi.IssuerSpec, corev1.Secret, map[string][]byte) (HealthChecker, error)

type Signer interface {
	Sign(context.Context, signer.CertificateRequestObject) ([]byte, error)
}

type SignerBuilder func(context.Context, *czertainlyissuerapi.IssuerSpec, corev1.Secret, map[string][]byte, map[string]string) (Signer, error)

type Issuer struct {
	HealthCheckerBuilder     HealthCheckerBuilder
	SignerBuilder            SignerBuilder
	ClusterResourceNamespace string

	client client.Client
}

func (s Issuer) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	s.client = mgr.GetClient()

	return (&controllers.CombinedController{
		IssuerTypes:        []issuerapi.Issuer{&czertainlyissuerapi.CzertainlyIssuer{}},
		ClusterIssuerTypes: []issuerapi.Issuer{&czertainlyissuerapi.CzertainlyClusterIssuer{}},

		FieldOwner:       "czertainly-issuer.czertainly.com",
		MaxRetryDuration: 1 * time.Minute,

		Sign:          s.Sign,
		Check:         s.Check,
		EventRecorder: mgr.GetEventRecorderFor("czertainly-issuer.czertainly.com"),
	}).SetupWithManager(ctx, mgr)
}

func (o *Issuer) getIssuerDetails(issuerObject issuerapi.Issuer) (*czertainlyissuerapi.IssuerSpec, string, error) {
	switch t := issuerObject.(type) {
	case *czertainlyissuerapi.CzertainlyIssuer:
		return &t.Spec, issuerObject.GetNamespace(), nil
	case *czertainlyissuerapi.CzertainlyClusterIssuer:
		return &t.Spec, o.ClusterResourceNamespace, nil
	default:
		// A permanent error will cause the Issuer to not retry until the
		// Issuer is updated.
		return nil, "", signer.PermanentError{
			Err: fmt.Errorf("unexpected issuer type: %t", issuerObject),
		}
	}
}

func (o *Issuer) getAuthSecret(ctx context.Context, issuerSpec *czertainlyissuerapi.IssuerSpec, namespace string) (corev1.Secret, error) {
	authSecretName := types.NamespacedName{
		Namespace: namespace,
		Name:      issuerSpec.AuthSecretName,
	}

	var authSecret corev1.Secret
	if err := o.client.Get(ctx, authSecretName, &authSecret); err != nil {
		return corev1.Secret{}, fmt.Errorf("%w, authSecret name: %s, reason: %v", errGetAuthSecret, authSecretName, err)
	}

	return authSecret, nil
}

func (o *Issuer) getCaBundleSecretData(ctx context.Context, issuerSpec *czertainlyissuerapi.IssuerSpec, namespace string) (map[string][]byte, error) {
	caBundleSecretName := types.NamespacedName{
		Namespace: namespace,
		Name:      issuerSpec.CaBundleSecretName,
	}

	var caBundleSecret corev1.Secret
	// If the issuer has a CA bundle, get it
	if issuerSpec.CaBundleSecretName != "" {
		if err := o.client.Get(ctx, caBundleSecretName, &caBundleSecret); err != nil {
			return nil, fmt.Errorf("%w, caBundleSecret name: %s, reason: %v", errGetAuthSecret, caBundleSecretName, err)
		}

		return caBundleSecret.Data, nil
	}

	return nil, nil
}

// Check checks that the CA it is available. Certificate requests will not be
// processed until this check passes.
func (o *Issuer) Check(ctx context.Context, issuerObject issuerapi.Issuer) error {
	issuerSpec, namespace, err := o.getIssuerDetails(issuerObject)
	if err != nil {
		return err
	}

	authSecret, err := o.getAuthSecret(ctx, issuerSpec, namespace)
	if err != nil {
		return err
	}

	caBundleSecretData, err := o.getCaBundleSecretData(ctx, issuerSpec, namespace)
	if err != nil {
		return err
	}

	checker, err := o.HealthCheckerBuilder(ctx, issuerSpec, authSecret, caBundleSecretData)
	if err != nil {
		return fmt.Errorf("%w: %v", errHealthCheckerBuilder, err)
	}

	if err := checker.Check(); err != nil {
		return fmt.Errorf("%w: %v", errHealthCheckerCheck, err)
	}

	return nil
}

// Sign returns a signed certificate for the supplied CertificateRequestObject (a cert-manager CertificateRequest resource or
// a kubernetes CertificateSigningRequest resource). The CertificateRequestObject contains a GetRequest method that returns
// a certificate template that can be used as a starting point for the generated certificate.
// The Sign method should return a PEMBundle containing the signed certificate and any intermediate certificates (see the PEMBundle docs for more information).
// If the Sign method returns an error, the issuance will be retried until the MaxRetryDuration is reached.
// Special errors and cases can be found in the issuer-lib README: https://github.com/cert-manager/issuer-lib/tree/main?tab=readme-ov-file#how-it-works
func (o *Issuer) Sign(ctx context.Context, cr signer.CertificateRequestObject, issuerObject issuerapi.Issuer) (signer.PEMBundle, error) {
	issuerSpec, namespace, err := o.getIssuerDetails(issuerObject)
	if err != nil {
		// Returning an IssuerError will change the status of the Issuer to Failed too.
		return signer.PEMBundle{}, signer.IssuerError{
			Err: err,
		}
	}

	authSecret, err := o.getAuthSecret(ctx, issuerSpec, namespace)
	if err != nil {
		// Returning an IssuerError will change the status of the Issuer to Failed too.
		return signer.PEMBundle{}, signer.IssuerError{
			Err: err,
		}
	}

	caBundleSecretData, err := o.getCaBundleSecretData(ctx, issuerSpec, namespace)
	if err != nil {
		// Returning an IssuerError will change the status of the Issuer to Failed too.
		return signer.PEMBundle{}, signer.IssuerError{
			Err: err,
		}
	}

	_, _, _, err = cr.GetRequest()
	if err != nil {
		return signer.PEMBundle{}, err
	}

	signerObj, err := o.SignerBuilder(ctx, issuerSpec, authSecret, caBundleSecretData, cr.GetAnnotations())
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("%w: %v", errSignerBuilder, err)
	}

	signed, err := signerObj.Sign(ctx, cr)
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("%w: %v", errSignerSign, err)
	}

	bundle, err := pki.ParseSingleCertificateChainPEM(signed)
	if err != nil {
		return signer.PEMBundle{}, err
	}

	return signer.PEMBundle(bundle), nil
}
