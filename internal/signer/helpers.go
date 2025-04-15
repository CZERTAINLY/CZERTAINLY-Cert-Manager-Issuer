package signer

import (
	"context"
	"fmt"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// getCertificateOwnerName extracts the name of the Certificate owner from the associated CertificateRequest object.
func getCertificateOwnerName(cr signer.CertificateRequestObject) (string, error) {
	for _, ownerRef := range cr.GetOwnerReferences() {
		if ownerRef.Kind == "Certificate" && ownerRef.APIVersion == "cert-manager.io/v1" {
			return ownerRef.Name, nil
		}
	}
	return "", fmt.Errorf("CertificateRequest %s/%s has no Certificate owner", cr.GetNamespace(), cr.GetName())
}

// getOwningCertificate retrieves the Certificate object that owns the given CertificateRequest object.
func getOwningCertificate(
	ctx context.Context,
	cr signer.CertificateRequestObject,
	k8sClient client.Client,
) (*certmanagerv1.Certificate, error) {
	certName, err := getCertificateOwnerName(cr)
	if err != nil {
		return nil, err
	}

	key := client.ObjectKey{
		Name:      certName,
		Namespace: cr.GetNamespace(),
	}

	cert := &certmanagerv1.Certificate{}
	if err := k8sClient.Get(ctx, key, cert); err != nil {
		return nil, fmt.Errorf("failed to get Certificate %s/%s: %w", key.Namespace, key.Name, err)
	}

	return cert, nil
}

// patchOwningCertificateWithUUID adds the given UUID as an annotation to the owning Certificate of the CertificateRequest.
func patchOwningCertificateWithUUID(
	ctx context.Context,
	cr signer.CertificateRequestObject,
	k8sClient client.Client,
	uuid string,
) error {
	cert, err := getOwningCertificate(ctx, cr, k8sClient)
	if err != nil {
		return err
	}

	original := cert.DeepCopy()
	if cert.Annotations == nil {
		cert.Annotations = map[string]string{}
	}
	cert.Annotations[certificateUuidAnnotation] = uuid

	if err := k8sClient.Patch(ctx, cert, client.MergeFrom(original)); err != nil {
		return fmt.Errorf("failed to patch Certificate %s/%s with UUID: %w", cert.Namespace, cert.Name, err)
	}

	return nil
}

// patchCertificateRequestWithUUID adds the given UUID as an annotation to the CertificateRequest.
func patchCertificateRequestWithUUID(
	ctx context.Context,
	cr signer.CertificateRequestObject,
	k8sClient client.Client,
	uuid string,
) error {
	certReq := &certmanagerv1.CertificateRequest{}

	key := types.NamespacedName{
		Name:      cr.GetName(),
		Namespace: cr.GetNamespace(),
	}
	if err := k8sClient.Get(ctx, key, certReq); err != nil {
		return fmt.Errorf("failed to get CertificateRequest %s/%s: %w", key.Namespace, key.Name, err)
	}

	original := certReq.DeepCopy()

	if certReq.Annotations == nil {
		certReq.Annotations = map[string]string{}
	}
	certReq.Annotations[certificateUuidAnnotation] = uuid

	if err := k8sClient.Patch(ctx, certReq, client.MergeFrom(original)); err != nil {
		return fmt.Errorf("failed to patch CertificateRequest %s/%s with UUID: %w", key.Namespace, key.Name, err)
	}

	return nil
}

// secretContainsCertificate checks if the CertificateRequest's owning Certificate has a Secret of type kubernetes.io/tls
// and if that Secret contains a certificate in the tls.crt field.
func secretContainsCertificate(ctx context.Context, cr signer.CertificateRequestObject, k8sClient client.Client) (bool, error) {
	cert, err := getOwningCertificate(ctx, cr, k8sClient)
	if err != nil {
		return false, err
	}

	// get the certificate spec.secretName
	secretName := cert.Spec.SecretName

	// get the secret
	secret := &corev1.Secret{}
	key := types.NamespacedName{
		Name:      secretName,
		Namespace: cr.GetNamespace(),
	}

	if err := k8sClient.Get(ctx, key, secret); err != nil {
		return false, fmt.Errorf("failed to get Secret %s/%s: %w", key.Namespace, key.Name, err)
	}

	// check if the secret is of type kubernetes.io/tls
	// if not, return error
	if secret.Type != corev1.SecretTypeTLS {
		return false, fmt.Errorf("secret %s/%s is not of type kubernetes.io/tls", key.Namespace, key.Name)
	}

	// when the secret is of type kubernetes.io/tls, check if the certificate is present in tls.crt
	if secret.Data["tls.crt"] == nil {
		return false, nil
	}

	return true, nil
}

// privateKeyRotated checks if the CertificateRequest's owning Certificate has a PrivateKeyRotationPolicy set to Always.
func privateKeyRotated(ctx context.Context, cr signer.CertificateRequestObject, k8sClient client.Client) (bool, error) {
	cert, err := getOwningCertificate(ctx, cr, k8sClient)
	if err != nil {
		return false, err
	}

	// ensure PrivateKey is not nil before accessing RotationPolicy
	privateKey := cert.Spec.PrivateKey
	if privateKey == nil {
		return false, nil
	}

	return privateKey.RotationPolicy == certmanagerv1.RotationPolicyAlways, nil
}
