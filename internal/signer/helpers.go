package signer

import (
	"context"
	"fmt"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"k8s.io/apimachinery/pkg/types"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// patchOwningCertificateWithUUID adds the given UUID as an annotation to the Certificate
// that owns the given CertificateRequest.
func patchOwningCertificateWithUUID(
	ctx context.Context,
	cr signer.CertificateRequestObject, // 👈 or signer.CertificateRequestObject if not aliased
	k8sClient client.Client,
	uuid string,
) error {
	var certName string
	for _, ownerRef := range cr.GetOwnerReferences() {
		if ownerRef.Kind == "Certificate" && ownerRef.APIVersion == "cert-manager.io/v1" {
			certName = ownerRef.Name
			break
		}
	}

	if certName == "" {
		return fmt.Errorf("CertificateRequest %s/%s has no Certificate owner", cr.GetNamespace(), cr.GetName())
	}

	cert := &certmanagerv1.Certificate{}
	key := client.ObjectKey{
		Name:      certName,
		Namespace: cr.GetNamespace(),
	}
	if err := k8sClient.Get(ctx, key, cert); err != nil {
		return fmt.Errorf("failed to get Certificate %s/%s: %w", key.Namespace, key.Name, err)
	}

	original := cert.DeepCopy()
	if cert.Annotations == nil {
		cert.Annotations = map[string]string{}
	}
	cert.Annotations[certificateUuidAnnotation] = uuid

	if err := k8sClient.Patch(ctx, cert, client.MergeFrom(original)); err != nil {
		return fmt.Errorf("failed to patch Certificate %s/%s with UUID: %w", key.Namespace, key.Name, err)
	}

	return nil
}

// patchCertificateRequestWithUUID adds the given UUID as an annotation to the CertificateRequest.
func patchCertificateRequestWithUUID(
	ctx context.Context,
	cr signer.CertificateRequestObject, // 👈 or signer.CertificateRequestObject if not aliased
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
