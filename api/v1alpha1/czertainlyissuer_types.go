package v1alpha1

import (
	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].reason"
// +kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message"
// +kubebuilder:printcolumn:name="LastTransition",type="string",type="date",JSONPath=".status.conditions[?(@.type==\"Ready\")].lastTransitionTime"
// +kubebuilder:printcolumn:name="ObservedGeneration",type="integer",JSONPath=".status.conditions[?(@.type==\"Ready\")].observedGeneration"
// +kubebuilder:printcolumn:name="Generation",type="integer",JSONPath=".metadata.generation"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// CzertainlyIssuer is the Schema for the issuers API
type CzertainlyIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec            `json:"spec,omitempty"`
	Status v1alpha1.IssuerStatus `json:"status,omitempty"`
}

// IssuerSpec defines the desired state of SampleIssuer
type IssuerSpec struct {
	// ApiUrl is the URL to access CZERTAINLY platform API,
	// for example: "https://my.czertainly.com/api".
	ApiUrl string `json:"apiUrl"`

	// AuthSecretName is a reference to a kubernetes.io/tls or Opaque Secret that is
	// used to authenticate and authorize to CZERTAINLY platform.
	// The Secret must be in the same namespace
	// as the referent. If the referent is a ClusterIssuer, the reference instead
	// refers to the resource with the given name in the configured
	// 'cluster resource namespace', which is set as a flag on the controller
	// component (and defaults to the namespace that the controller runs in).
	AuthSecretName string `json:"authSecretName"`

	// RaProfileUuid is the UUID of the RA profile to use when managing certificates.
	// You can get the UUID of configured RA profile in the CZERTAINLY platform. The user
	// should have permission to use the RA profile.
	RaProfileUuid string `json:"raProfileUuid"`

	// RaProfileName is the name of the RA profile to use when managing certificates.
	// This is the name of configured RA profile in the CZERTAINLY platform. The user
	// should have permission to use the RA profile.
	// +optional
	RaProfileName string `json:"raProfileName"`

	// CaBundleSecretName is a reference to a Secret that contains the CA bundle to
	// use when verifying the CZERTAINLY platform's serving certificates.
	// The Secret must be in the same namespace as the referent and must
	// contain 'ca.crt' in data. If the referent is a ClusterIssuer, the reference instead
	// refers to the resource with the given name in the configured
	// 'cluster resource namespace', which is set as a flag on the controller
	// component (and defaults to the namespace that the controller runs in).
	// +optional
	CaBundleSecretName string `json:"caBundleSecretName"`
}

func (vi *CzertainlyIssuer) GetStatus() *v1alpha1.IssuerStatus {
	return &vi.Status
}

// GetIssuerTypeIdentifier returns a string that uniquely identifies the
// issuer type. This should be a constant across all instances of this
// issuer type. This string is used as a prefix when determining the
// issuer type for a Kubernetes CertificateSigningRequest resource based
// on the issuerName field. The value should be formatted as follows:
// "<issuer resource (plural)>.<issuer group>". For example, the value
// "simpleclusterissuers.issuer.cert-manager.io" will match all CSRs
// with an issuerName set to eg. "simpleclusterissuers.issuer.cert-manager.io/issuer1".
func (vi *CzertainlyIssuer) GetIssuerTypeIdentifier() string {
	// ACTION REQUIRED: Change this to a unique string that identifies your issuer
	return "czertainlyissuers.czertainly-issuer.czertainly.com"
}

// issuer-lib requires that we implement the Issuer interface
// so that it can interact with our Issuer resource.
var _ v1alpha1.Issuer = &CzertainlyIssuer{}

//+kubebuilder:object:root=true

// CzertainlyIssuerList contains a list of Issuer
type CzertainlyIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CzertainlyIssuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CzertainlyIssuer{}, &CzertainlyIssuerList{})
}
