package v1alpha1

import (
	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].reason"
// +kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message"
// +kubebuilder:printcolumn:name="LastTransition",type="string",type="date",JSONPath=".status.conditions[?(@.type==\"Ready\")].lastTransitionTime"
// +kubebuilder:printcolumn:name="ObservedGeneration",type="integer",JSONPath=".status.conditions[?(@.type==\"Ready\")].observedGeneration"
// +kubebuilder:printcolumn:name="Generation",type="integer",JSONPath=".metadata.generation"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// CzertainlyClusterIssuer is the Schema for the clusterissuers API
type CzertainlyClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec            `json:"spec,omitempty"`
	Status v1alpha1.IssuerStatus `json:"status,omitempty"`
}

func (vi *CzertainlyClusterIssuer) GetStatus() *v1alpha1.IssuerStatus {
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
func (vi *CzertainlyClusterIssuer) GetIssuerTypeIdentifier() string {
	// ACTION REQUIRED: Change this to a unique string that identifies your cluster issuer
	return "czertainlyclusterissuers.czertainly-issuer.czertainly.com"
}

// issuer-lib requires that we implement the Issuer interface
// so that it can interact with our Issuer resource.
var _ v1alpha1.Issuer = &CzertainlyClusterIssuer{}

//+kubebuilder:object:root=true

// CzertainlyClusterIssuerList contains a list of ClusterIssuer
type CzertainlyClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CzertainlyClusterIssuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CzertainlyClusterIssuer{}, &CzertainlyClusterIssuerList{})
}
