package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IssuerSpec defines the desired state of Issuer
type IssuerSpec struct {
	// ApiUrl is the URL to access CZERTAINLY platform API,
	// for example: "https://my.czertainly.com/api".
	ApiUrl string `json:"serverUrl"`

	// AuthSecretName is a reference to a kubernetes.io/tls Secret that is
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

// IssuerStatus defines the observed state of Issuer
type IssuerStatus struct {
	// List of status conditions to indicate the status of a CertificateRequest.
	// Known condition types are `Ready`.
	// +optional
	Conditions []IssuerCondition `json:"conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Issuer is the Schema for the issuers API
type Issuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec   `json:"spec,omitempty"`
	Status IssuerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// IssuerList contains a list of Issuer
type IssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Issuer `json:"items"`
}

// IssuerCondition contains condition information for an Issuer.
type IssuerCondition struct {
	// Type of the condition, known values are ('Ready').
	Type IssuerConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
	Status ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`
}

// IssuerConditionType represents an Issuer condition value.
type IssuerConditionType string

const (
	// IssuerConditionReady represents the fact that a given Issuer condition
	// is in ready state and able to issue certificates.
	// If the `status` of this condition is `False`, CertificateRequest controllers
	// should prevent attempts to sign certificates.
	IssuerConditionReady IssuerConditionType = "Ready"
)

// ConditionStatus represents a condition's status.
// +kubebuilder:validation:Enum=True;False;Unknown
type ConditionStatus string

// These are valid condition statuses. "ConditionTrue" means a resource is in
// the condition; "ConditionFalse" means a resource is not in the condition;
// "ConditionUnknown" means kubernetes can't decide if a resource is in the
// condition or not. In the future, we could add other intermediate
// conditions, e.g. ConditionDegraded.
const (
	// ConditionTrue represents the fact that a given condition is true
	ConditionTrue ConditionStatus = "True"

	// ConditionFalse represents the fact that a given condition is false
	ConditionFalse ConditionStatus = "False"

	// ConditionUnknown represents the fact that a given condition is unknown
	ConditionUnknown ConditionStatus = "Unknown"
)

func init() {
	SchemeBuilder.Register(&Issuer{}, &IssuerList{})
}
