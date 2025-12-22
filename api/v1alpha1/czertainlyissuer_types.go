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

	// HttpTransport contains settings for HTTP client and transport used to
	// communicate with CZERTAINLY platform API and can be used to override
	// default timeouts and connection settings.
	// +optional
	HttpTransport *HttpTransport `json:"httpTransport,omitempty"`
}

type HttpTransport struct {
	// DialTimeout is the maximum amount of time a dial will wait for a connect to complete. (default: 5s)
	// +optional
	DialTimeout *metav1.Duration `json:"dialTimeout,omitempty"`

	// DialKeepAlive specifies the interval between keep-alive probes for an active network connection. (default: 30s)
	// +optional
	DialKeepAlive *metav1.Duration `json:"dialKeepAlive,omitempty"`

	// TLSHandshakeTimeout specifies the maximum amount of time to wait for a TLS handshake.
	// Zero means no timeout. (default: 5s)
	// +optional
	TLSHandshakeTimeout *metav1.Duration `json:"tlsHandshakeTimeout,omitempty"`

	// ResponseHeaderTimeout, if non-zero, specifies the amount of time to wait for a server's response headers
	// after fully writing the request (including its body, if any). This time does not include the time to read
	// the response body. (default: 20s)
	// +optional
	ResponseHeaderTimeout *metav1.Duration `json:"responseHeaderTimeout,omitempty"`

	// ExpectContinueTimeout, if non-zero, specifies the amount of time to wait for a server's first response headers
	// after fully writing the request headers if the request has an "Expect: 100-continue" header. Zero means
	// no timeout and causes the body to be sent immediately, without waiting for the server to approve.
	// This time does not include the time to send the request header. (default: 1s)
	// +optional
	ExpectContinueTimeout *metav1.Duration `json:"expectContinueTimeout,omitempty"`

	// IdleConnTimeout is the maximum amount of time an idle (keep-alive) connection will remain idle before closing
	// itself. Zero means no limit. (default: 90s)
	// +optional
	IdleConnTimeout *metav1.Duration `json:"idleConnTimeout,omitempty"`

	// MaxIdleConns controls the maximum number of idle (keep-alive) connections across all hosts.
	// Zero means no limit. (default: 200)
	// +optional
	MaxIdleConns *int `json:"maxIdleConns,omitempty"`

	// MaxIdleConnsPerHost, if non-zero, controls the maximum idle (keep-alive) connections to keep
	// per-host. (default: 20)
	// +optional
	MaxIdleConnsPerHost *int `json:"maxIdleConnsPerHost,omitempty"`

	// ClientTimeout specifies a time limit for requests made. The timeout includes connection time, any redirects,
	// and reading the response body. A Timeout of zero means no timeout. (default: 30s)
	// +optional
	ClientTimeout *metav1.Duration `json:"clientTimeout,omitempty"`
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
