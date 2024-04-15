package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmgen "github.com/cert-manager/cert-manager/test/unit/gen"
	logrtesting "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/record"
	clock "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	czertainlyissuerapi "github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/api/v1alpha1"
	"github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/internal/issuer/signer"
)

var (
	fixedClockStart = time.Date(2021, time.January, 1, 1, 0, 0, 0, time.UTC)
	fixedClock      = clock.NewFakeClock(fixedClockStart)
)

type fakeSigner struct {
	errSign error
}

func (o *fakeSigner) Sign(context.Context, []byte) ([]byte, error) {
	return []byte("fake signed certificate"), o.errSign
}

func TestCertificateRequestReconcile(t *testing.T) {
	nowMetaTime := metav1.NewTime(fixedClockStart)

	type testCase struct {
		name                         types.NamespacedName
		secretObjects                []client.Object
		issuerObjects                []client.Object
		crObjects                    []client.Object
		signerBuilder                signer.SignerBuilder
		clusterResourceNamespace     string
		expectedResult               ctrl.Result
		expectedError                error
		expectedReadyConditionStatus cmmeta.ConditionStatus
		expectedReadyConditionReason string
		expectedFailureTime          *metav1.Time
		expectedCertificate          []byte
	}
	tests := map[string]testCase{
		// TODO: Remove
		//"online-test": {
		//	name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
		//	crObjects: []client.Object{
		//		cmgen.CertificateRequest(
		//			"cr1",
		//			cmgen.SetCertificateRequestNamespace("ns1"),
		//			cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
		//				Name:  "issuer1",
		//				Group: czertainlyissuerapi.GroupVersion.Group,
		//				Kind:  "Issuer",
		//			}),
		//			cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
		//				Type:   cmapi.CertificateRequestConditionApproved,
		//				Status: cmmeta.ConditionTrue,
		//			}),
		//			cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
		//				Type:   cmapi.CertificateRequestConditionReady,
		//				Status: cmmeta.ConditionUnknown,
		//			}),
		//			cmgen.SetCertificateRequestCSR([]byte("-----BEGIN CERTIFICATE REQUEST-----\nMIICYDCCAUgCAQAwGzEZMBcGA1UEAwwQc2lnbnNlcnZlci1yYS0wMTCCASIwDQYJ\nKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKDJYK05g9U3jn60jJaDVuRO1Ud7Dl20\nBXpwmQed9NgWjQwUwizRRLUOdJmYxlRpQvvchzoz1gOaxJ2MSHgGLAkgGYpLLqWS\nDSXE4TOpia7QrRgQGbcmMxiX9+Q+X5ut7bzFjlr1Tl/WXcFW5/F1HX6Ht2WdLJoM\nynZvwKoPeJyv7gs7YfM6nBIWWsw+49/64znwbYZ5Cyd4+PHINpF8g7ny/TrgByoH\nw48sGrfgngPXlGwbPke1L1hFZKvPLQcW3eKkfNxpS5wudVMF5ilkoGXrj6TgsBgg\n02ryGxv1NtV2+7x/d3V9d0HfYMl245+dQE8H8fPeyS093/vuLrsVSg8CAwEAAaAA\nMA0GCSqGSIb3DQEBCwUAA4IBAQA4+QwzQc8X12f9b3u0HR/pis+UXL3nJngvU3xi\nI/0CfcP9jkiRX5wimjihUOaMV/TFXPGCopkvsjMBF54QeIZU5vPquL0oZ5GYbTm6\nFGVboVKVTJhAtPLSL+/r5CbYYoWtV2XkNnxdqQjepj/CIADdC2X8LfYvgkVT7UOo\neud0NRiBRsfsePGPfaHi9KyP2LtJXu9brJffBiRJzORIthMFChmNBt4nV5VN/mZS\nHX1z8/KMRYiqk0bVNsAYavqwjqLOQUI8k2AbB/N43QN1TS8/MS7+YiZenU7Opn+S\nQeAGX3NcI8h/Ld61ztyx66e4NXWpjSBm8PTMaAf90xXgj/IC\n-----END CERTIFICATE REQUEST-----")),
		//		),
		//	},
		//	issuerObjects: []client.Object{&czertainlyissuerapi.Issuer{
		//		ObjectMeta: metav1.ObjectMeta{
		//			Name:      "issuer1",
		//			Namespace: "ns1",
		//		},
		//		Spec: czertainlyissuerapi.IssuerSpec{
		//			ServerUrl:      "https://develop.czertainly.online",
		//			RaProfileName:  "9cb76b6a-c291-4e23-b11a-bb3da76adbc6",
		//			AuthSecretName: "issuer1-credentials",
		//		},
		//		Status: czertainlyissuerapi.IssuerStatus{
		//			Conditions: []czertainlyissuerapi.IssuerCondition{
		//				{
		//					Type:   czertainlyissuerapi.IssuerConditionReady,
		//					Status: czertainlyissuerapi.ConditionTrue,
		//				},
		//			},
		//		},
		//	},
		//	},
		//	secretObjects: []client.Object{&corev1.Secret{
		//		ObjectMeta: metav1.ObjectMeta{
		//			Name:      "issuer1-credentials",
		//			Namespace: "ns1",
		//		},
		//		Type: corev1.SecretTypeTLS,
		//		Data: map[string][]byte{
		//			"tls.crt": []byte("-----BEGIN CERTIFICATE-----\nMIIDPTCCAiUCFBd+dfQuley5j4MetX3iewvIxHZDMA0GCSqGSIb3DQEBCwUAMF0x\nCzAJBgNVBAYTAkNaMRAwDgYDVQQIDAdDemVjaGlhMQswCQYDVQQHDAJDQjENMAsG\nA1UECgwEM0tFWTEMMAoGA1UECwwDREVWMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcN\nMjAwOTI1MTE1NDU3WhcNMzAwODA0MTE1NDU3WjBZMQswCQYDVQQGEwJDWjEQMA4G\nA1UECAwHQ3plY2hpYTELMAkGA1UEBwwCQ0IxCzAJBgNVBAoMAkNGMQwwCgYDVQQL\nDANERVYxEDAOBgNVBAMMB0NMSUVOVDEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\nggEKAoIBAQC/SsO+9IzQ85xxyiT+ou8RDNxZMP0Ja8YKrdu19BTFjyLtVLpb+I1X\nqzlXFdJcObYZ5ZboyALB00i5Ds0TTs8ydgEeaw0K2O96DnGh4z5r4qLuF+fpVR+3\nA8kKRSrqJN1JNPFeb+NKsilUNvx5plZBm5+VTd64Sop6r1DALEDBS8AxRJSgp4x/\noCq+T4zLh9XDyVUQ68axLgF86sS4YcBYKQVTH7KwRx+FGPFnBqt2ll2IherJ1N1d\nheXdLqzPYY+uIhs55wUPRhQibjiJhM9NgMYsmOPZRzsPIr6+gUil82rmSfyMg/A0\nwT4dsm6MT7ly6PPRyxoRvhNvfn96FsCRAgMBAAEwDQYJKoZIhvcNAQELBQADggEB\nAI+YNR82n23p9014wa+99aEWJfujlirY07jhAQmsGTkkFM5QTNJzwi6VYnUwjlJM\nOXw8fEiBVRHUiyLV5RWZGiGZuLdCZgYCjtzCtWuOPidShAK5GpLDipG9upZ+RCNp\nBXVbb6J5tEI0esTSxZ/jwj2JqZZayhRmRXL/j8vGRn74atTILeFwUIYsSreoMI8w\nG1Rk0que09LgP1RmCiSl1GUSTL/lrK/dYaw0orZwUxzKg/KNnTYprYiAIVRsHUz8\nbkd6mGEBCfDdpEp0l7laBej2R8RhGDwuxjma1ZrwlCsKLlpdn2lwzqIEc+Zl7dxi\nLTb1NLMH80f4LCuF1iFCD6E=\n-----END CERTIFICATE-----"),
		//			"tls.key": []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC/SsO+9IzQ85xx\nyiT+ou8RDNxZMP0Ja8YKrdu19BTFjyLtVLpb+I1XqzlXFdJcObYZ5ZboyALB00i5\nDs0TTs8ydgEeaw0K2O96DnGh4z5r4qLuF+fpVR+3A8kKRSrqJN1JNPFeb+NKsilU\nNvx5plZBm5+VTd64Sop6r1DALEDBS8AxRJSgp4x/oCq+T4zLh9XDyVUQ68axLgF8\n6sS4YcBYKQVTH7KwRx+FGPFnBqt2ll2IherJ1N1dheXdLqzPYY+uIhs55wUPRhQi\nbjiJhM9NgMYsmOPZRzsPIr6+gUil82rmSfyMg/A0wT4dsm6MT7ly6PPRyxoRvhNv\nfn96FsCRAgMBAAECggEBAJ0fxS8pYi0TnNIej0qU/LdNkAS253EAlFgbPFf1V8Z6\nbt7wdG6s9zQmkV/FrddRFBGrcsxb1V/ts1NGJA6S8j/pi7u3hKv/Sp1AFfg6VwB4\n1QmqmzQeVoGWW2DTNY/DnfvOv9+pGdI2CxqAW9t0VG9pa6hQoPtRRvPE4xgmgT4D\nFgglbPuupMSeRbWXtDs9RfpK2sOyR69p4D8uhNGxM4XFb2d3UEp4RQTpO9YmdMtH\nzrfDEH/HaDKUHAYq7Ki/ibZ5OexI6hcDdsUTIspmLLsUtwTsxWAp/SnwIodkM91K\nI3w0OIuCTm7ILk2US3AEQ4YttN+GriXPudfDi7t7iAECgYEA4hpgd7QegbA20e55\naExJJb3UeitfkMBxOSDtDQwEz4zjETPpYibvnBDW3M3/53nMdsDSO8s1BMotA/y2\n4hmABic2yavx42loTpKgEVWiCKWo/QTaQL9fkuo9U18tWSG89PbVINeb+wvi2HTi\ndb4B9+0LpJD/r5PUFzpBBGUjLRECgYEA2JYHzt6QqJm+fXRf1nZYPkfCxfgkWJdg\naAFfsCYdzwUMrkgDEus9C854mtoZ2tvG63KI0eRjWFXiUScA68wCC2JQwkeHC+Vi\ncL4cepl5xDXEg/em7JSlVVR9MWThA8XoK3+sE7SWkfdnDx9aXX/+ifhpgBjV0DZa\nGv0hpzzYW4ECgYEAvKrB4GDeK918gQR7LjqptuKGEENtBP5v+/mrlH147i9jshEd\nJ5fRzOqIP8ttRBvwLw+K3fYckZiao38Wo+gfWgMSxonB1783GIllI9HO2WRSdH6+\nF9UYzSDEd3MuBfgPEmF9SmBfecZbTb+K0DDyt4yHcJTFph62lYM4iZBTH+ECgYEA\nnNJ9UteqjLnNyQ7jeej02huhtzCGOLNa9dPQ0j23Jbe1R9gSibdU22CjyRQU1nh+\nHusukDO7jzGYjkQckZ+E93M3oISkDwQHdDTjcA4CsgRwh1FhRzoWQKPNhl9R4iaB\nhkWKdjYzM/ucXsHH752G06XP1hWlc353XcVdgbc3vYECgYB4UgYJF+EezWrITWej\n6uiZmzckp+6mXH4VyUd1kwFNwJLnjYput5ixJQ63Yt0LBS98Msa8hGnygEguO9Dx\ntAIDDshlF+pvrCnfrR3XJ7WYMHlQshC6BzJBBqjTDxZ0Wn+mPO1AkitdGdoQ5C+F\nUhLJp+X8pVHlVmXLJp/7LBNbiQ==\n-----END RSA PRIVATE KEY-----"),
		//		},
		//	},
		//	},
		//	signerBuilder:                signer.CzertainlySignerFromIssuerAndSecretData,
		//	expectedReadyConditionStatus: cmmeta.ConditionTrue,
		//	expectedReadyConditionReason: cmapi.CertificateRequestReasonIssued,
		//	expectedFailureTime:          nil,
		//	expectedCertificate:          []byte("-----BEGIN CERTIFICATE-----"), // certificate will be different
		//},
		"success-issuer": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: czertainlyissuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			issuerObjects: []client.Object{&czertainlyissuerapi.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "issuer1",
					Namespace: "ns1",
				},
				Spec: czertainlyissuerapi.IssuerSpec{
					AuthSecretName: "issuer1-credentials",
				},
				Status: czertainlyissuerapi.IssuerStatus{
					Conditions: []czertainlyissuerapi.IssuerCondition{
						{
							Type:   czertainlyissuerapi.IssuerConditionReady,
							Status: czertainlyissuerapi.ConditionTrue,
						},
					},
				},
			},
			},
			secretObjects: []client.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "issuer1-credentials",
					Namespace: "ns1",
				},
			},
			},
			signerBuilder: func(context.Context, *czertainlyissuerapi.IssuerSpec, map[string][]byte, map[string][]byte, map[string]string) (signer.Signer, error) {
				return &fakeSigner{}, nil
			},
			expectedReadyConditionStatus: cmmeta.ConditionTrue,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonIssued,
			expectedFailureTime:          nil,
			expectedCertificate:          []byte("fake signed certificate"),
		},
		"success-cluster-issuer": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "clusterissuer1",
						Group: czertainlyissuerapi.GroupVersion.Group,
						Kind:  "ClusterIssuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			issuerObjects: []client.Object{
				&czertainlyissuerapi.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1",
					},
					Spec: czertainlyissuerapi.IssuerSpec{
						AuthSecretName: "clusterissuer1-credentials",
					},
					Status: czertainlyissuerapi.IssuerStatus{
						Conditions: []czertainlyissuerapi.IssuerCondition{
							{
								Type:   czertainlyissuerapi.IssuerConditionReady,
								Status: czertainlyissuerapi.ConditionTrue,
							},
						},
					},
				},
			},
			secretObjects: []client.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "clusterissuer1-credentials",
					Namespace: "kube-system",
				},
			}},
			signerBuilder: func(context.Context, *czertainlyissuerapi.IssuerSpec, map[string][]byte, map[string][]byte, map[string]string) (signer.Signer, error) {
				return &fakeSigner{}, nil
			},
			clusterResourceNamespace:     "kube-system",
			expectedReadyConditionStatus: cmmeta.ConditionTrue,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonIssued,
			expectedFailureTime:          nil,
			expectedCertificate:          []byte("fake signed certificate"),
		},
		"certificaterequest-not-found": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
		},
		"issuer-ref-foreign-group": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: "foreign-issuer.example.com",
					}),
				),
			},
		},
		"certificaterequest-already-ready": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: czertainlyissuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionTrue,
					}),
				),
			},
		},
		"certificaterequest-missing-ready-condition": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: czertainlyissuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
				),
			},
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"issuer-ref-unknown-kind": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: czertainlyissuerapi.GroupVersion.Group,
						Kind:  "ForeignKind",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonFailed,
		},
		"issuer-not-found": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: czertainlyissuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			expectedError:                errGetIssuer,
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"clusterissuer-not-found": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "clusterissuer1",
						Group: czertainlyissuerapi.GroupVersion.Group,
						Kind:  "ClusterIssuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			expectedError:                errGetIssuer,
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"issuer-not-ready": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: czertainlyissuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			issuerObjects: []client.Object{
				&czertainlyissuerapi.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Status: czertainlyissuerapi.IssuerStatus{
						Conditions: []czertainlyissuerapi.IssuerCondition{
							{
								Type:   czertainlyissuerapi.IssuerConditionReady,
								Status: czertainlyissuerapi.ConditionFalse,
							},
						},
					},
				},
			},
			expectedError:                errIssuerNotReady,
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"issuer-secret-not-found": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: czertainlyissuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			issuerObjects: []client.Object{
				&czertainlyissuerapi.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: czertainlyissuerapi.IssuerSpec{
						AuthSecretName: "issuer1-credentials",
					},
					Status: czertainlyissuerapi.IssuerStatus{
						Conditions: []czertainlyissuerapi.IssuerCondition{
							{
								Type:   czertainlyissuerapi.IssuerConditionReady,
								Status: czertainlyissuerapi.ConditionTrue,
							},
						},
					},
				},
			},
			expectedError:                errGetAuthSecret,
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"signer-builder-error": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: czertainlyissuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			secretObjects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
				},
			},
			issuerObjects: []client.Object{
				&czertainlyissuerapi.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: czertainlyissuerapi.IssuerSpec{
						AuthSecretName: "issuer1-credentials",
					},
					Status: czertainlyissuerapi.IssuerStatus{
						Conditions: []czertainlyissuerapi.IssuerCondition{
							{
								Type:   czertainlyissuerapi.IssuerConditionReady,
								Status: czertainlyissuerapi.ConditionTrue,
							},
						},
					},
				},
			},
			signerBuilder: func(context.Context, *czertainlyissuerapi.IssuerSpec, map[string][]byte, map[string][]byte, map[string]string) (signer.Signer, error) {
				return nil, errors.New("simulated signer builder error")
			},
			expectedError:                errSignerBuilder,
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"signer-error": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: czertainlyissuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			secretObjects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
				},
			},
			issuerObjects: []client.Object{
				&czertainlyissuerapi.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: czertainlyissuerapi.IssuerSpec{
						AuthSecretName: "issuer1-credentials",
					},
					Status: czertainlyissuerapi.IssuerStatus{
						Conditions: []czertainlyissuerapi.IssuerCondition{
							{
								Type:   czertainlyissuerapi.IssuerConditionReady,
								Status: czertainlyissuerapi.ConditionTrue,
							},
						},
					},
				},
			},
			signerBuilder: func(context.Context, *czertainlyissuerapi.IssuerSpec, map[string][]byte, map[string][]byte, map[string]string) (signer.Signer, error) {
				return &fakeSigner{errSign: errors.New("simulated sign error")}, nil
			},
			expectedError:                errSignerSign,
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"request-not-approved": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: czertainlyissuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			secretObjects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
				},
			},
			issuerObjects: []client.Object{
				&czertainlyissuerapi.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: czertainlyissuerapi.IssuerSpec{
						AuthSecretName: "issuer1-credentials",
					},
					Status: czertainlyissuerapi.IssuerStatus{
						Conditions: []czertainlyissuerapi.IssuerCondition{
							{
								Type:   czertainlyissuerapi.IssuerConditionReady,
								Status: czertainlyissuerapi.ConditionTrue,
							},
						},
					},
				},
			},
			signerBuilder: func(context.Context, *czertainlyissuerapi.IssuerSpec, map[string][]byte, map[string][]byte, map[string]string) (signer.Signer, error) {
				return &fakeSigner{}, nil
			},
			expectedFailureTime: nil,
			expectedCertificate: nil,
		},
		"request-denied": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			crObjects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: czertainlyissuerapi.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionDenied,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			issuerObjects: []client.Object{
				&czertainlyissuerapi.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: czertainlyissuerapi.IssuerSpec{
						AuthSecretName: "issuer1-credentials",
					},
					Status: czertainlyissuerapi.IssuerStatus{
						Conditions: []czertainlyissuerapi.IssuerCondition{
							{
								Type:   czertainlyissuerapi.IssuerConditionReady,
								Status: czertainlyissuerapi.ConditionTrue,
							},
						},
					},
				},
			},
			secretObjects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
				},
			},
			signerBuilder: func(context.Context, *czertainlyissuerapi.IssuerSpec, map[string][]byte, map[string][]byte, map[string]string) (signer.Signer, error) {
				return &fakeSigner{}, nil
			},
			expectedCertificate:          nil,
			expectedFailureTime:          &nowMetaTime,
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonDenied,
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, czertainlyissuerapi.AddToScheme(scheme))
	require.NoError(t, cmapi.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			eventRecorder := record.NewFakeRecorder(100)
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tc.secretObjects...).
				WithObjects(tc.crObjects...).
				WithObjects(tc.issuerObjects...).
				WithStatusSubresource(tc.issuerObjects...).
				WithStatusSubresource(tc.crObjects...).
				Build()
			controller := CertificateRequestReconciler{
				Client:                   fakeClient,
				Scheme:                   scheme,
				ClusterResourceNamespace: tc.clusterResourceNamespace,
				SignerBuilder:            tc.signerBuilder,
				CheckApprovedCondition:   true,
				Clock:                    fixedClock,
				recorder:                 eventRecorder,
			}

			var crBefore cmapi.CertificateRequest
			if err := fakeClient.Get(context.TODO(), tc.name, &crBefore); err != nil {
				require.NoError(t, client.IgnoreNotFound(err), "unexpected error from fake client")
			}

			result, reconcileErr := controller.Reconcile(
				ctrl.LoggerInto(context.TODO(), logrtesting.NewTestLogger(t)),
				reconcile.Request{NamespacedName: tc.name},
			)

			var actualEvents []string
			for {
				select {
				case e := <-eventRecorder.Events:
					actualEvents = append(actualEvents, e)
					continue
				default:
					break
				}
				break
			}
			if tc.expectedError != nil {
				assertErrorIs(t, tc.expectedError, reconcileErr)
			} else {
				assert.NoError(t, reconcileErr)
			}

			assert.Equal(t, tc.expectedResult, result, "Unexpected result")

			// For tests where the target CertificateRequest exists, we perform some further checks,
			// otherwise exit early.
			var crAfter cmapi.CertificateRequest
			if err := fakeClient.Get(context.TODO(), tc.name, &crAfter); err != nil {
				require.NoError(t, client.IgnoreNotFound(err), "unexpected error from fake client")
				return
			}

			// If the CR is unchanged after the Reconcile then we expect no
			// Events and need not perform any further checks.
			// NB: controller-runtime FakeClient updates the Resource version.
			if crBefore.ResourceVersion == crAfter.ResourceVersion {
				assert.Empty(t, actualEvents, "Events should only be created if the CertificateRequest is modified")
				return
			}

			// Certificate checks.
			// Always check the certificate, in case it has been unexpectedly
			// set without also having first added and updated the Ready
			// condition.
			assert.Equal(t, tc.expectedCertificate, crAfter.Status.Certificate)

			if !apiequality.Semantic.DeepEqual(tc.expectedFailureTime, crAfter.Status.FailureTime) {
				assert.Equal(t, tc.expectedFailureTime, crAfter.Status.FailureTime)
			}

			// Condition checks
			condition := cmutil.GetCertificateRequestCondition(&crAfter, cmapi.CertificateRequestConditionReady)
			// If the CertificateRequest is expected to have a Ready condition then we perform some extra checks.
			if tc.expectedReadyConditionStatus != "" {
				if assert.NotNilf(
					t,
					condition,
					"Ready condition was expected but not found: tc.expectedReadyConditionStatus == %v",
					tc.expectedReadyConditionStatus,
				) {
					verifyCertificateRequestReadyCondition(t, tc.expectedReadyConditionStatus, tc.expectedReadyConditionReason, condition)
				}
			} else {
				assert.Nil(t, condition, "Unexpected Ready condition")
			}

			// Event checks
			if condition != nil {
				// The desired Event behaviour is as follows:
				//
				// * An Event should always be generated when the Ready condition is set.
				// * Event contents should match the status and message of the condition.
				// * Event type should be Warning if the Reconcile failed (temporary error)
				// * Event type should be warning if the condition status is failed (permanent error)
				expectedEventType := corev1.EventTypeNormal
				if reconcileErr != nil || condition.Reason == cmapi.CertificateRequestReasonFailed {
					expectedEventType = corev1.EventTypeWarning
				}
				// If there was a Reconcile error, there will be a retry and
				// this should be reflected in the Event message.
				eventMessage := condition.Message
				if reconcileErr != nil {
					eventMessage = fmt.Sprintf("Temporary error. Retrying: %v", reconcileErr)
				}
				// Each Reconcile should only emit a single Event
				assert.Equal(
					t,
					[]string{fmt.Sprintf("%s %s %s", expectedEventType, czertainlyissuerapi.EventReasonCertificateRequestReconciler, eventMessage)},
					actualEvents,
					"expected a single event matching the condition",
				)
			} else {
				assert.Empty(t, actualEvents, "Found unexpected Events without a corresponding Ready condition")
			}
		})
	}
}

func assertErrorIs(t *testing.T, expectedError, actualError error) {
	if !assert.Error(t, actualError) {
		return
	}
	assert.Truef(t, errors.Is(actualError, expectedError), "unexpected error type. expected: %v, got: %v", expectedError, actualError)
}

func verifyCertificateRequestReadyCondition(t *testing.T, status cmmeta.ConditionStatus, reason string, condition *cmapi.CertificateRequestCondition) {
	assert.Equal(t, status, condition.Status, "unexpected condition status")
	validReasons := sets.NewString(
		cmapi.CertificateRequestReasonPending,
		cmapi.CertificateRequestReasonFailed,
		cmapi.CertificateRequestReasonIssued,
		cmapi.CertificateRequestReasonDenied,
	)
	assert.Contains(t, validReasons, reason, "unexpected condition reason")
	assert.Equal(t, reason, condition.Reason, "unexpected condition reason")
}
