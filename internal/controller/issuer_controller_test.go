package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"

	logrtesting "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	czertainlyissuerapi "github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/api/v1alpha1"
	"github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/internal/issuer/signer"
	issuerutil "github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/internal/issuer/util"
)

type fakeHealthChecker struct {
	errCheck error
}

func (o *fakeHealthChecker) Check() error {
	return o.errCheck
}

func TestIssuerReconcile(t *testing.T) {
	type testCase struct {
		kind                         string
		name                         types.NamespacedName
		issuerObjects                []client.Object
		secretObjects                []client.Object
		healthCheckerBuilder         signer.HealthCheckerBuilder
		clusterResourceNamespace     string
		expectedResult               ctrl.Result
		expectedError                error
		expectedReadyConditionStatus czertainlyissuerapi.ConditionStatus
	}

	tests := map[string]testCase{
		// TODO: Remove
		//"online-test": {
		//	kind: "Issuer",
		//	name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
		//	issuerObjects: []client.Object{
		//		&czertainlyissuerapi.Issuer{
		//			ObjectMeta: metav1.ObjectMeta{
		//				Name:      "issuer1",
		//				Namespace: "ns1",
		//			},
		//			Spec: czertainlyissuerapi.IssuerSpec{
		//				ServerUrl:      "https://develop.czertainly.online",
		//				AuthSecretName: "issuer1-credentials",
		//			},
		//			Status: czertainlyissuerapi.IssuerStatus{
		//				Conditions: []czertainlyissuerapi.IssuerCondition{
		//					{
		//						Type:   czertainlyissuerapi.IssuerConditionReady,
		//						Status: czertainlyissuerapi.ConditionUnknown,
		//					},
		//				},
		//			},
		//		},
		//	},
		//	// client1
		//	secretObjects: []client.Object{
		//		&corev1.Secret{
		//			ObjectMeta: metav1.ObjectMeta{
		//				Name:      "issuer1-credentials",
		//				Namespace: "ns1",
		//			},
		//			Type: corev1.SecretTypeTLS,
		//			Data: map[string][]byte{
		//				"tls.crt": []byte("-----BEGIN CERTIFICATE-----\nMIIDPTCCAiUCFBd+dfQuley5j4MetX3iewvIxHZDMA0GCSqGSIb3DQEBCwUAMF0x\nCzAJBgNVBAYTAkNaMRAwDgYDVQQIDAdDemVjaGlhMQswCQYDVQQHDAJDQjENMAsG\nA1UECgwEM0tFWTEMMAoGA1UECwwDREVWMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcN\nMjAwOTI1MTE1NDU3WhcNMzAwODA0MTE1NDU3WjBZMQswCQYDVQQGEwJDWjEQMA4G\nA1UECAwHQ3plY2hpYTELMAkGA1UEBwwCQ0IxCzAJBgNVBAoMAkNGMQwwCgYDVQQL\nDANERVYxEDAOBgNVBAMMB0NMSUVOVDEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\nggEKAoIBAQC/SsO+9IzQ85xxyiT+ou8RDNxZMP0Ja8YKrdu19BTFjyLtVLpb+I1X\nqzlXFdJcObYZ5ZboyALB00i5Ds0TTs8ydgEeaw0K2O96DnGh4z5r4qLuF+fpVR+3\nA8kKRSrqJN1JNPFeb+NKsilUNvx5plZBm5+VTd64Sop6r1DALEDBS8AxRJSgp4x/\noCq+T4zLh9XDyVUQ68axLgF86sS4YcBYKQVTH7KwRx+FGPFnBqt2ll2IherJ1N1d\nheXdLqzPYY+uIhs55wUPRhQibjiJhM9NgMYsmOPZRzsPIr6+gUil82rmSfyMg/A0\nwT4dsm6MT7ly6PPRyxoRvhNvfn96FsCRAgMBAAEwDQYJKoZIhvcNAQELBQADggEB\nAI+YNR82n23p9014wa+99aEWJfujlirY07jhAQmsGTkkFM5QTNJzwi6VYnUwjlJM\nOXw8fEiBVRHUiyLV5RWZGiGZuLdCZgYCjtzCtWuOPidShAK5GpLDipG9upZ+RCNp\nBXVbb6J5tEI0esTSxZ/jwj2JqZZayhRmRXL/j8vGRn74atTILeFwUIYsSreoMI8w\nG1Rk0que09LgP1RmCiSl1GUSTL/lrK/dYaw0orZwUxzKg/KNnTYprYiAIVRsHUz8\nbkd6mGEBCfDdpEp0l7laBej2R8RhGDwuxjma1ZrwlCsKLlpdn2lwzqIEc+Zl7dxi\nLTb1NLMH80f4LCuF1iFCD6E=\n-----END CERTIFICATE-----"),
		//				"tls.key": []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC/SsO+9IzQ85xx\nyiT+ou8RDNxZMP0Ja8YKrdu19BTFjyLtVLpb+I1XqzlXFdJcObYZ5ZboyALB00i5\nDs0TTs8ydgEeaw0K2O96DnGh4z5r4qLuF+fpVR+3A8kKRSrqJN1JNPFeb+NKsilU\nNvx5plZBm5+VTd64Sop6r1DALEDBS8AxRJSgp4x/oCq+T4zLh9XDyVUQ68axLgF8\n6sS4YcBYKQVTH7KwRx+FGPFnBqt2ll2IherJ1N1dheXdLqzPYY+uIhs55wUPRhQi\nbjiJhM9NgMYsmOPZRzsPIr6+gUil82rmSfyMg/A0wT4dsm6MT7ly6PPRyxoRvhNv\nfn96FsCRAgMBAAECggEBAJ0fxS8pYi0TnNIej0qU/LdNkAS253EAlFgbPFf1V8Z6\nbt7wdG6s9zQmkV/FrddRFBGrcsxb1V/ts1NGJA6S8j/pi7u3hKv/Sp1AFfg6VwB4\n1QmqmzQeVoGWW2DTNY/DnfvOv9+pGdI2CxqAW9t0VG9pa6hQoPtRRvPE4xgmgT4D\nFgglbPuupMSeRbWXtDs9RfpK2sOyR69p4D8uhNGxM4XFb2d3UEp4RQTpO9YmdMtH\nzrfDEH/HaDKUHAYq7Ki/ibZ5OexI6hcDdsUTIspmLLsUtwTsxWAp/SnwIodkM91K\nI3w0OIuCTm7ILk2US3AEQ4YttN+GriXPudfDi7t7iAECgYEA4hpgd7QegbA20e55\naExJJb3UeitfkMBxOSDtDQwEz4zjETPpYibvnBDW3M3/53nMdsDSO8s1BMotA/y2\n4hmABic2yavx42loTpKgEVWiCKWo/QTaQL9fkuo9U18tWSG89PbVINeb+wvi2HTi\ndb4B9+0LpJD/r5PUFzpBBGUjLRECgYEA2JYHzt6QqJm+fXRf1nZYPkfCxfgkWJdg\naAFfsCYdzwUMrkgDEus9C854mtoZ2tvG63KI0eRjWFXiUScA68wCC2JQwkeHC+Vi\ncL4cepl5xDXEg/em7JSlVVR9MWThA8XoK3+sE7SWkfdnDx9aXX/+ifhpgBjV0DZa\nGv0hpzzYW4ECgYEAvKrB4GDeK918gQR7LjqptuKGEENtBP5v+/mrlH147i9jshEd\nJ5fRzOqIP8ttRBvwLw+K3fYckZiao38Wo+gfWgMSxonB1783GIllI9HO2WRSdH6+\nF9UYzSDEd3MuBfgPEmF9SmBfecZbTb+K0DDyt4yHcJTFph62lYM4iZBTH+ECgYEA\nnNJ9UteqjLnNyQ7jeej02huhtzCGOLNa9dPQ0j23Jbe1R9gSibdU22CjyRQU1nh+\nHusukDO7jzGYjkQckZ+E93M3oISkDwQHdDTjcA4CsgRwh1FhRzoWQKPNhl9R4iaB\nhkWKdjYzM/ucXsHH752G06XP1hWlc353XcVdgbc3vYECgYB4UgYJF+EezWrITWej\n6uiZmzckp+6mXH4VyUd1kwFNwJLnjYput5ixJQ63Yt0LBS98Msa8hGnygEguO9Dx\ntAIDDshlF+pvrCnfrR3XJ7WYMHlQshC6BzJBBqjTDxZ0Wn+mPO1AkitdGdoQ5C+F\nUhLJp+X8pVHlVmXLJp/7LBNbiQ==\n-----END RSA PRIVATE KEY-----"),
		//			},
		//		},
		//	},
		//	healthCheckerBuilder:         signer.CzertainlyHealthCheckerFromIssuerAndSecretData,
		//	expectedReadyConditionStatus: czertainlyissuerapi.ConditionTrue,
		//	expectedResult:               ctrl.Result{RequeueAfter: defaultHealthCheckInterval},
		//},
		"success-issuer": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
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
								Status: czertainlyissuerapi.ConditionUnknown,
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
			healthCheckerBuilder: func(context.Context, *czertainlyissuerapi.IssuerSpec, map[string][]byte, map[string][]byte) (signer.HealthChecker, error) {
				return &fakeHealthChecker{}, nil
			},
			expectedReadyConditionStatus: czertainlyissuerapi.ConditionTrue,
			expectedResult:               ctrl.Result{RequeueAfter: defaultHealthCheckInterval},
		},
		"success-clusterissuer": {
			kind: "ClusterIssuer",
			name: types.NamespacedName{Name: "clusterissuer1"},
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
								Status: czertainlyissuerapi.ConditionUnknown,
							},
						},
					},
				},
			},
			secretObjects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "clusterissuer1-credentials",
						Namespace: "kube-system",
					},
				},
			},
			healthCheckerBuilder: func(context.Context, *czertainlyissuerapi.IssuerSpec, map[string][]byte, map[string][]byte) (signer.HealthChecker, error) {
				return &fakeHealthChecker{}, nil
			},
			clusterResourceNamespace:     "kube-system",
			expectedReadyConditionStatus: czertainlyissuerapi.ConditionTrue,
			expectedResult:               ctrl.Result{RequeueAfter: defaultHealthCheckInterval},
		},
		"issuer-kind-unrecognised": {
			kind: "UnrecognizedType",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
		},
		"issuer-not-found": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
		},
		"issuer-missing-ready-condition": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			issuerObjects: []client.Object{
				&czertainlyissuerapi.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
				},
			},
			expectedReadyConditionStatus: czertainlyissuerapi.ConditionUnknown,
		},
		"issuer-missing-secret": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
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
								Status: czertainlyissuerapi.ConditionUnknown,
							},
						},
					},
				},
			},
			expectedError:                errGetAuthSecret,
			expectedReadyConditionStatus: czertainlyissuerapi.ConditionFalse,
		},
		"issuer-failing-healthchecker-builder": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
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
								Status: czertainlyissuerapi.ConditionUnknown,
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
			healthCheckerBuilder: func(context.Context, *czertainlyissuerapi.IssuerSpec, map[string][]byte, map[string][]byte) (signer.HealthChecker, error) {
				return nil, errors.New("simulated health checker builder error")
			},
			expectedError:                errHealthCheckerBuilder,
			expectedReadyConditionStatus: czertainlyissuerapi.ConditionFalse,
		},
		"issuer-failing-healthchecker-check": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
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
								Status: czertainlyissuerapi.ConditionUnknown,
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
			healthCheckerBuilder: func(context.Context, *czertainlyissuerapi.IssuerSpec, map[string][]byte, map[string][]byte) (signer.HealthChecker, error) {
				return &fakeHealthChecker{errCheck: errors.New("simulated health check error")}, nil
			},
			expectedError:                errHealthCheckerCheck,
			expectedReadyConditionStatus: czertainlyissuerapi.ConditionFalse,
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, czertainlyissuerapi.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			eventRecorder := record.NewFakeRecorder(100)
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tc.secretObjects...).
				WithObjects(tc.issuerObjects...).
				WithStatusSubresource(tc.issuerObjects...).
				Build()
			if tc.kind == "" {
				tc.kind = "Issuer"
			}
			controller := IssuerReconciler{
				Kind:                     tc.kind,
				Client:                   fakeClient,
				Scheme:                   scheme,
				HealthCheckerBuilder:     tc.healthCheckerBuilder,
				ClusterResourceNamespace: tc.clusterResourceNamespace,
				recorder:                 eventRecorder,
			}

			issuerBefore, err := controller.newIssuer()
			if err == nil {
				if err := fakeClient.Get(context.TODO(), tc.name, issuerBefore); err != nil {
					require.NoError(t, client.IgnoreNotFound(err), "unexpected error from fake client")
				}
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

			// For tests where the target {Cluster}Issuer exists, we perform some further checks,
			// otherwise exit early.
			issuerAfter, err := controller.newIssuer()
			if err == nil {
				if err := fakeClient.Get(context.TODO(), tc.name, issuerAfter); err != nil {
					require.NoError(t, client.IgnoreNotFound(err), "unexpected error from fake client")
				}
			}
			if issuerAfter == nil {
				return
			}

			// If the CR is unchanged after the Reconcile then we expect no
			// Events and need not perform any further checks.
			// NB: controller-runtime FakeClient updates the Resource version.
			if issuerBefore.GetResourceVersion() == issuerAfter.GetResourceVersion() {
				assert.Empty(t, actualEvents, "Events should only be created if the {Cluster}Issuer is modified")
				return
			}
			_, issuerStatusAfter, err := issuerutil.GetSpecAndStatus(issuerAfter)
			require.NoError(t, err)

			condition := issuerutil.GetReadyCondition(issuerStatusAfter)

			if tc.expectedReadyConditionStatus != "" {
				if assert.NotNilf(
					t,
					condition,
					"Ready condition was expected but not found: tc.expectedReadyConditionStatus == %v",
					tc.expectedReadyConditionStatus,
				) {
					verifyIssuerReadyCondition(t, tc.expectedReadyConditionStatus, condition)
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
				if reconcileErr != nil || condition.Status == czertainlyissuerapi.ConditionFalse {
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
					[]string{fmt.Sprintf("%s %s %s", expectedEventType, czertainlyissuerapi.EventReasonIssuerReconciler, eventMessage)},
					actualEvents,
					"expected a single event matching the condition",
				)
			} else {
				assert.Empty(t, actualEvents, "Found unexpected Events without a corresponding Ready condition")
			}
		})
	}
}

func verifyIssuerReadyCondition(t *testing.T, status czertainlyissuerapi.ConditionStatus, condition *czertainlyissuerapi.IssuerCondition) {
	assert.Equal(t, status, condition.Status, "unexpected condition status")
}
