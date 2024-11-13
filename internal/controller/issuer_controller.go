package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	czertainlyissuerapi "github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/api/v1alpha1"
	"github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/internal/issuer/signer"
	issuerutil "github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/internal/issuer/util"
)

const (
	defaultHealthCheckInterval = time.Minute
)

var (
	errApiUrl               = errors.New("API URL is not set")
	errRaProfileName        = errors.New("RA profile name is not set")
	errGetAuthSecret        = errors.New("failed to get Secret containing Issuer credentials")
	errGetCaBundleSecret    = errors.New("failed to get Secret containing CA bundle")
	errHealthCheckerBuilder = errors.New("failed to build the healthchecker")
	errHealthCheckerCheck   = errors.New("healthcheck failed")
)

// IssuerReconciler reconciles a Issuer object
type IssuerReconciler struct {
	client.Client
	Kind                     string
	Scheme                   *runtime.Scheme
	ClusterResourceNamespace string
	HealthCheckerBuilder     signer.HealthCheckerBuilder
	recorder                 record.EventRecorder
}

// +kubebuilder:rbac:groups=czertainly-issuer.czertainly.com,resources=issuers;clusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=czertainly-issuer.czertainly.com,resources=issuers/status;clusterissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *IssuerReconciler) newIssuer() (client.Object, error) {
	issuerGVK := czertainlyissuerapi.GroupVersion.WithKind(r.Kind)
	ro, err := r.Scheme.New(issuerGVK)
	if err != nil {
		return nil, err
	}
	return ro.(client.Object), nil
}

func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrl.LoggerFrom(ctx)

	issuer, err := r.newIssuer()
	if err != nil {
		log.Error(err, "Unrecognised issuer type")
		return ctrl.Result{}, nil
	}
	if err := r.Get(ctx, req.NamespacedName, issuer); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %v", err)
		}
		log.Info("Not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	issuerSpec, issuerStatus, err := issuerutil.GetSpecAndStatus(issuer)
	if err != nil {
		log.Error(err, "Unexpected error while getting issuer spec and status. Not retrying.")
		return ctrl.Result{}, nil
	}

	// report gives feedback by updating the Ready Condition of the {Cluster}Issuer
	// For added visibility we also log a message and create a Kubernetes Event.
	report := func(conditionStatus czertainlyissuerapi.ConditionStatus, message string, err error) {
		eventType := corev1.EventTypeNormal
		if err != nil {
			log.Error(err, message)
			eventType = corev1.EventTypeWarning
			message = fmt.Sprintf("%s: %v", message, err)
		} else {
			log.Info(message)
		}
		r.recorder.Event(
			issuer,
			eventType,
			czertainlyissuerapi.EventReasonIssuerReconciler,
			message,
		)
		issuerutil.SetReadyCondition(issuerStatus, conditionStatus, czertainlyissuerapi.EventReasonIssuerReconciler, message)
	}

	// Always attempt to update the Ready condition
	defer func() {
		if err != nil {
			report(czertainlyissuerapi.ConditionFalse, "Temporary error. Retrying", err)
		}
		if updateErr := r.Status().Update(ctx, issuer); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	if ready := issuerutil.GetReadyCondition(issuerStatus); ready == nil {
		report(czertainlyissuerapi.ConditionUnknown, "First seen", nil)
		return ctrl.Result{}, nil
	}

	authSecretName := types.NamespacedName{
		Name: issuerSpec.AuthSecretName,
	}

	caBundleSecretName := types.NamespacedName{
		Name: issuerSpec.CaBundleSecretName,
	}

	switch issuer.(type) {
	case *czertainlyissuerapi.Issuer:
		authSecretName.Namespace = req.Namespace
		caBundleSecretName.Namespace = req.Namespace
	case *czertainlyissuerapi.ClusterIssuer:
		authSecretName.Namespace = r.ClusterResourceNamespace
		caBundleSecretName.Namespace = r.ClusterResourceNamespace
	default:
		log.Error(fmt.Errorf("unexpected issuer type: %t", issuer), "Not retrying.")
		return ctrl.Result{}, nil
	}

	var authSecret corev1.Secret
	if err := r.Get(ctx, authSecretName, &authSecret); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w, authSecret name: %s, reason: %v", errGetAuthSecret, authSecretName, err)
	}

	var caBundleSecret corev1.Secret
	// If the issuer has a CA bundle, get it
	if issuerSpec.CaBundleSecretName != "" {
		if err := r.Get(ctx, caBundleSecretName, &caBundleSecret); err != nil {
			return ctrl.Result{}, fmt.Errorf("%w, caBundleSecret name: %s, reason: %v", errGetAuthSecret, caBundleSecretName, err)
		}
	}

	checker, err := r.HealthCheckerBuilder(ctx, issuerSpec, authSecret.Data, caBundleSecret.Data)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errHealthCheckerBuilder, err)
	}

	if err := checker.Check(); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errHealthCheckerCheck, err)
	}

	report(czertainlyissuerapi.ConditionTrue, "Success", nil)
	return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
}

func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	issuerType, err := r.newIssuer()
	if err != nil {
		return err
	}
	r.recorder = mgr.GetEventRecorderFor(czertainlyissuerapi.EventSource)
	return ctrl.NewControllerManagedBy(mgr).
		For(issuerType).
		Complete(r)
}
