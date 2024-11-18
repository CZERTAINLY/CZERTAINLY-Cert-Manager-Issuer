package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/klog/v2"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	czertainlyissuerv1alpha1 "github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/api/v1alpha1"
	"github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/internal/controllers"
	"github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/internal/signer"
	"github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/internal/version"
	//+kubebuilder:scaffold:imports
)

const inClusterNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

func main() {
	var metricsAddr string
	var probeAddr string
	var enableLeaderElection bool
	var clusterResourceNamespace string
	var printVersion bool
	var disableApprovedCheck bool

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&clusterResourceNamespace, "cluster-resource-namespace", "", "The namespace for secrets in which cluster-scoped resources are found.")
	flag.BoolVar(&printVersion, "version", false, "Print version to stdout and exit")
	flag.BoolVar(&disableApprovedCheck, "disable-approved-check", false,
		"Disables waiting for CertificateRequests to have an approved condition before signing.")

	// Options for configuring logging
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)

	flag.Parse()

	logr := zap.New(zap.UseFlagOptions(&opts))

	klog.SetLogger(logr)
	ctrl.SetLogger(logr)

	logr.Info("Version", "version", version.Version)

	if printVersion {
		return
	}

	setupLog := logr.WithName("setup")

	if err := getInClusterNamespace(&clusterResourceNamespace); err != nil {
		if errors.Is(err, errNotInCluster) {
			setupLog.Error(err, "please supply --cluster-resource-namespace")
		} else {
			setupLog.Error(err, "unexpected error while getting in-cluster Namespace")
		}
		os.Exit(1)
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(cmapi.AddToScheme(scheme))
	utilruntime.Must(czertainlyissuerv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme

	setupLog.Info(
		"starting",
		"version", version.Version,
		"enable-leader-election", enableLeaderElection,
		"metrics-addr", metricsAddr,
		"cluster-resource-namespace", clusterResourceNamespace,
	)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: server.Options{
			BindAddress: metricsAddr,
		},
		WebhookServer: webhook.NewServer(webhook.Options{
			Port: 9443,
		}),
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "54c549fd.example.com",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(ctrl.SetupSignalHandler())
	defer cancel()

	if err = (&controllers.Issuer{
		HealthCheckerBuilder:     signer.CzertainlyHealthCheckerFromIssuerAndSecretData,
		SignerBuilder:            signer.CzertainlySignerFromIssuerAndSecretData,
		ClusterResourceNamespace: clusterResourceNamespace,
	}).SetupWithManager(ctx, mgr); err != nil {
		setupLog.Error(err, "unable to create Signer controllers")
		os.Exit(1)
	}

	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

var errNotInCluster = errors.New("not running in-cluster")

// Copied from controller-runtime/pkg/leaderelection
func getInClusterNamespace(clusterResourceNamespace *string) error {
	if *clusterResourceNamespace != "" {
		return nil
	}

	// Check whether the namespace file exists.
	// If not, we are not running in cluster so can't guess the namespace.
	_, err := os.Stat(inClusterNamespacePath)
	if os.IsNotExist(err) {
		return errNotInCluster
	} else if err != nil {
		return fmt.Errorf("error checking namespace file: %w", err)
	}

	// Load the namespace file and return its content
	namespace, err := os.ReadFile(inClusterNamespacePath)
	if err != nil {
		return fmt.Errorf("error reading namespace file: %w", err)
	}
	*clusterResourceNamespace = string(namespace)

	return nil
}
