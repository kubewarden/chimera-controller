/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"errors"
	"flag"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8spoliciesv1 "k8s.io/api/policy/v1"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/api/policies/v1alpha2"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
	"github.com/kubewarden/kubewarden-controller/internal/controller"
	"github.com/kubewarden/kubewarden-controller/internal/featuregates"
	"github.com/kubewarden/kubewarden-controller/internal/metrics"
	//+kubebuilder:scaffold:imports
)

//nolint:gochecknoglobals // Following the kubebuilder pattern
var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha2.AddToScheme(scheme))
	utilruntime.Must(policiesv1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

//nolint:funlen // Avoid splitting the main function in multiple functions to avoid changing the retcode logic for metrics shutdown
func main() {
	retcode := 0
	defer func() { os.Exit(retcode) }()

	var metricsAddr string
	var enableLeaderElection bool
	var deploymentsNamespace string
	var webhookServiceName string
	var alwaysAcceptAdmissionReviewsOnDeploymentsNamespace bool
	var probeAddr string
	var enableMetrics bool
	var enableTracing bool
	var enableOtelSidecar bool
	var openTelemetryClientCertificateSecret string
	var openTelemetryCertificateSecret string
	var clientCAConfigMapName string

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8088", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&enableMetrics, "enable-metrics", false,
		"Enable metrics collection for all Policy Servers and the Kubewarden Controller")
	flag.BoolVar(&enableTracing, "enable-tracing", false,
		"Enable tracing collection for all Policy Servers")
	flag.BoolVar(&enableOtelSidecar, "enable-otel-sidecar", false,
		"Enable OpenTelemetry sidecar in Policy Servers")
	flag.StringVar(&openTelemetryClientCertificateSecret, "opentelemetry-client-certificate-secret", "", "")
	flag.StringVar(&openTelemetryCertificateSecret, "opentelemetry-certificate-secret", "", "")
	flag.StringVar(&deploymentsNamespace,
		"deployments-namespace",
		"",
		"The namespace where the kubewarden resources will be created.")
	flag.StringVar(&webhookServiceName,
		"webhook-service-name",
		"kubewarden-controller-webhook-service",
		"The name of the service that will be used to expose controller webhooks.")
	flag.BoolVar(&alwaysAcceptAdmissionReviewsOnDeploymentsNamespace,
		"always-accept-admission-reviews-on-deployments-namespace",
		false,
		"Always accept admission reviews targeting the deployments-namespace.")
	flag.StringVar(&clientCAConfigMapName, "client-ca-configmap-name", "", "The name of the ConfigMap containing the client CA certificate. If provided, mTLS will be enabled.")

	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if enableMetrics {
		shutdown, err := metrics.New()
		if err != nil {
			setupLog.Error(err, "unable to initialize metrics provider")
			retcode = 1
			return
		}
		setupLog.Info("Metrics initialized")

		// cleanly shutdown and flush telemetry on application exit
		defer func() {
			// Do not make the application hang when it is shutdown.
			ctx, cancel := context.WithTimeout(context.Background(), constants.MetricsShutdownTimeout)
			defer cancel()

			if err := shutdown(ctx); err != nil { //nolint:govet // err is shadowed in purpose
				setupLog.Error(err, "Unable to shutdown telemetry")
				retcode = 1
				return
			}
		}()
	}

	mgr, err := setupManager(deploymentsNamespace, metricsAddr, probeAddr, enableLeaderElection, clientCAConfigMapName != "")
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		retcode = 1
		return
	}

	featureGateAdmissionWebhookMatchConditions, err := featuregates.CheckAdmissionWebhookMatchConditions(ctrl.GetConfigOrDie())
	if err != nil {
		setupLog.Error(err, "unable to check for feature gate AdmissionWebhookMatchConditions")
	}

	otelConfiguration := controller.TelemetryConfiguration{
		MetricsEnabled:              enableMetrics,
		TracingEnabled:              enableTracing,
		OtelSidecarEnabled:          enableOtelSidecar,
		OtelCertificateSecret:       openTelemetryCertificateSecret,
		OtelClientCertificateSecret: openTelemetryClientCertificateSecret,
	}
	if err = setupReconcilers(mgr,
		deploymentsNamespace,
		webhookServiceName,
		alwaysAcceptAdmissionReviewsOnDeploymentsNamespace,
		featureGateAdmissionWebhookMatchConditions,
		otelConfiguration,
		clientCAConfigMapName,
	); err != nil {
		setupLog.Error(err, "unable to create controllers")
		retcode = 1
		return
	}

	if err = setupWebhooks(mgr, deploymentsNamespace); err != nil {
		setupLog.Error(err, "unable to create webhooks")
		retcode = 1
		return
	}

	//+kubebuilder:scaffold:builder

	if err = setupProbes(mgr); err != nil {
		setupLog.Error(err, "unable to set up probes")
		retcode = 1
		return
	}

	setupLog.Info("starting manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		retcode = 1
		return
	}
}

func setupManager(deploymentsNamespace string, metricsAddr string, probeAddr string, enableLeaderElection bool, enableMutualTLS bool) (ctrl.Manager, error) {
	namespaceSelector := cache.ByObject{
		Field: fields.ParseSelectorOrDie("metadata.namespace=" + deploymentsNamespace),
	}

	clientCAName := ""
	if enableMutualTLS {
		clientCAName = constants.ClientCACert
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "a4ddbf36.kubewarden.io",
		// Warning: the manager creates a client, which then uses Watches to monitor
		// certain resources. By default, the client is not going to be namespaced,
		// it will be able to watch resources across the entire cluster. This is of
		// course constrained by the RBAC rules applied to the ServiceAccount that
		// runs the controller.
		// *However*, even when accessing a resource inside a specific Namespace,
		// the default behavior of the cache is to create a Watch that is not namespaced;
		// hence requires the privilege to access all the resources of that type inside
		// of the cluster. That can cause runtime error if the ServiceAccount lacking
		// this privilege.
		// For example, when we access a secret inside the `kubewarden`
		// namespace, the cache will create a Watch against Secrets, that will require
		// privileged to access ALL the secrets of the cluster.
		//
		// To be able to have stricter RBAC rules, we need to instruct the cache to
		// only watch objects inside of the namespace where the controller is running.
		// That applies ONLY to the namespaced resources that we know the controller
		// is going to own inside of a specific namespace.
		// For example, Secret resources are going to be defined by the controller
		// only inside of the `kubewarden` namespace; hence their watch can be namespaced.
		// On the other hand, AdmissionPolicy resources are namespaced, but the controller
		// requires to access them across all the namespaces of the cluster; hence the
		// cache must not be namespaced.
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&appsv1.ReplicaSet{}:                 namespaceSelector,
				&corev1.Secret{}:                     namespaceSelector,
				&corev1.Pod{}:                        namespaceSelector,
				&corev1.Service{}:                    namespaceSelector,
				&k8spoliciesv1.PodDisruptionBudget{}: namespaceSelector,
				&corev1.ConfigMap{}:                  namespaceSelector,
				&appsv1.Deployment{}:                 namespaceSelector,
			},
		},
		WebhookServer: webhook.NewServer(webhook.Options{
			ClientCAName: clientCAName,
		}),
	})
	return mgr, err
}

func setupProbes(mgr ctrl.Manager) error {
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return errors.Join(errors.New("unable to set up health check"), err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return errors.Join(errors.New("unable to set up ready check"), err)
	}
	return nil
}

func setupReconcilers(mgr ctrl.Manager,
	deploymentsNamespace,
	webhookServiceName string,
	alwaysAcceptAdmissionReviewsOnDeploymentsNamespace,
	featureGateAdmissionWebhookMatchConditions bool,
	otelConfiguration controller.TelemetryConfiguration,
	clientCAConfigMapName string,
) error {
	if err := (&controller.PolicyServerReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		Log:                  ctrl.Log.WithName("policy-server-reconciler"),
		DeploymentsNamespace: deploymentsNamespace,
		AlwaysAcceptAdmissionReviewsInDeploymentsNamespace: alwaysAcceptAdmissionReviewsOnDeploymentsNamespace,
		TelemetryConfiguration:                             otelConfiguration,
		ClientCAConfigMapName:                              clientCAConfigMapName,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create PolicyServer controller"), err)
	}

	if err := (&controller.AdmissionPolicyReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		Log:                  ctrl.Log.WithName("admission-policy-reconciler"),
		DeploymentsNamespace: deploymentsNamespace,
		FeatureGateAdmissionWebhookMatchConditions: featureGateAdmissionWebhookMatchConditions,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create AdmissionPolicy controller"), err)
	}

	if err := (&controller.ClusterAdmissionPolicyReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		Log:                  ctrl.Log.WithName("cluster-admission-policy-reconciler"),
		DeploymentsNamespace: deploymentsNamespace,
		FeatureGateAdmissionWebhookMatchConditions: featureGateAdmissionWebhookMatchConditions,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create ClusterAdmissionPolicy controller"), err)
	}

	if err := (&controller.CertReconciler{
		Client:                      mgr.GetClient(),
		Log:                         ctrl.Log.WithName("cert-recociler"),
		DeploymentsNamespace:        deploymentsNamespace,
		WebhookServiceName:          webhookServiceName,
		CARootSecretName:            constants.CARootSecretName,
		WebhookServerCertSecretName: constants.WebhookServerCertSecretName,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create Cert controller"), err)
	}

	if err := (&controller.AdmissionPolicyGroupReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		Log:                  ctrl.Log.WithName("admission-policy-group-reconciler"),
		DeploymentsNamespace: deploymentsNamespace,
		FeatureGateAdmissionWebhookMatchConditions: featureGateAdmissionWebhookMatchConditions,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create AdmissionPolicyGroup controller"), err)
	}

	if err := (&controller.ClusterAdmissionPolicyGroupReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		Log:                  ctrl.Log.WithName("cluster-admission-policy-group-reconciler"),
		DeploymentsNamespace: deploymentsNamespace,
		FeatureGateAdmissionWebhookMatchConditions: featureGateAdmissionWebhookMatchConditions,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create ClusterAdmissionPolicyGroup controller"), err)
	}
	return nil
}

func setupWebhooks(mgr ctrl.Manager, deploymentsNamespace string) error {
	if err := (&policiesv1.PolicyServer{}).SetupWebhookWithManager(mgr, deploymentsNamespace); err != nil {
		return errors.Join(errors.New("unable to create webhook for policy servers"), err)
	}
	if err := (&policiesv1.ClusterAdmissionPolicy{}).SetupWebhookWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create webhook for cluster admission policies"), err)
	}
	if err := (&policiesv1.AdmissionPolicy{}).SetupWebhookWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create webhook for admission policies"), err)
	}
	if err := (&policiesv1.AdmissionPolicyGroup{}).SetupWebhookWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create webhook for admission policies groups"), err)
	}
	if err := (&policiesv1.ClusterAdmissionPolicyGroup{}).SetupWebhookWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create webhook for cluster admission policies groups"), err)
	}
	return nil
}
