package constants

import "time"

const (
	// DefaultPolicyServer is the default policy server name to be used when
	// policies does not have a policy server name defined.
	DefaultPolicyServer = "default"

	// PolicyServer Deployment.
	PolicyServerEnableMetricsEnvVar                 = "KUBEWARDEN_ENABLE_METRICS"
	PolicyServerDeploymentConfigVersionAnnotation   = "kubewarden/config-version"
	PolicyServerDeploymentPodSpecConfigVersionLabel = "kubewarden/config-version"
	PolicyServerPort                                = 8443
	PolicyServerMetricsPortEnvVar                   = "KUBEWARDEN_POLICY_SERVER_SERVICES_METRICS_PORT"
	PolicyServerMetricsPort                         = 8080
	PolicyServerReadinessProbe                      = "/readiness"
	PolicyServerLogFmtEnvVar                        = "KUBEWARDEN_LOG_FMT"

	// PolicyServer ConfigMap.
	PolicyServerConfigPoliciesEntry         = "policies.yml"
	PolicyServerDeploymentRestartAnnotation = "kubectl.kubernetes.io/restartedAt"
	PolicyServerConfigSourcesEntry          = "sources.yml"
	PolicyServerSourcesConfigContainerPath  = "/sources"

	// PolicyServer VerificationSecret.
	PolicyServerVerificationConfigEntry         = "verification-config"
	PolicyServerVerificationConfigContainerPath = "/verification"

	// Labels.
	AppLabelKey                     = "app"
	PolicyServerLabelKey            = "kubewarden/policy-server"
	PartOfLabelKey                  = "app.kubernetes.io/part-of"
	PartOfLabelValue                = "kubewarden"
	ComponentLabelKey               = "app.kubernetes.io/component"
	ComponentPolicyServerLabelValue = "policy-server"

	// Index.
	PolicyServerIndexKey = ".spec.policyServer"

	// Finalizers.
	KubewardenFinalizerPre114 = "kubewarden"
	KubewardenFinalizer       = "kubewarden.io/finalizer"

	// Kubernetes.
	KubernetesRevisionAnnotation = "deployment.kubernetes.io/revision"

	// OPTEL.
	OptelInjectAnnotation = "sidecar.opentelemetry.io/inject"

	// Webhook Configurations.
	WebhookConfigurationPolicyNameAnnotationKey      = "kubewardenPolicyName"
	WebhookConfigurationPolicyNamespaceAnnotationKey = "kubewardenPolicyNamespace"

	// Scope.
	NamespacePolicyScope = "namespace"
	ClusterPolicyScope   = "cluster"

	// Duration to be used when a policy should be reconciliation should be
	/// requeued.
	TimeToRequeuePolicyReconciliation = 2 * time.Second
	MetricsShutdownTimeout            = 5 * time.Second

	// Server Cert Secrets.
	WebhookServerCertSecretName = "kubewarden-webhook-server-cert" //nolint:gosec // This is not a credential
	ServerCert                  = "tls.crt"
	ServerPrivateKey            = "tls.key"

	// CA Root Secret.
	CARootSecretName = "kubewarden-ca"
	CARootCert       = "ca.crt"
	CARootPrivateKey = "ca.key"
	OldCARootCert    = "old-ca.crt"

	// Client CA ConfigMap.
	ClientCACert = "client-ca.crt"

	// Certs.
	CertExpirationYears  = 10
	CACertExpiration     = 10 * 365 * 24 * time.Hour
	ServerCertExpiration = 1 * 365 * 24 * time.Hour
	CertLookahead        = 60 * 24 * time.Hour
)
