package constants

const (
	// PolicyServer Secret
	PolicyServerTLSCert                  = "policy-server-cert"
	PolicyServerTLSKey                   = "policy-server-key"
	PolicyServerCARootSecretName         = "policy-server-root-ca"
	PolicyServerCARootPemName            = "policy-server-root-ca-pem"
	PolicyServerCARootCACert             = "policy-server-root-ca-cert"
	PolicyServerCARootPrivateKeyCertName = "policy-server-root-ca-privatekey-cert"

	// PolicyServer Deployment
	PolicyServerDeploymentConfigAnnotation = "config/version"
	PolicyServerPort                       = 8443
	PolicyServerReadinessProbe             = "/readiness"

	// PolicyServer ConfigMap
	PolicyServerConfigPoliciesEntry         = "policies.yml"
	PolicyServerDeploymentRestartAnnotation = "kubectl.kubernetes.io/restartedAt"
	PolicyServerConfigSourcesEntry          = "sources.yml"

	// Label
	AppLabelKey              = "app"
	PolicyServerNameLabelKey = "policyServerName"

	// Index
	PolicyServerIndexKey  = "policyServer"
	PolicyServerIndexName = "name"

	// Finalizers
	KubewardenFinalizer = "kubewarden"
)
