package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

const (
	certsVolumeName                  = "certs"
	policiesConfigContainerPath      = "/config"
	policiesFilename                 = "policies.yml"
	sourcesFilename                  = "sources.yml"
	verificationFilename             = "verification.yml"
	policiesVolumeName               = "policies"
	sourcesVolumeName                = "sources"
	verificationConfigVolumeName     = "verification"
	kubewardenCAVolumeName           = "kubewarden-ca-cert"
	clientCAVolumeName               = "client-ca-cert"
	secretsContainerPath             = "/pki"
	imagePullSecretVolumeName        = "imagepullsecret"
	dockerConfigJSONPolicyServerPath = "/home/kubewarden/.docker"
	policyStoreVolume                = "policy-store"
	policyStoreVolumePath            = "/tmp"
	sigstoreCacheDirPath             = "/tmp/sigstore-data"
	otelClientCertificateVolumeName  = "otel-collector-client-certificate"
	otelCertificateVolumeName        = "otel-collector-certificate"
	defaultOtelCertificateMountMode  = 420
)

// reconcilePolicyServerDeployment reconciles the Deployment that runs the PolicyServer.
func (r *PolicyServerReconciler) reconcilePolicyServerDeployment(ctx context.Context, policyServer *policiesv1.PolicyServer) error {
	configMapVersion, err := r.policyServerConfigMapVersion(ctx, policyServer)
	if err != nil {
		return fmt.Errorf("cannot get policy-server ConfigMap version: %w", err)
	}

	policyServerDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer.NameWithPrefix(),
			Namespace: r.DeploymentsNamespace,
		},
	}
	_, err = controllerutil.CreateOrPatch(ctx, r.Client, policyServerDeployment, func() error {
		return r.updatePolicyServerDeployment(ctx, policyServer, policyServerDeployment, configMapVersion)
	})
	if err != nil {
		return fmt.Errorf("error reconciling policy-server deployment: %w", err)
	}

	return nil
}

func configureVerificationConfig(policyServer *policiesv1.PolicyServer, admissionContainer *corev1.Container) {
	if policyServer.Spec.VerificationConfig != "" {
		admissionContainer.VolumeMounts = append(admissionContainer.VolumeMounts,
			corev1.VolumeMount{
				Name:      verificationConfigVolumeName,
				ReadOnly:  true,
				MountPath: constants.PolicyServerVerificationConfigContainerPath,
			})
		admissionContainer.Env = append(admissionContainer.Env,
			corev1.EnvVar{
				Name:  "KUBEWARDEN_VERIFICATION_CONFIG_PATH",
				Value: filepath.Join(constants.PolicyServerVerificationConfigContainerPath, verificationFilename),
			})
	}
}

func (r *PolicyServerReconciler) updatePolicyServerDeployment(ctx context.Context, policyServer *policiesv1.PolicyServer, policyServerDeployment *appsv1.Deployment, configMapVersion string) error {
	admissionContainer := getPolicyServerContainer(policyServer)

	if r.AlwaysAcceptAdmissionReviewsInDeploymentsNamespace {
		admissionContainer.Env = append(admissionContainer.Env, corev1.EnvVar{
			Name:  "KUBEWARDEN_ALWAYS_ACCEPT_ADMISSION_REVIEWS_ON_NAMESPACE",
			Value: r.DeploymentsNamespace,
		})
	}

	configureVerificationConfig(policyServer, &admissionContainer)
	configureImagePullSecret(policyServer, &admissionContainer)
	configuresInsecureSources(policyServer, &admissionContainer)

	podSecurityContext := &corev1.PodSecurityContext{}
	if policyServer.Spec.SecurityContexts.Pod != nil {
		podSecurityContext = policyServer.Spec.SecurityContexts.Pod
	}
	if policyServer.Spec.SecurityContexts.Container != nil {
		admissionContainer.SecurityContext = policyServer.Spec.SecurityContexts.Container
	} else {
		admissionContainer.SecurityContext = defaultContainerSecurityContext()
	}

	templateAnnotations := policyServer.Spec.Annotations
	if templateAnnotations == nil {
		templateAnnotations = make(map[string]string)
	}

	configureLabelsAndAnnotations(policyServerDeployment, policyServer, configMapVersion)

	policyServerDeployment.Spec = buildPolicyServerDeploymentSpec(
		policyServer,
		admissionContainer,
		configMapVersion,
		templateAnnotations,
		podSecurityContext,
	)
	r.adaptDeploymentForMetricsAndTracingConfiguration(policyServerDeployment, templateAnnotations)
	r.adaptDeploymentSettingsForPolicyServer(policyServerDeployment, policyServer)

	if err := r.configureMutualTLS(ctx, policyServerDeployment); err != nil {
		return fmt.Errorf("failed to configure mutual TLS: %w", err)
	}
	if err := controllerutil.SetOwnerReference(policyServer, policyServerDeployment, r.Client.Scheme()); err != nil {
		return errors.Join(errors.New("failed to set policy server deployment owner reference"), err)
	}

	return nil
}

// / Adapts the policy server deployment to support metrics and tracing
// configuration. It's possible to use Otel collector as a sidecar or send
// data to a remote collector. This function is responsible to configure the
// policy server deployment for both.
func (r *PolicyServerReconciler) adaptDeploymentForMetricsAndTracingConfiguration(policyServerDeployment *appsv1.Deployment, templateAnnotations map[string]string) {
	admissionContainer := &policyServerDeployment.Spec.Template.Spec.Containers[0]
	if r.MetricsEnabled {
		envvar := corev1.EnvVar{Name: constants.PolicyServerEnableMetricsEnvVar, Value: "true"}
		if index := envVarsContainVariable(admissionContainer.Env, constants.PolicyServerEnableMetricsEnvVar); index >= 0 {
			admissionContainer.Env[index] = envvar
		} else {
			admissionContainer.Env = append(admissionContainer.Env, envvar)
		}
	}
	if r.TracingEnabled {
		logFmtEnvVar := corev1.EnvVar{Name: constants.PolicyServerLogFmtEnvVar, Value: "otlp"}
		if index := envVarsContainVariable(admissionContainer.Env, constants.PolicyServerLogFmtEnvVar); index >= 0 {
			admissionContainer.Env[index] = logFmtEnvVar
		} else {
			admissionContainer.Env = append(admissionContainer.Env, logFmtEnvVar)
		}
	}

	// If the otel sidecar is disabled, we  need to configure the policy
	// server to send data to the remote collector. To keep the
	// configuration simple, we are replicating the same OTEL configuration
	// from the controller to the policy server. Therefore, it's not
	// necessary to change in the `PolicyServer` CRD.
	//
	// To allow a secure communication (including mTLS), it's necessary to
	// mount in the policy server deployment the same secrets containing
	// the certificates used by the controller. It's expected that the
	// secret has the tls.crt, tls.key and ca.crt keys in its data fields.
	// The default field names for the secrets of type kubernetes.io/tls.

	// Therefore, the mount path used in the policy server is the same used
	// in the controller. The base directory is extracted from the OTEL
	// environment variables. Allow us to use the same envvar values in the
	// policy server deployment.
	if (r.MetricsEnabled || r.TracingEnabled) && !r.OtelSidecarEnabled {
		setOtelCertificateMounts(policyServerDeployment, r.OtelCertificateSecret, r.OtelClientCertificateSecret)
		// As the controller is sending data to remote otel collector, we need
		// to replicate the env vars to the policy server deployment. Thus, it
		// will be able to send data to the same collector.
		replicateOtelEnvVars(policyServerDeployment)
	}

	// If the otel sidecar is enabled, we need to inject the sidecar in the
	// policy server deployment. The exporter will communicate with the sidecar
	// using the localhost address.
	if (r.MetricsEnabled || r.TracingEnabled) && r.OtelSidecarEnabled {
		templateAnnotations[constants.OptelInjectAnnotation] = "true"
		envvar := corev1.EnvVar{Name: "OTEL_EXPORTER_OTLP_ENDPOINT", Value: "http://localhost:4317"}
		if index := envVarsContainVariable(admissionContainer.Env, "OTEL_EXPORTER_OTLP_ENDPOINT"); index >= 0 {
			admissionContainer.Env[index] = envvar
		} else {
			admissionContainer.Env = append(admissionContainer.Env, envvar)
		}
	}
}

func (r *PolicyServerReconciler) adaptDeploymentSettingsForPolicyServer(policyServerDeployment *appsv1.Deployment, policyServer *policiesv1.PolicyServer) {
	if policyServer.Spec.VerificationConfig != "" {
		policyServerDeployment.Spec.Template.Spec.Volumes = append(
			policyServerDeployment.Spec.Template.Spec.Volumes,
			corev1.Volume{
				Name: verificationConfigVolumeName,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: policyServer.Spec.VerificationConfig,
						},
						Items: []corev1.KeyToPath{
							{
								Key:  constants.PolicyServerVerificationConfigEntry,
								Path: verificationFilename,
							},
						},
					},
				},
			},
		)
	}

	if policyServer.Spec.ImagePullSecret != "" {
		policyServerDeployment.Spec.Template.Spec.Volumes = append(
			policyServerDeployment.Spec.Template.Spec.Volumes,
			corev1.Volume{
				Name: imagePullSecretVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: policyServer.Spec.ImagePullSecret,
						Items: []corev1.KeyToPath{
							{
								Key:  ".dockerconfigjson",
								Path: "config.json",
							},
						},
					},
				},
			},
		)
	}

	if len(policyServer.Spec.InsecureSources) > 0 || len(policyServer.Spec.SourceAuthorities) > 0 {
		policyServerDeployment.Spec.Template.Spec.Volumes = append(
			policyServerDeployment.Spec.Template.Spec.Volumes,
			corev1.Volume{
				Name: sourcesVolumeName,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: policyServer.NameWithPrefix(),
						},
					},
				},
			},
		)
	}
}

func configureImagePullSecret(policyServer *policiesv1.PolicyServer, admissionContainer *corev1.Container) {
	if policyServer.Spec.ImagePullSecret != "" {
		admissionContainer.VolumeMounts = append(admissionContainer.VolumeMounts,
			corev1.VolumeMount{
				Name:      imagePullSecretVolumeName,
				ReadOnly:  true,
				MountPath: dockerConfigJSONPolicyServerPath,
			})
		admissionContainer.Env = append(admissionContainer.Env,
			corev1.EnvVar{
				Name:  "KUBEWARDEN_DOCKER_CONFIG_JSON_PATH",
				Value: dockerConfigJSONPolicyServerPath,
			})
	}
}

func configuresInsecureSources(policyServer *policiesv1.PolicyServer, admissionContainer *corev1.Container) {
	if len(policyServer.Spec.InsecureSources) > 0 || len(policyServer.Spec.SourceAuthorities) > 0 {
		admissionContainer.VolumeMounts = append(admissionContainer.VolumeMounts,
			corev1.VolumeMount{
				Name:      sourcesVolumeName,
				ReadOnly:  true,
				MountPath: constants.PolicyServerSourcesConfigContainerPath,
			})
		admissionContainer.Env = append(admissionContainer.Env,
			corev1.EnvVar{
				Name:  "KUBEWARDEN_SOURCES_PATH",
				Value: filepath.Join(constants.PolicyServerSourcesConfigContainerPath, sourcesFilename),
			})
	}
}

func configureLabelsAndAnnotations(policyServerDeployment *appsv1.Deployment, policyServer *policiesv1.PolicyServer, configMapVersion string) {
	if policyServerDeployment.ObjectMeta.Annotations == nil {
		policyServerDeployment.ObjectMeta.Annotations = make(map[string]string)
	}
	policyServerDeployment.ObjectMeta.Annotations[constants.PolicyServerDeploymentConfigVersionAnnotation] = configMapVersion

	if policyServerDeployment.Labels == nil {
		policyServerDeployment.Labels = make(map[string]string)
	}
	policyServerDeployment.Labels[constants.AppLabelKey] = policyServer.AppLabel()
	policyServerDeployment.Labels[constants.PolicyServerLabelKey] = policyServer.Name
}

func (r *PolicyServerReconciler) configureMutualTLS(ctx context.Context, policyServerDeployment *appsv1.Deployment) error {
	policyServerDeployment.Spec.Template.Spec.Volumes = append(
		policyServerDeployment.Spec.Template.Spec.Volumes,
		corev1.Volume{
			Name: kubewardenCAVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: constants.CARootSecretName,
					Items: []corev1.KeyToPath{
						{
							Key:  constants.CARootCert,
							Path: constants.CARootCert,
						},
					},
				},
			},
		},
	)

	admissionContainer := &policyServerDeployment.Spec.Template.Spec.Containers[0]
	if r.ClientCAConfigMapName != "" {
		if err := r.Client.Get(ctx, types.NamespacedName{Name: r.ClientCAConfigMapName, Namespace: r.DeploymentsNamespace}, &corev1.ConfigMap{}); err != nil {
			return fmt.Errorf("failed to fetch client CA config map: %w", err)
		}

		policyServerDeployment.Spec.Template.Spec.Volumes = append(
			policyServerDeployment.Spec.Template.Spec.Volumes,
			corev1.Volume{
				Name: clientCAVolumeName,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: r.ClientCAConfigMapName,
						},
						Items: []corev1.KeyToPath{
							{
								Key:  constants.ClientCACert,
								Path: constants.ClientCACert,
							},
						},
					},
				},
			},
		)

		admissionContainer.Env = append(admissionContainer.Env, corev1.EnvVar{
			Name:  "KUBEWARDEN_CLIENT_CA_FILE",
			Value: fmt.Sprintf("%s,%s", constants.CARootCert, constants.ClientCACert),
		})

		return nil
	}

	admissionContainer.Env = append(admissionContainer.Env, corev1.EnvVar{
		Name:  "KUBEWARDEN_CLIENT_CA_FILE",
		Value: constants.CARootCert,
	})

	return nil
}

func buildPolicyServerDeploymentSpec(
	policyServer *policiesv1.PolicyServer,
	admissionContainer corev1.Container,
	configMapVersion string,
	templateAnnotations map[string]string,
	podSecurityContext *corev1.PodSecurityContext,
) appsv1.DeploymentSpec {
	return appsv1.DeploymentSpec{
		Replicas: &policyServer.Spec.Replicas,
		Selector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				constants.AppLabelKey: policyServer.AppLabel(),
			},
		},
		Strategy: appsv1.DeploymentStrategy{
			Type: appsv1.RollingUpdateDeploymentStrategyType,
		},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					constants.AppLabelKey: policyServer.AppLabel(),
					constants.PolicyServerDeploymentPodSpecConfigVersionLabel: configMapVersion,
					constants.PolicyServerLabelKey:                            policyServer.Name,
				},
				Annotations: templateAnnotations,
			},
			Spec: corev1.PodSpec{
				SecurityContext:    podSecurityContext,
				Containers:         []corev1.Container{admissionContainer},
				ServiceAccountName: policyServer.Spec.ServiceAccountName,
				Tolerations:        policyServer.Spec.Tolerations,
				Affinity:           &policyServer.Spec.Affinity,
				Volumes: []corev1.Volume{
					{
						Name: policyStoreVolume,
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					},
					{
						Name: certsVolumeName,
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName: policyServer.NameWithPrefix(),
							},
						},
					},
					{
						Name: policiesVolumeName,
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: policyServer.NameWithPrefix(),
								},
								Items: []corev1.KeyToPath{
									{
										Key:  constants.PolicyServerConfigPoliciesEntry,
										Path: policiesFilename,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func setOtelCertificateMounts(policyServerDeployment *appsv1.Deployment, otelCertificateSecret, otelClientCertificateSecret string) {
	admissionContainer := &policyServerDeployment.Spec.Template.Spec.Containers[0]
	defaultCertificateMountMode := int32(defaultOtelCertificateMountMode)

	certificatePath := filepath.Dir(os.Getenv("OTEL_EXPORTER_OTLP_CERTIFICATE"))
	if otelCertificateSecret != "" {
		policyServerDeployment.Spec.Template.Spec.Volumes = append(policyServerDeployment.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: otelCertificateVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  otelCertificateSecret,
					DefaultMode: &defaultCertificateMountMode,
				},
			},
		})
		admissionContainer.VolumeMounts = append(admissionContainer.VolumeMounts, corev1.VolumeMount{
			Name:      otelCertificateVolumeName,
			ReadOnly:  true,
			MountPath: certificatePath,
		})
	}
	clientCertificatePath := filepath.Dir(os.Getenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE"))
	if otelClientCertificateSecret != "" {
		policyServerDeployment.Spec.Template.Spec.Volumes = append(policyServerDeployment.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: otelClientCertificateVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  otelClientCertificateSecret,
					DefaultMode: &defaultCertificateMountMode,
				},
			},
		})
		admissionContainer.VolumeMounts = append(admissionContainer.VolumeMounts, corev1.VolumeMount{
			Name:      otelClientCertificateVolumeName,
			ReadOnly:  true,
			MountPath: clientCertificatePath,
		})
	}
}

func replicateOtelEnvVars(policyServerDeployment *appsv1.Deployment) {
	admissionContainer := &policyServerDeployment.Spec.Template.Spec.Containers[0]
	otelEnvVarToReplicate := []string{
		"OTEL_EXPORTER_OTLP_CERTIFICATE",
		"OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE",
		"OTEL_EXPORTER_OTLP_CLIENT_KEY",
		"OTEL_EXPORTER_OTLP_COMPRESSION",
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_HEADERS",
		"OTEL_EXPORTER_OTLP_INSECURE",
		"OTEL_EXPORTER_OTLP_METRICS_CERTIFICATE",
		"OTEL_EXPORTER_OTLP_METRICS_CLIENT_CERTIFICATE",
		"OTEL_EXPORTER_OTLP_METRICS_CLIENT_KEY",
		"OTEL_EXPORTER_OTLP_METRICS_COMPRESSION",
		"OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_HEADERS",
		"OTEL_EXPORTER_OTLP_METRICS_INSECURE",
		"OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE",
		"OTEL_EXPORTER_OTLP_METRICS_TIMEOUT",
		"OTEL_EXPORTER_OTLP_TIMEOUT",
		"OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE",
		"OTEL_EXPORTER_OTLP_TRACES_CLIENT_CERTIFICATE",
		"OTEL_EXPORTER_OTLP_TRACES_CLIENT_KEY",
		"OTEL_EXPORTER_OTLP_TRACES_COMPRESSION",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_HEADERS",
		"OTEL_EXPORTER_OTLP_TRACES_INSECURE",
		"OTEL_EXPORTER_OTLP_TRACES_TIMEOUT",
	}
	for _, envVar := range otelEnvVarToReplicate {
		if value := os.Getenv(envVar); value != "" {
			envvar := corev1.EnvVar{Name: envVar, Value: value}
			if index := envVarsContainVariable(admissionContainer.Env, envVar); index >= 0 {
				admissionContainer.Env[index] = envvar
			} else {
				admissionContainer.Env = append(admissionContainer.Env, envvar)
			}
		}
	}
}

func envVarsContainVariable(envVars []corev1.EnvVar, envVarName string) int {
	for i, envvar := range envVars {
		if envvar.Name == envVarName {
			return i
		}
	}
	return -1
}

func defaultContainerSecurityContext() *corev1.SecurityContext {
	enableReadOnlyFilesystem := true
	privileged := false
	runAsNonRoot := true
	allowPrivilegeEscalation := false
	capabilities := corev1.Capabilities{
		Add:  []corev1.Capability{},
		Drop: []corev1.Capability{"all"},
	}
	admissionContainerSecurityContext := corev1.SecurityContext{
		ReadOnlyRootFilesystem:   &enableReadOnlyFilesystem,
		Privileged:               &privileged,
		AllowPrivilegeEscalation: &allowPrivilegeEscalation,
		Capabilities:             &capabilities,
		RunAsNonRoot:             &runAsNonRoot,
	}
	return &admissionContainerSecurityContext
}

func getPolicyServerContainer(policyServer *policiesv1.PolicyServer) corev1.Container {
	return corev1.Container{
		Name:  policyServer.NameWithPrefix(),
		Image: policyServer.Spec.Image,
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      certsVolumeName,
				ReadOnly:  true,
				MountPath: secretsContainerPath,
			},
			{
				Name:      policiesVolumeName,
				ReadOnly:  true,
				MountPath: policiesConfigContainerPath,
			},
			{
				Name:      policyStoreVolume,
				MountPath: policyStoreVolumePath,
			},
		},
		Env: append([]corev1.EnvVar{
			{
				Name:  "KUBEWARDEN_CERT_FILE",
				Value: filepath.Join(secretsContainerPath, constants.ServerCert),
			},
			{
				Name:  "KUBEWARDEN_KEY_FILE",
				Value: filepath.Join(secretsContainerPath, constants.ServerPrivateKey),
			},
			{
				Name:  "KUBEWARDEN_PORT",
				Value: strconv.Itoa(constants.PolicyServerPort),
			},
			{
				Name:  "KUBEWARDEN_POLICIES_DOWNLOAD_DIR",
				Value: policyStoreVolumePath,
			},
			{
				Name:  "KUBEWARDEN_POLICIES",
				Value: filepath.Join(policiesConfigContainerPath, policiesFilename),
			},
			{
				Name:  "KUBEWARDEN_SIGSTORE_CACHE_DIR",
				Value: sigstoreCacheDirPath,
			},
		}, policyServer.Spec.Env...),
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   constants.PolicyServerReadinessProbe,
					Port:   intstr.FromInt(constants.PolicyServerPort),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
		},
		Resources: corev1.ResourceRequirements{
			Requests: policyServer.Spec.Requests,
			Limits:   policyServer.Spec.Limits,
		},
	}
}
