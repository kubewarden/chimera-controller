package admission

import (
	"testing"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	corev1 "k8s.io/api/core/v1"
)

func TestMetricsEnabled(t *testing.T) {
	cases := []struct {
		policyServer           policiesv1.PolicyServer
		expectedMetricsEnabled bool
	}{
		{
			policyServer: policyServerWithEnvVar(
				"SOME_VAR", "SOME_VALUE",
			),
			expectedMetricsEnabled: false,
		},
		{
			policyServer: policyServerWithEnvVar(
				constants.PolicyServerEnableMetricsEnvVar, "1",
			),
			expectedMetricsEnabled: true,
		},
		{
			policyServer: policyServerWithEnvVar(
				constants.PolicyServerEnableMetricsEnvVar, "true",
			),
			expectedMetricsEnabled: true,
		},
		// If the environment variable is exported -- regardless of its value --, metrics are
		// considered enabled
		{
			policyServer: policyServerWithEnvVar(
				constants.PolicyServerEnableMetricsEnvVar, "",
			),
			expectedMetricsEnabled: true,
		},
		{
			policyServer: policyServerWithEnvVar(
				constants.PolicyServerEnableMetricsEnvVar, "0",
			),
			expectedMetricsEnabled: true,
		},
		{
			policyServer: policyServerWithEnvVar(
				constants.PolicyServerEnableMetricsEnvVar, "false",
			),
			expectedMetricsEnabled: true,
		},
	}

	for _, testCase := range cases {
		expected, actual := testCase.expectedMetricsEnabled, metricsEnabled(&testCase.policyServer)
		if actual != expected {
			t.Errorf("metrics enabled value (%v) does not match expected value: %v", actual, expected)
		}
	}
}

func policyServerWithEnvVar(name, value string) policiesv1.PolicyServer {
	return policiesv1.PolicyServer{
		Spec: policiesv1.PolicyServerSpec{
			Env: []corev1.EnvVar{
				{
					Name:  name,
					Value: value,
				},
			},
		},
	}
}
