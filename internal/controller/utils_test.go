/*
Copyright 2022.

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

package controller

import (
	"context"
	"errors"
	"fmt"
	"math/rand"

	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"github.com/onsi/gomega/types"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8spoliciesv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

const (
	integrationTestsFinalizer   = "integration-tests-safety-net-finalizer"
	defaultKubewardenRepository = "ghcr.io/kubewarden/policy-server"
	clientCAConfigMapName       = "client-ca"
)

func getTestAdmissionPolicy(ctx context.Context, namespace, name string) (*policiesv1.AdmissionPolicy, error) {
	admissionPolicy := policiesv1.AdmissionPolicy{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &admissionPolicy); err != nil {
		return nil, errors.Join(errors.New("could not find AdmissionPolicy"), err)
	}
	return &admissionPolicy, nil
}

func getTestAdmissionPolicyGroup(ctx context.Context, namespace, name string) (*policiesv1.AdmissionPolicyGroup, error) {
	admissionPolicyGroup := policiesv1.AdmissionPolicyGroup{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &admissionPolicyGroup); err != nil {
		return nil, errors.Join(errors.New("could not find AdmissionPolicyGroup"), err)
	}
	return &admissionPolicyGroup, nil
}

func getTestClusterAdmissionPolicy(ctx context.Context, name string) (*policiesv1.ClusterAdmissionPolicy, error) {
	clusterAdmissionPolicy := policiesv1.ClusterAdmissionPolicy{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, &clusterAdmissionPolicy); err != nil {
		return nil, errors.Join(errors.New("could not find ClusterAdmissionPolicy"), err)
	}
	return &clusterAdmissionPolicy, nil
}

func getTestClusterAdmissionPolicyGroup(ctx context.Context, name string) (*policiesv1.ClusterAdmissionPolicyGroup, error) {
	clusterAdmissionPolicyGroup := policiesv1.ClusterAdmissionPolicyGroup{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, &clusterAdmissionPolicyGroup); err != nil {
		return nil, errors.Join(errors.New("could not find ClusterAdmissionPolicyGroup"), err)
	}
	return &clusterAdmissionPolicyGroup, nil
}

func getTestPolicyServer(ctx context.Context, name string) (*policiesv1.PolicyServer, error) {
	policyServer := policiesv1.PolicyServer{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, &policyServer); err != nil {
		return nil, errors.Join(errors.New("could not find PolicyServer"), err)
	}
	return &policyServer, nil
}

func getTestPolicyServerService(ctx context.Context, policyServerName string) (*corev1.Service, error) {
	serviceName := getPolicyServerNameWithPrefix(policyServerName)
	service := corev1.Service{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: serviceName, Namespace: deploymentsNamespace}, &service); err != nil {
		return nil, errors.Join(errors.New("could not find Service owned by PolicyServer"), err)
	}
	return &service, nil
}

func getTestPolicyServerSecret(ctx context.Context, policyServerName string) (*corev1.Secret, error) {
	secretName := getPolicyServerNameWithPrefix(policyServerName)
	secret := corev1.Secret{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: secretName, Namespace: deploymentsNamespace}, &secret); err != nil {
		return nil, errors.Join(errors.New("could not find secret owned by PolicyServer"), err)
	}
	return &secret, nil
}

func getTestPolicyServerDeployment(ctx context.Context, policyServerName string) (*appsv1.Deployment, error) {
	deploymentName := getPolicyServerNameWithPrefix(policyServerName)
	deployment := appsv1.Deployment{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: deploymentName, Namespace: deploymentsNamespace}, &deployment); err != nil {
		return nil, errors.Join(errors.New("could not find Deployment owned by PolicyServer"), err)
	}
	return &deployment, nil
}

func getTestPolicyServerConfigMap(ctx context.Context, policyServerName string) (*corev1.ConfigMap, error) {
	configMapName := getPolicyServerNameWithPrefix(policyServerName)

	configmap := corev1.ConfigMap{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: configMapName, Namespace: deploymentsNamespace}, &configmap); err != nil {
		return nil, errors.Join(errors.New("could not find ConfigMap owned by PolicyServer"), err)
	}
	return &configmap, nil
}

func getPolicyServerNameWithPrefix(policyServerName string) string {
	policyServer := policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: policyServerName,
		},
	}
	return policyServer.NameWithPrefix()
}

func getTestValidatingWebhookConfiguration(ctx context.Context, name string) (*admissionregistrationv1.ValidatingWebhookConfiguration, error) {
	validatingWebhookConfiguration := admissionregistrationv1.ValidatingWebhookConfiguration{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, &validatingWebhookConfiguration); err != nil {
		return nil, errors.Join(errors.New("could not find ValidatingWebhookConfiguration"), err)
	}
	return &validatingWebhookConfiguration, nil
}

func getTestMutatingWebhookConfiguration(ctx context.Context, name string) (*admissionregistrationv1.MutatingWebhookConfiguration, error) {
	mutatingWebhookConfiguration := admissionregistrationv1.MutatingWebhookConfiguration{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, &mutatingWebhookConfiguration); err != nil {
		return nil, errors.Join(errors.New("could not find ValidatingWebhookConfiguration"), err)
	}
	return &mutatingWebhookConfiguration, nil
}

func getTestCASecret(ctx context.Context) (*corev1.Secret, error) {
	secret := corev1.Secret{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: constants.CARootSecretName, Namespace: deploymentsNamespace}, &secret); err != nil {
		return nil, errors.Join(errors.New("could not find CA secret"), err)
	}

	return &secret, nil
}

func getPolicyServerPodDisruptionBudget(ctx context.Context, policyServerName string) (*k8spoliciesv1.PodDisruptionBudget, error) {
	policyServer := policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: policyServerName,
		},
	}
	podDisruptionBudgetName := policyServer.NameWithPrefix()
	pdb := &k8spoliciesv1.PodDisruptionBudget{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: podDisruptionBudgetName, Namespace: deploymentsNamespace}, pdb); err != nil {
		return nil, errors.Join(errors.New("could not find PodDisruptionBudget"), err)
	}
	return pdb, nil
}

func policyServerPodDisruptionBudgetMatcher(policyServer *policiesv1.PolicyServer, minAvailable *intstr.IntOrString, maxUnavailable *intstr.IntOrString) types.GomegaMatcher {
	maxUnavailableMatcher := BeNil()
	minAvailableMatcher := BeNil()
	if minAvailable != nil {
		minAvailableMatcher = PointTo(Equal(*minAvailable))
	}
	if maxUnavailable != nil {
		maxUnavailableMatcher = PointTo(Equal(*maxUnavailable))
	}
	return SatisfyAll(
		Not(BeNil()),
		PointTo(MatchFields(IgnoreExtras, Fields{
			"ObjectMeta": MatchFields(IgnoreExtras, Fields{
				"OwnerReferences": ContainElement(MatchFields(IgnoreExtras, Fields{
					"Name": Equal(policyServer.GetName()),
					"Kind": Equal("PolicyServer"),
				})),
			}),
			"Spec": MatchFields(IgnoreExtras, Fields{
				"MaxUnavailable": maxUnavailableMatcher,
				"MinAvailable":   minAvailableMatcher,
				"Selector": PointTo(MatchAllFields(Fields{
					"MatchLabels": MatchAllKeys(Keys{
						constants.AppLabelKey:          Equal(policyServer.AppLabel()),
						constants.PolicyServerLabelKey: Equal(policyServer.GetName()),
					}),
					"MatchExpressions": Ignore(),
				})),
			}),
		}),
		),
	)
}

func alreadyExists() types.GomegaMatcher {
	return WithTransform(
		func(err error) bool {
			return err != nil && apierrors.IsAlreadyExists(err)
		},
		BeTrue(),
	)
}

func haveSucceededOrAlreadyExisted() types.GomegaMatcher {
	return SatisfyAny(
		BeNil(),
		alreadyExists(),
	)
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz1234567890")

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}

	return string(b)
}

func newName(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, randStringRunes(8))
}

func createPolicyServerAndWaitForItsService(ctx context.Context, policyServer *policiesv1.PolicyServer) {
	Expect(k8sClient.Create(ctx, policyServer)).To(haveSucceededOrAlreadyExisted())
	// Wait for the Service associated with the PolicyServer to be created
	Eventually(func() error {
		_, err := getTestPolicyServerService(ctx, policyServer.GetName())
		return err
	}, timeout, pollInterval).Should(Succeed())
}
