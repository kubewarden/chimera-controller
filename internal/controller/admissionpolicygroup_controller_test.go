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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

var _ = Describe("AdmissionPolicyGroup controller", Label("real-cluster"), func() {
	ctx := context.Background()
	policyNamespace := "admission-policy-group-controller-test"

	BeforeEach(func() {
		Expect(
			k8sClient.Create(ctx, &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: policyNamespace,
				},
			}),
		).To(haveSucceededOrAlreadyExisted())
	})

	When("creating a validating AdmissionPolicyGroup", Ordered, func() {
		var policyServerName string
		var policyName string
		var policy *policiesv1.AdmissionPolicyGroup

		BeforeAll(func() {
			policyServerName = newName("policy-server")
			createPolicyServerAndWaitForItsService(ctx, policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				Build())

			policyName = newName("validating-policy")
			policy = policiesv1.NewAdmissionPolicyGroupFactory().
				WithName(policyName).
				WithNamespace(policyNamespace).
				WithPolicyServer(policyServerName).
				Build()
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		})

		It("should set the AdminissionPolicyGroup to active sometime after its creation", func() {
			By("changing the policy status to pending")
			Eventually(func() (*policiesv1.AdmissionPolicyGroup, error) {
				return getTestAdmissionPolicyGroup(ctx, policyNamespace, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusPending)),
			)

			By("changing the policy status to active")
			Eventually(func() (*policiesv1.AdmissionPolicyGroup, error) {
				return getTestAdmissionPolicyGroup(ctx, policyNamespace, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusActive)),
			)
		})

		It("should create the ValidatingWebhookConfiguration", func() {
			Eventually(func() error {
				validatingWebhookConfiguration, err := getTestValidatingWebhookConfiguration(ctx, policy.GetUniqueName())
				if err != nil {
					return err
				}

				Expect(validatingWebhookConfiguration.Labels[constants.PartOfLabelKey]).To(Equal(constants.PartOfLabelValue))
				Expect(validatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey]).To(Equal(policyName))
				Expect(validatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey]).To(Equal(policyNamespace))
				Expect(validatingWebhookConfiguration.Webhooks).To(HaveLen(1))
				Expect(validatingWebhookConfiguration.Webhooks[0].ClientConfig.Service.Name).To(Equal("policy-server-" + policyServerName))
				Expect(validatingWebhookConfiguration.Webhooks[0].MatchConditions).To(HaveLen(1))

				caSecret, err := getTestCASecret(ctx)
				Expect(err).ToNot(HaveOccurred())
				Expect(validatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle).To(Equal(caSecret.Data[constants.CARootCert]))

				return nil
			}, timeout, pollInterval).Should(Succeed())
		})

		It("should reconcile the ValidationWebhookConfiguration to the original state after some change", func() {
			var originalValidatingWebhookConfiguration *admissionregistrationv1.ValidatingWebhookConfiguration
			var validatingWebhookConfiguration *admissionregistrationv1.ValidatingWebhookConfiguration
			Eventually(func() error {
				var err error
				validatingWebhookConfiguration, err = getTestValidatingWebhookConfiguration(ctx, policy.GetUniqueName())
				if err != nil {
					return err
				}
				originalValidatingWebhookConfiguration = validatingWebhookConfiguration.DeepCopy()
				return nil
			}, timeout, pollInterval).Should(Succeed())

			By("changing the ValidatingWebhookConfiguration")
			delete(validatingWebhookConfiguration.Labels, constants.PartOfLabelKey)
			delete(validatingWebhookConfiguration.Annotations, constants.WebhookConfigurationPolicyNameAnnotationKey)
			validatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] = newName("namespace")
			validatingWebhookConfiguration.Webhooks[0].ClientConfig.Service.Name = newName("service")
			validatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle = []byte("invalid")
			Expect(
				k8sClient.Update(ctx, validatingWebhookConfiguration),
			).To(Succeed())

			By("reconciling the ValidatingWebhookConfiguration to its original state")
			Eventually(func() (*admissionregistrationv1.ValidatingWebhookConfiguration, error) {
				return getTestValidatingWebhookConfiguration(ctx, policy.GetUniqueName())
			}, timeout, pollInterval).Should(
				And(
					HaveField("Labels", Equal(originalValidatingWebhookConfiguration.Labels)),
					HaveField("Annotations", Equal(originalValidatingWebhookConfiguration.Annotations)),
					HaveField("Webhooks", Equal(originalValidatingWebhookConfiguration.Webhooks)),
				),
			)

			// simulate uninitialized labels and annotation maps (behavior of Kubewarden <= 1.9.0), or user change
			By("setting the ValidatingWebhookConfiguration labels and annotation to nil")
			validatingWebhookConfiguration, err := getTestValidatingWebhookConfiguration(ctx, policy.GetUniqueName())
			Expect(err).ToNot(HaveOccurred())
			originalValidatingWebhookConfiguration = validatingWebhookConfiguration.DeepCopy()
			validatingWebhookConfiguration.Labels = nil
			validatingWebhookConfiguration.Annotations = nil
			Expect(
				k8sClient.Update(ctx, validatingWebhookConfiguration),
			).To(Succeed())

			By("reconciling the ValidatingWebhookConfiguration to its original state")
			Eventually(func() (*admissionregistrationv1.ValidatingWebhookConfiguration, error) {
				return getTestValidatingWebhookConfiguration(ctx, policy.GetUniqueName())
			}, timeout, pollInterval).Should(
				And(
					HaveField("Labels", Equal(originalValidatingWebhookConfiguration.Labels)),
					HaveField("Annotations", Equal(originalValidatingWebhookConfiguration.Annotations)),
					HaveField("Webhooks", Equal(originalValidatingWebhookConfiguration.Webhooks)),
				),
			)
		})

		It("should delete the ValidatingWebhookConfiguration when the AdmissionPolicyGroup is deleted", func() {
			By("deleting the AdmissionPolicyGroup")
			Expect(
				k8sClient.Delete(ctx, policy),
			).To(Succeed())

			By("waiting for the ValidatingWebhookConfiguration to be deleted")
			Eventually(func(g Gomega) {
				_, err := getTestValidatingWebhookConfiguration(ctx, policy.GetUniqueName())

				g.Expect(apierrors.IsNotFound(err)).To(BeTrue())
			}, timeout, pollInterval).Should(Succeed())
		})
	})

	It("should set policy status to unscheduled when creating an AdmissionPolicyGroup without a PolicyServer assigned", func() {
		policyName := newName("unscheduled-policy")
		Expect(
			k8sClient.Create(ctx, policiesv1.NewAdmissionPolicyGroupFactory().
				WithName(policyName).
				WithNamespace(policyNamespace).
				WithPolicyServer("").
				Build()),
		).To(haveSucceededOrAlreadyExisted())

		Eventually(func() (*policiesv1.AdmissionPolicyGroup, error) {
			return getTestAdmissionPolicyGroup(ctx, policyNamespace, policyName)
		}, timeout, pollInterval).Should(
			HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusUnscheduled)),
		)
	})

	When("creating an AdmissionPolicyGroup with a PolicyServer assigned but not running yet", Ordered, func() {
		policyName := newName("scheduled-policy")
		policyServerName := newName("policy-server")

		BeforeAll(func() {
			Expect(
				k8sClient.Create(ctx, policiesv1.NewAdmissionPolicyGroupFactory().
					WithName(policyName).
					WithNamespace(policyNamespace).
					WithPolicyServer(policyServerName).
					Build()),
			).To(haveSucceededOrAlreadyExisted())
		})

		It("should set the policy status to scheduled", func() {
			Eventually(func() (*policiesv1.AdmissionPolicyGroup, error) {
				return getTestAdmissionPolicyGroup(ctx, policyNamespace, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusScheduled)),
			)
		})

		It("should set the policy status to active when the PolicyServer is created", func() {
			By("creating the PolicyServer")
			Expect(
				k8sClient.Create(ctx, policiesv1.NewPolicyServerFactory().
					WithName(policyServerName).
					Build()),
			).To(haveSucceededOrAlreadyExisted())

			By("changing the policy status to pending")
			Eventually(func() (*policiesv1.AdmissionPolicyGroup, error) {
				return getTestAdmissionPolicyGroup(ctx, policyNamespace, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusPending)),
			)

			By("changing the policy status to active")
			Eventually(func() (*policiesv1.AdmissionPolicyGroup, error) {
				return getTestAdmissionPolicyGroup(ctx, policyNamespace, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusActive)),
			)
		})
	})
})
