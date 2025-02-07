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
	. "github.com/onsi/gomega/gstruct"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

var _ = Describe("ClusterAdmissionPolicyGroup controller", Label("real-cluster"), func() {
	ctx := context.Background()

	When("creating a validating ClusterAdmissionPolicyGroup", Ordered, func() {
		var policyServerName string
		var policyName string
		var policy *policiesv1.ClusterAdmissionPolicyGroup

		BeforeAll(func() {
			policyServerName = newName("policy-server")
			createPolicyServerAndWaitForItsService(ctx, policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				Build())

			policyName = newName("validating-policy")
			policy = policiesv1.NewClusterAdmissionPolicyGroupFactory().
				WithName(policyName).
				WithPolicyServer(policyServerName).
				Build()
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		})

		It("should set the ClusterAdmissionPolicyGroup to active", func() {
			By("changing the policy status to pending")
			Eventually(func() (*policiesv1.ClusterAdmissionPolicyGroup, error) {
				return getTestClusterAdmissionPolicyGroup(ctx, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusPending)),
			)

			By("changing the policy status to active")
			Eventually(func() (*policiesv1.ClusterAdmissionPolicyGroup, error) {
				return getTestClusterAdmissionPolicyGroup(ctx, policyName)
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
				Expect(validatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey]).To(BeEmpty())
				Expect(validatingWebhookConfiguration.Webhooks).To(HaveLen(1))
				Expect(validatingWebhookConfiguration.Webhooks[0].NamespaceSelector.MatchExpressions).To(ContainElement(MatchFields(IgnoreExtras,
					Fields{
						"Key":      Equal("kubernetes.io/metadata.name"),
						"Operator": BeEquivalentTo("NotIn"),
						"Values":   ConsistOf(deploymentsNamespace),
					})))
				Expect(validatingWebhookConfiguration.Webhooks[0].ClientConfig.Service.Name).To(Equal("policy-server-" + policyServerName))
				Expect(validatingWebhookConfiguration.Webhooks[0].MatchConditions).To(HaveLen(1))

				caSecret, err := getTestCASecret(ctx)
				Expect(err).ToNot(HaveOccurred())
				Expect(validatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle).To(Equal(caSecret.Data[constants.CARootCert]))

				return nil
			}, timeout, pollInterval).Should(Succeed())
		})

		It("should be reconcile the ValidationWebhookConfiguration to the original state after some change", func() {
			By("changing the ValidatingWebhookConfiguration")
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
		})

		It("should delete the ValidatingWebhookConfiguration when the ClusterAdmissionPolicyGroup is deleted", func() {
			By("deleting the ClusterAdmissionPolicyGroup")
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

	It("should set policy status to unscheduled when creating an ClusterAdmissionPolicyGroup without a PolicyServer assigned", func() {
		policyName := newName("unscheduled-policy")
		Expect(
			k8sClient.Create(ctx, policiesv1.NewClusterAdmissionPolicyGroupFactory().
				WithName(policyName).
				WithPolicyServer("").
				Build()),
		).To(haveSucceededOrAlreadyExisted())

		Eventually(func() (*policiesv1.ClusterAdmissionPolicyGroup, error) {
			return getTestClusterAdmissionPolicyGroup(ctx, policyName)
		}, timeout, pollInterval).Should(
			HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusUnscheduled)),
		)
	})

	When("creating a ClusterAdmissionPolicyGroup with a PolicyServer assigned but not running yet", Ordered, func() {
		policyName := newName("scheduled-policy")
		policyServerName := newName("policy-server")

		BeforeAll(func() {
			Expect(
				k8sClient.Create(ctx, policiesv1.NewClusterAdmissionPolicyGroupFactory().
					WithName(policyName).
					WithPolicyServer(policyServerName).
					Build()),
			).To(haveSucceededOrAlreadyExisted())
		})

		It("should set the policy status to scheduled", func() {
			Expect(
				k8sClient.Create(ctx, policiesv1.NewClusterAdmissionPolicyGroupFactory().
					WithName(policyName).
					WithPolicyServer(policyServerName).
					Build()),
			).To(haveSucceededOrAlreadyExisted())

			Eventually(func() (*policiesv1.ClusterAdmissionPolicyGroup, error) {
				return getTestClusterAdmissionPolicyGroup(ctx, policyName)
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
			Eventually(func() (*policiesv1.ClusterAdmissionPolicyGroup, error) {
				return getTestClusterAdmissionPolicyGroup(ctx, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusPending)),
			)

			By("changing the policy status to active")
			Eventually(func() (*policiesv1.ClusterAdmissionPolicyGroup, error) {
				return getTestClusterAdmissionPolicyGroup(ctx, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusActive)),
			)
		})
	})
})
