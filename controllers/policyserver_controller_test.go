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

package controllers

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"      //nolint:revive
	. "github.com/onsi/gomega"         //nolint:revive
	. "github.com/onsi/gomega/gstruct" //nolint:revive
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	k8spoliciesv1 "k8s.io/api/policy/v1"
)

var _ = Describe("PolicyServer controller", func() {
	var policyServerName string

	BeforeEach(func() {
		policyServerName = newName("policy-server")
	})

	When("deleting a PolicyServer", func() {
		JustBeforeEach(func() {
			Expect(
				k8sClient.Create(ctx, policyServerFactory(policyServerName)),
			).To(haveSucceededOrAlreadyExisted())
			// Wait for the Service associated with the PolicyServer to be created
			Eventually(func() error {
				_, err := getTestPolicyServerService(policyServerName)
				return err
			}, timeout, pollInterval).Should(Succeed())
		})

		AfterEach(func() {
			// As we are testing policy server deletion, we need to remove the finalizer
			// from the policy server to allow the deletion to happen.
			// This is necessary because the JustBeforeEach block creates a policy server
			// for every single test here.
			policyServer, err := getTestPolicyServer(policyServerName)
			Expect(err).Should(Succeed())
			controllerutil.RemoveFinalizer(policyServer, IntegrationTestsFinalizer)
			err = reconciler.Client.Update(ctx, policyServer)
			Expect(err).ToNot(HaveOccurred())
			Eventually(func() error {
				_, err := getTestPolicyServer(policyServerName)
				return err
			}, timeout, pollInterval).ShouldNot(Succeed())
		})

		Context("with assigned policies", func() {
			var policyName string

			BeforeEach(func() {
				policyName = newName("policy")
			})

			JustBeforeEach(func() {
				Expect(
					k8sClient.Create(ctx, clusterAdmissionPolicyFactory(policyName, policyServerName, false)),
				).To(Succeed())
				Eventually(func() error {
					_, err := getTestClusterAdmissionPolicy(policyName)
					return err
				}, timeout, pollInterval).Should(Succeed())
				Expect(
					getTestPolicyServerService(policyServerName),
				).To(
					HaveField("DeletionTimestamp", BeNil()),
				)
			})

			AfterEach(func() {
				// To allow every "It" node to be independent,
				// we need to delete and remove the finalizer
				// from the policy.
				err := k8sClient.Delete(ctx, clusterAdmissionPolicyFactory(policyName, policyServerName, false))
				// There is a test which deletes the policy and
				// policy server. Therefore, if the policy is
				// gone, we are safe to skip the AfterEach
				if err != nil && apierrors.IsNotFound(err) {
					return
				}
				Expect(err).To(Succeed())
				policy, err := getTestClusterAdmissionPolicy(policyName)
				Expect(err).Should(Succeed())
				controllerutil.RemoveFinalizer(policy, IntegrationTestsFinalizer)
				err = reconciler.Client.Update(ctx, policy)
				Expect(err).ToNot(HaveOccurred())
				Eventually(func() error {
					_, err := getTestClusterAdmissionPolicy(policyName)
					return err
				}, timeout, pollInterval).ShouldNot(Succeed())
			})

			It("should delete assigned policies", func() {
				Expect(
					k8sClient.Delete(ctx, policyServerFactory(policyServerName)),
				).To(Succeed())

				Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
					return getTestClusterAdmissionPolicy(policyName)
				}, timeout, pollInterval).ShouldNot(
					HaveField("DeletionTimestamp", BeNil()),
				)
			})

			It("should not delete its managed resources until all the scheduled policies are gone", func() {
				Expect(
					k8sClient.Delete(ctx, policyServerFactory(policyServerName)),
				).To(Succeed())

				Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
					return getTestClusterAdmissionPolicy(policyName)
				}).Should(And(
					HaveField("DeletionTimestamp", Not(BeNil())),
					HaveField("Finalizers", Not(ContainElement(constants.KubewardenFinalizer))),
					HaveField("Finalizers", ContainElement(IntegrationTestsFinalizer)),
				))

				Eventually(func() error {
					_, err := getTestPolicyServerService(policyServerName)
					return err
				}).Should(Succeed())
			})

			It(fmt.Sprintf("should get its %q finalizer removed", constants.KubewardenFinalizer), func() {
				policy, err := getTestClusterAdmissionPolicy(policyName)
				Expect(err).ToNot(HaveOccurred())

				controllerutil.RemoveFinalizer(policy, IntegrationTestsFinalizer)
				err = reconciler.Client.Update(ctx, policy)
				Expect(err).ToNot(HaveOccurred())

				Expect(
					k8sClient.Delete(ctx, policyServerFactory(policyServerName)),
				).To(Succeed())

				// wait for the reconciliation loop of the ClusterAdmissionPolicy to remove the resource
				Eventually(func() error {
					_, err := getTestClusterAdmissionPolicy(policyName)
					return err
				}, timeout, pollInterval).ShouldNot(Succeed())

				Eventually(func() error {
					_, err := getTestPolicyServerService(policyServerName)
					return err
				}, timeout, pollInterval).ShouldNot(Succeed())

				Eventually(func() (*policiesv1.PolicyServer, error) {
					return getTestPolicyServer(policyServerName)
				}, timeout, pollInterval).ShouldNot(
					HaveField("Finalizers", ContainElement(constants.KubewardenFinalizer)),
				)
			})
		})

		Context("with no assigned policies", func() {
			It("should get its finalizer removed", func() {
				Expect(
					k8sClient.Delete(ctx, policyServerFactory(policyServerName)),
				).To(Succeed())

				Eventually(func() (*policiesv1.PolicyServer, error) {
					return getTestPolicyServer(policyServerName)
				}, timeout, pollInterval).ShouldNot(
					HaveField("Finalizers", ContainElement(constants.KubewardenFinalizer)),
				)
			})

		})
	})

	When("creating a new PolicyServer", func() {
		var policyServer *policiesv1.PolicyServer

		JustBeforeEach(func() {
			Expect(
				k8sClient.Create(ctx, policyServer),
			).To(haveSucceededOrAlreadyExisted())
			// Wait for the Service associated with the PolicyServer to be created
			Eventually(func() error {
				_, err := getTestPolicyServerService(policyServerName)
				return err
			}, timeout, pollInterval).Should(Succeed())
		})

		AfterEach(func() {
			// As we are testing policy server deletion, we need to remove the finalizer
			// from the policy server to allow the deletion to happen.
			// This is necessary because the JustBeforeEach block creates a policy server
			// for every single test here.
			Eventually(func() error {
				policyServer, err := getTestPolicyServer(policyServerName)
				if err != nil {
					fmt.Println("cannot get policy server")
					fmt.Println(err)
					return err
				}
				controllerutil.RemoveFinalizer(policyServer, IntegrationTestsFinalizer)
				err = reconciler.Client.Update(ctx, policyServer)
				if err != nil {
					fmt.Println("cannot update policy server")
					fmt.Println(err)
				}
				return err
			}).Should(Succeed())
			Expect(k8sClient.Delete(ctx, policyServer)).To(Succeed())
			Eventually(func() error {
				_, err := getTestPolicyServer(policyServerName)
				return err
			}, timeout, pollInterval).ShouldNot(Succeed())

		})

		Context("with no assigned policies", func() {

			BeforeEach(func() {
				policyServer = policyServerFactory(policyServerName)
			})

			It("the policy server configmap should be created empty", func() {
				Eventually(func() error {
					_, err := getTestPolicyServerConfigMap(policyServerName)
					return err
				}, timeout, pollInterval).Should(Succeed())
				configmap, err := getTestPolicyServerConfigMap(policyServerName)
				Expect(err).ToNot(HaveOccurred())
				Expect(configmap).To(PointTo(MatchFields(IgnoreExtras, Fields{
					"Data": MatchAllKeys(Keys{
						constants.PolicyServerConfigPoliciesEntry: Equal("{}"),
						constants.PolicyServerConfigSourcesEntry:  Equal("{}"),
					}),
				})))
			})
		})

		Context("with PodDisruptionBudget configuration", func() {

			BeforeEach(func() {
				policyServer = policyServerFactory(policyServerName)
			})

			Context("with MinAvailable set", func() {
				var minAvailable *intstr.IntOrString

				BeforeEach(func() {
					available := intstr.FromInt(2)
					minAvailable = &available
					policyServer.Spec.MinAvailable = minAvailable
				})
				It("should create a PodDisruptionBudget with MinAvailable set", func() {
					Eventually(func() *k8spoliciesv1.PodDisruptionBudget {
						pdb, _ := getPolicyServerPodDisruptionBudget(policyServerName)
						return pdb
					}, timeout, pollInterval).Should(policyServerPodDisruptionBudgetMatcher(policyServer, minAvailable, nil))
				})
			})

			Context("with MaxUnavailable set", func() {
				var maxUnavailable *intstr.IntOrString

				BeforeEach(func() {
					unavailable := intstr.FromInt(2)
					maxUnavailable = &unavailable
					policyServer.Spec.MaxUnavailable = maxUnavailable
				})

				It("should create a PodDisruptionBudget with MaxUnavailable set", func() {
					Eventually(func() *k8spoliciesv1.PodDisruptionBudget {
						pdb, _ := getPolicyServerPodDisruptionBudget(policyServerName)
						return pdb
					}, timeout, pollInterval).Should(policyServerPodDisruptionBudgetMatcher(policyServer, nil, maxUnavailable))
				})
			})

			It("with no PodDisruptionBudget configuration should not create a PodDisruptionBudget", func() {
				Consistently(func() error {
					_, err := getPolicyServerPodDisruptionBudget(policyServerName)
					return err
				}, 10*time.Second, pollInterval).ShouldNot(Succeed())
			})

			It("updating the policy server with a PodDisruptionBudget configuration should create a PodDisruptionBudget with the new configuration", func() {
				Consistently(func() error {
					_, err := getPolicyServerPodDisruptionBudget(policyServerName)
					return err
				}, 10*time.Second, pollInterval).ShouldNot(Succeed())

				By("updating the PolicyServer with a MaxAvailable PDB configuration")
				policyServer, err := getTestPolicyServer(policyServerName)
				Expect(err).ToNot(HaveOccurred())
				maxUnavailable := intstr.FromInt(2)
				policyServer.Spec.MaxUnavailable = &maxUnavailable
				err = k8sClient.Update(ctx, policyServer)
				Expect(err).ToNot(HaveOccurred())

				By("creating a PodDisruptionBudget with a MaxUnavailable configuration")
				Eventually(func() *k8spoliciesv1.PodDisruptionBudget {
					pdb, _ := getPolicyServerPodDisruptionBudget(policyServerName)
					return pdb
				}, timeout, pollInterval).Should(policyServerPodDisruptionBudgetMatcher(policyServer, nil, &maxUnavailable))
			})
		})

		Context("with requests and no limits", func() {

			BeforeEach(func() {
				policyServer = policyServerFactory(policyServerName)
				policyServer.Spec.Limits = corev1.ResourceList{
					"cpu":    resource.MustParse("100m"),
					"memory": resource.MustParse("1Gi"),
				}
			})

			It("should create the PolicyServer pod with the limits and the requests", func() {
				By("creating a deployment with limits and requests set")
				Eventually(func() error {
					deployment, err := getTestPolicyServerDeployment(policyServerName)
					if err != nil {
						return err
					}
					Expect(deployment.Spec.Template.Spec.Containers[0].Resources.Limits).To(Equal(policyServer.Spec.Limits))
					return nil
				}, timeout, pollInterval).Should(Succeed())

				By("creating a pod with limit and request set")
				Eventually(func() error {
					pod, err := getTestPolicyServerPod(policyServerName)
					if err != nil {
						return err
					}

					Expect(pod.Spec.Containers[0].Resources.Limits).To(Equal(policyServer.Spec.Limits))

					By("setting the requests to the same value as the limits")
					Expect(pod.Spec.Containers[0].Resources.Requests).To(Equal(policyServer.Spec.Limits))

					return nil
				}, timeout, pollInterval).Should(Succeed())
			})

			It("when the requests are updated should update the PolicyServer pod with the new requests", func() {
				By("updating the PolicyServer requests")
				updatedRequestsResources := corev1.ResourceList{
					"cpu":    resource.MustParse("50m"),
					"memory": resource.MustParse("500Mi"),
				}
				Eventually(func() error {
					policyServer, err := getTestPolicyServer(policyServerName)
					if err != nil {
						return err
					}
					policyServer.Spec.Requests = updatedRequestsResources
					return k8sClient.Update(ctx, policyServer)
				}).Should(Succeed())

				By("updating the pod with the new requests")
				Eventually(func() (*corev1.Container, error) {
					pod, err := getTestPolicyServerPod(policyServerName)
					if err != nil {
						return nil, err
					}
					return &pod.Spec.Containers[0], nil
				}, timeout, pollInterval).Should(
					And(
						HaveField("Resources.Requests", Equal(updatedRequestsResources)),
						HaveField("Resources.Limits", Equal(policyServer.Spec.Limits)),
					),
				)
			})
		})
	})
})
