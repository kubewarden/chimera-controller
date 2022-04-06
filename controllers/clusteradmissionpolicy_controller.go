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
	"context"
	"fmt"

	"github.com/go-logr/logr"
	v1alpha2 "github.com/kubewarden/kubewarden-controller/apis/v1alpha2"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admission"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/naming"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

//+kubebuilder:rbac:groups=policies.kubewarden.io,resources=clusteradmissionpolicies,verbs=get;list;watch;delete
//+kubebuilder:rbac:groups=policies.kubewarden.io,resources=clusteradmissionpolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=policies.kubewarden.io,resources=clusteradmissionpolicies/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
//+kubebuilder:rbac:groups=apps,resources=replicasets;deployments,verbs=get;list;watch

// ClusterAdmissionPolicyReconciler reconciles a ClusterAdmissionPolicy object
type ClusterAdmissionPolicyReconciler struct {
	client.Client
	Log        logr.Logger
	Scheme     *runtime.Scheme
	Reconciler admission.Reconciler
}

// Reconcile reconciles admission policies
func (r *ClusterAdmissionPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var clusterAdmissionPolicy v1alpha2.ClusterAdmissionPolicy
	if err := r.Reconciler.APIReader.Get(ctx, req.NamespacedName, &clusterAdmissionPolicy); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("cannot retrieve admission policy: %w", err)
	}

	return startReconciling(ctx, r.Reconciler.Client, r.Reconciler, &clusterAdmissionPolicy)
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterAdmissionPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha2.ClusterAdmissionPolicy{}).
		Watches(
			&source.Kind{Type: &corev1.Pod{}},
			handler.EnqueueRequestsFromMapFunc(r.findClusterAdmissionPoliciesForPod),
		).
		// Despite this policy server watch is not strictly necessary, we
		// include it for the integration tests, so that we identify
		// policy server creations even when the controller-manager is not
		// present (so no pods end up being created)
		Watches(
			&source.Kind{Type: &v1alpha2.PolicyServer{}},
			handler.EnqueueRequestsFromMapFunc(r.findClusterAdmissionPoliciesForPolicyServer),
		).
		Complete(r)

	return errors.Wrap(err, "failed enrolling controller with manager")
}

func (r *ClusterAdmissionPolicyReconciler) findClusterAdmissionPoliciesForConfigMap(object client.Object) []reconcile.Request {
	configMap, ok := object.(*corev1.ConfigMap)
	if !ok {
		return []reconcile.Request{}
	}
	policyMap, err := getPolicyMapFromConfigMap(configMap)
	if err != nil {
		return []reconcile.Request{}
	}
	return policyMap.ToClusterAdmissionPolicyReconcileRequests()
}

func (r *ClusterAdmissionPolicyReconciler) findClusterAdmissionPoliciesForPod(object client.Object) []reconcile.Request {
	pod, ok := object.(*corev1.Pod)
	if !ok {
		return []reconcile.Request{}
	}
	policyServerName, ok := pod.Labels[constants.PolicyServerLabelKey]
	if !ok {
		return []reconcile.Request{}
	}
	policyServerDeploymentName := naming.PolicyServerDeploymentNameForPolicyServerName(policyServerName)
	configMap := corev1.ConfigMap{}
	err := r.Reconciler.APIReader.Get(context.TODO(), client.ObjectKey{
		Namespace: pod.ObjectMeta.Namespace,
		Name:      policyServerDeploymentName, // As the deployment name matches the name of the ConfigMap
	}, &configMap)
	if err != nil {
		return []reconcile.Request{}
	}
	return r.findClusterAdmissionPoliciesForConfigMap(&configMap)
}

func (r *ClusterAdmissionPolicyReconciler) findClusterAdmissionPoliciesForPolicyServer(object client.Object) []reconcile.Request {
	policyServer, ok := object.(*v1alpha2.PolicyServer)
	if !ok {
		return []reconcile.Request{}
	}
	policyServerDeploymentName := naming.PolicyServerDeploymentNameForPolicyServerName(policyServer.Name)
	configMap := corev1.ConfigMap{}
	err := r.Reconciler.APIReader.Get(context.TODO(), client.ObjectKey{
		Namespace: r.Reconciler.DeploymentsNamespace,
		Name:      policyServerDeploymentName, // As the deployment name matches the name of the ConfigMap
	}, &configMap)
	if err != nil {
		return []reconcile.Request{}
	}
	return r.findClusterAdmissionPoliciesForConfigMap(&configMap)
}
