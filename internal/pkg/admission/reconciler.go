package admission

import (
	"context"
	"errors"
	"fmt"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admissionregistration"
	appsv1 "k8s.io/api/apps/v1"
	"strings"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policiesv1alpha2 "github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
)

type Reconciler struct {
	Client               client.Client
	DeploymentsNamespace string
	Log                  logr.Logger
}

type errorList []error

func (errorList errorList) Error() string {
	errors := []string{}
	for _, error := range errorList {
		errors = append(errors, error.Error())
	}
	return strings.Join(errors, ", ")
}

func (r *Reconciler) ReconcileDeletion(
	ctx context.Context,
	policyServer *policiesv1alpha2.PolicyServer,
) error {
	errors := errorList{}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer.NameWithPrefix(),
			Namespace: r.DeploymentsNamespace,
		},
	}
	err := r.Client.Delete(ctx, deployment)
	if err != nil {
		r.Log.Error(err, "ReconcileDeletion: cannot delete PolicyServer Deployment %s", policyServer.Name)
		errors = append(errors, err)
	}

	certificateSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer.NameWithPrefix(),
			Namespace: r.DeploymentsNamespace,
		},
	}

	err = r.Client.Delete(ctx, certificateSecret)
	if err != nil {
		r.Log.Error(err, "ReconcileDeletion: cannot delete PolicyServer Certificate Secret %s", policyServer.Name)
		errors = append(errors, err)
	}

	if len(errors) == 0 {
		return nil
	}

	return errors
}

func setFalseConditionType(
	conditions *[]metav1.Condition,
	conditionType policiesv1alpha2.PolicyConditionType,
	message string,
) {
	apimeta.SetStatusCondition(
		conditions,
		metav1.Condition{
			Type:    string(conditionType),
			Status:  metav1.ConditionFalse,
			Reason:  string(policiesv1alpha2.ReconciliationFailed),
			Message: message,
		},
	)
}

func setTrueConditionType(conditions *[]metav1.Condition, conditionType policiesv1alpha2.PolicyConditionType) {
	apimeta.SetStatusCondition(
		conditions,
		metav1.Condition{
			Type:   string(conditionType),
			Status: metav1.ConditionTrue,
			Reason: string(policiesv1alpha2.ReconciliationSucceeded),
		},
	)
}

func (r *Reconciler) Reconcile(
	ctx context.Context,
	policyServer *policiesv1alpha2.PolicyServer,
) error {
	policyServerCARootSecret, err := r.fetchOrInitializePolicyServerCARootSecret(ctx, admissionregistration.GenerateCA, admissionregistration.PemEncodeCertificate)
	if err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			policiesv1alpha2.PolicyServerCARootSecretReconciled,
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return err
	}

	if err := r.reconcileSecret(ctx, policyServerCARootSecret); err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			policiesv1alpha2.PolicyServerCARootSecretReconciled,
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return err
	}

	setTrueConditionType(
		&policyServer.Status.Conditions,
		policiesv1alpha2.PolicyServerCARootSecretReconciled,
	)

	policyServerSecret, err := r.fetchOrInitializePolicyServerSecret(ctx, policyServer.NameWithPrefix(), policyServerCARootSecret, admissionregistration.GenerateCert)
	if err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			policiesv1alpha2.PolicyServerSecretReconciled,
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return err
	}

	if err := r.reconcileSecret(ctx, policyServerSecret); err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			policiesv1alpha2.PolicyServerSecretReconciled,
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return err
	}

	if err := r.reconcilePolicyServerConfigMap(ctx, policyServer, AddPolicy); err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			policiesv1alpha2.PolicyServerConfigMapReconciled,
			fmt.Sprintf("error reconciling configmap: %v", err),
		)
		return err
	}

	setTrueConditionType(
		&policyServer.Status.Conditions,
		policiesv1alpha2.PolicyServerConfigMapReconciled,
	)

	if err := r.reconcilePolicyServerDeployment(ctx, policyServer); err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			policiesv1alpha2.PolicyServerDeploymentReconciled,
			fmt.Sprintf("error reconciling deployment: %v", err),
		)
		return err
	}

	setTrueConditionType(
		&policyServer.Status.Conditions,
		policiesv1alpha2.PolicyServerDeploymentReconciled,
	)
	// TODO reconcile service and webhook

	return nil
}

func (r *Reconciler) enablePolicyWebhook(
	ctx context.Context,
	clusterAdmissionPolicy *policiesv1alpha2.ClusterAdmissionPolicy,
	policyServerSecret *corev1.Secret,
	policyServerName string) error {
	policyServerReady, err := r.isPolicyServerReady(ctx)

	if err != nil {
		return err
	}

	if !policyServerReady {
		return errors.New("policy server not yet ready")
	}

	// register the new dynamic admission controller only once the policy is
	// served by the PolicyServer deployment
	if clusterAdmissionPolicy.Spec.Mutating {
		if err := r.reconcileMutatingWebhookConfiguration(ctx, clusterAdmissionPolicy, policyServerSecret, policyServerName); err != nil {
			setFalseConditionType(
				&clusterAdmissionPolicy.Status.Conditions,
				policiesv1alpha2.PolicyServerWebhookConfigurationReconciled,
				fmt.Sprintf("error reconciling mutating webhook configuration: %v", err),
			)
			return err
		}

		setTrueConditionType(
			&clusterAdmissionPolicy.Status.Conditions,
			policiesv1alpha2.PolicyServerWebhookConfigurationReconciled,
		)
	} else {
		if err := r.reconcileValidatingWebhookConfiguration(ctx, clusterAdmissionPolicy, policyServerSecret, policyServerName); err != nil {
			setFalseConditionType(
				&clusterAdmissionPolicy.Status.Conditions,
				policiesv1alpha2.PolicyServerWebhookConfigurationReconciled,
				fmt.Sprintf("error reconciling validating webhook configuration: %v", err),
			)
			return err
		}

		setTrueConditionType(
			&clusterAdmissionPolicy.Status.Conditions,
			policiesv1alpha2.PolicyServerWebhookConfigurationReconciled,
		)
	}

	return nil
}
