package admission

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/admissionregistration"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

type generateCAFunc = func() (*admissionregistration.CA, error)
type pemEncodeCertificateFunc = func(certificate []byte) ([]byte, error)
type generateCertFunc = func(ca []byte, commonName string, extraSANs []string, CAPrivateKey *rsa.PrivateKey) ([]byte, []byte, error)

func (r *Reconciler) reconcileSecret(ctx context.Context, secret *corev1.Secret) error {
	err := r.Client.Create(ctx, secret)
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}

	return fmt.Errorf("error reconciling policy-server Secret: %w", err)
}

func (r *Reconciler) fetchOrInitializePolicyServerSecret(ctx context.Context, policyServerName string, caSecret *corev1.Secret, generateCert generateCertFunc) (*corev1.Secret, error) {
	policyServerSecret := corev1.Secret{}
	err := r.Client.Get(
		ctx,
		client.ObjectKey{
			Namespace: r.DeploymentsNamespace,
			Name:      constants.PolicyServerSecretNamePrefix + policyServerName},
		&policyServerSecret)
	if err != nil && apierrors.IsNotFound(err) {
		return r.buildPolicyServerSecret(policyServerName, caSecret, generateCert)
	}
	if err != nil {
		return &corev1.Secret{},
			fmt.Errorf("cannot fetch or initialize Policy Server secret: %w", err)
	}

	policyServerSecret.ResourceVersion = ""

	return &policyServerSecret, nil
}

func (r *Reconciler) buildPolicyServerSecret(policyServerName string, caSecret *corev1.Secret, generateCert generateCertFunc) (*corev1.Secret, error) {
	ca, err := extractCaFromSecret(caSecret)
	servingCert, servingKey, err := generateCert(
		ca.CaCert,
		fmt.Sprintf("%s.%s.svc", constants.PolicyServerServiceNamePrefix+policyServerName, r.DeploymentsNamespace),
		[]string{fmt.Sprintf("%s.%s.svc", constants.PolicyServerServiceNamePrefix+policyServerName, r.DeploymentsNamespace)},
		ca.CaPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate policy-server %s certificate: %w", policyServerName, err)
	}
	secretContents := map[string]string{
		constants.PolicyServerTLSCert: string(servingCert),
		constants.PolicyServerTLSKey:  string(servingKey),
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.PolicyServerSecretNamePrefix + policyServerName,
			Namespace: r.DeploymentsNamespace,
		},
		StringData: secretContents,
		Type:       corev1.SecretTypeOpaque,
	}, nil
}

func extractCaFromSecret(caSecret *corev1.Secret) (*admissionregistration.CA, error) {
	caCert, ok := caSecret.Data[constants.PolicyServerCARootCACert]
	if !ok {
		return nil, fmt.Errorf("")
	}
	caPrivateKeyBytes, ok := caSecret.Data[constants.PolicyServerCARootPrivateKeyCertName]
	if !ok {
		return nil, fmt.Errorf("")
	}

	caPrivateKey, err := x509.ParsePKCS1PrivateKey(caPrivateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("")
	}
	return &admissionregistration.CA{CaCert: caCert, CaPrivateKey: caPrivateKey}, nil
}

func (r *Reconciler) fetchOrInitializePolicyServerCARootSecret(ctx context.Context, generateCA generateCAFunc, pemEncodeCertificate pemEncodeCertificateFunc) (*corev1.Secret, error) {
	policyServerSecret := corev1.Secret{}
	err := r.Client.Get(
		ctx,
		client.ObjectKey{
			Namespace: r.DeploymentsNamespace,
			Name:      constants.PolicyServerCARootSecretName},
		&policyServerSecret)
	if err != nil && apierrors.IsNotFound(err) {
		return r.buildPolicyServerCARootSecret(generateCA, pemEncodeCertificate)
	}
	policyServerSecret.ResourceVersion = ""
	if err != nil {
		return &corev1.Secret{},
			fmt.Errorf("cannot fetch or initialize Policy Server secret: %w", err)
	}

	return &policyServerSecret, nil
}

func (r *Reconciler) buildPolicyServerCARootSecret(generateCA generateCAFunc, pemEncodeCertificate pemEncodeCertificateFunc) (*corev1.Secret, error) {
	ca, err := generateCA()
	if err != nil {
		return nil, fmt.Errorf("cannot generate policy-server secret CA: %w", err)
	}
	caPEMEncoded, err := pemEncodeCertificate(ca.CaCert)
	if err != nil {
		return nil, fmt.Errorf("cannot encode policy-server secret CA: %w", err)
	}
	caPrivateKeyBytes := x509.MarshalPKCS1PrivateKey(ca.CaPrivateKey)
	secretContents := map[string][]byte{
		constants.PolicyServerCARootCACert:             ca.CaCert,
		constants.PolicyServerCARootPemName:            caPEMEncoded,
		constants.PolicyServerCARootPrivateKeyCertName: caPrivateKeyBytes,
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.PolicyServerCARootSecretName,
			Namespace: r.DeploymentsNamespace,
		},
		Data: secretContents,
		Type: corev1.SecretTypeOpaque,
	}, nil
}
