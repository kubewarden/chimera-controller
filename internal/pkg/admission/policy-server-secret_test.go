package admission

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admissionregistration"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"testing"
)

func TestFetchOrInitializePolicyServerCARootSecret(t *testing.T) {
	caPemBytes := []byte{}
	ca, err := admissionregistration.GenerateCA()
	generateCACalled := false

	generateCAFunc := func() (*admissionregistration.CA, error) {
		generateCACalled = true
		return ca, err
	}

	pemEncodeCertificateFunc := func(certificate []byte) ([]byte, error) {
		if bytes.Compare(certificate, ca.CaCert) != 0 {
			return nil, fmt.Errorf("certificate received should be the one returned by generateCA")
		}
		return caPemBytes, nil
	}

	caSecretContents := map[string][]byte{
		constants.PolicyServerCARootCACert:             ca.CaCert,
		constants.PolicyServerCARootPemName:            caPemBytes,
		constants.PolicyServerCARootPrivateKeyCertName: x509.MarshalPKCS1PrivateKey(ca.CaPrivateKey),
	}

	var tests = []struct {
		name             string
		r                Reconciler
		err              error
		secretContents   map[string][]byte
		generateCACalled bool
	}{
		{"Existing CA", createReconcilerWithExistingCA(), nil, mockSecretContents, false},
		{"CA does not exist", createReconcilerWithEmptyClient(), nil, caSecretContents, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			secret, err := test.r.fetchOrInitializePolicyServerCARootSecret(context.Background(), generateCAFunc, pemEncodeCertificateFunc)
			if diff := cmp.Diff(secret.Data, test.secretContents); diff != "" {
				t.Errorf("got an unexpected secret, diff %s", diff)
			}

			if err != test.err {
				t.Errorf("got %s, want %s", err, test.err)
			}

			if generateCACalled != test.generateCACalled {
				t.Errorf("got %t, want %t", generateCACalled, test.generateCACalled)
			}
			generateCACalled = false
		})
	}

}

func TestFetchOrInitializePolicyServerSecret(t *testing.T) {
	generateCertCalled := false
	servingCert := []byte{1}
	servingKey := []byte{2}
	ca, _ := admissionregistration.GenerateCA()
	caSecret := &corev1.Secret{Data: map[string][]byte{constants.PolicyServerCARootCACert: ca.CaCert, constants.PolicyServerCARootPrivateKeyCertName: x509.MarshalPKCS1PrivateKey(ca.CaPrivateKey)}}

	generateCertFunc := func(ca []byte, commonName string, extraSANs []string, CAPrivateKey *rsa.PrivateKey) ([]byte, []byte, error) {
		generateCertCalled = true
		return servingCert, servingKey, nil
	}

	caSecretContents := map[string]string{
		constants.PolicyServerTLSCert: string(servingCert),
		constants.PolicyServerTLSKey:  string(servingKey),
	}

	var tests = []struct {
		name               string
		r                  Reconciler
		err                error
		secretContents     map[string]string
		generateCertCalled bool
	}{
		{"Existing cert", createReconcilerWithExistingCert(), nil, mockSecretCert, false},
		{"cert does not exist", createReconcilerWithEmptyClient(), nil, caSecretContents, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			secret, err := test.r.fetchOrInitializePolicyServerSecret(context.Background(), "policyServer", caSecret, generateCertFunc)
			if diff := cmp.Diff(secret.StringData, test.secretContents); diff != "" {
				t.Errorf("got an unexpected secret, diff %s", diff)
			}

			if err != test.err {
				t.Errorf("got %s, want %s", err, test.err)
			}

			if generateCertCalled != test.generateCertCalled {
				t.Errorf("got %t, want %t", generateCertCalled, test.generateCertCalled)
			}
			generateCertCalled = false
		})
	}

}

const namespace = "namespace"

var mockSecretContents = map[string][]byte{"ca": []byte("secretContents")}

func createReconcilerWithExistingCA() Reconciler {
	mockSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.PolicyServerCARootSecretName,
			Namespace: namespace,
		},
		Data: mockSecretContents,
		Type: corev1.SecretTypeOpaque,
	}

	// Create a fake client to mock API calls. It will return the mock secret
	cl := fake.NewClientBuilder().WithObjects(mockSecret).Build()
	return Reconciler{
		Client:               cl,
		DeploymentsNamespace: namespace,
	}
}

var mockSecretCert = map[string]string{"cert": "certString"}

func createReconcilerWithExistingCert() Reconciler {
	mockSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policyServer",
			Namespace: namespace,
		},
		StringData: mockSecretCert,
		Type:       corev1.SecretTypeOpaque,
	}

	// Create a fake client to mock API calls. It will return the mock secret
	cl := fake.NewClientBuilder().WithObjects(mockSecret).Build()
	return Reconciler{
		Client:               cl,
		DeploymentsNamespace: namespace,
	}
}

func createReconcilerWithEmptyClient() Reconciler {
	// Create a fake client to mock API calls.
	cl := fake.NewClientBuilder().WithObjects().Build()
	return Reconciler{
		Client:               cl,
		DeploymentsNamespace: namespace,
	}
}
