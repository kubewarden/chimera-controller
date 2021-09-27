module github.com/kubewarden/kubewarden-controller

go 1.15

require (
	cloud.google.com/go v0.60.0 // indirect
	github.com/ereslibre/kube-webhook-wrapper v0.0.0-20210917112934-65d7cb499c29
	github.com/go-logr/logr v0.4.0
	github.com/google/go-cmp v0.5.5
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.15.0
	github.com/pkg/errors v0.9.1
	k8s.io/api v0.22.1
	k8s.io/apimachinery v0.22.1
	k8s.io/client-go v0.22.1
	sigs.k8s.io/controller-runtime v0.10.0
)

replace github.com/ereslibre/kube-webhook-wrapper => ../../kube-webhook-wrapper
