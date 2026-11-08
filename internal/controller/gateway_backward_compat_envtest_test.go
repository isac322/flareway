/*
Copyright 2026 The Flareway Authors.

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
	"os"
	"os/exec"
	"strings"
	"path/filepath"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/gatewayapi"
)

func TestGatewayBackwardCompatV163StandardCRDs(t *testing.T) {
	crds := gatewayAPIV163StandardCRDs(t)
	environment := &envtest.Environment{
		CRDs: crds,
		CRDDirectoryPaths: []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	config, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := environment.Stop(); err != nil {
			t.Error(err)
		}
	}()

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := gatewayv1.Install(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	kube, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := kube.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "flareway-system"}}); err != nil {
		t.Fatal(err)
	}

	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "compat-v163"}}
	if err := kube.Create(ctx, namespace); err != nil {
		t.Fatal(err)
	}
	configObject := defaultGatewayClassConfig()
	configObject.Name = "compat-config"
	configObject.Spec.ConformanceMode = true
	if err := kube.Create(ctx, configObject); err != nil {
		t.Fatal(err)
	}
	class := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "compat-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayapi.ControllerName,
			ParametersRef: &gatewayv1.ParametersReference{
				Group: gatewayv1.Group(v1alpha1.Group), Kind: gatewayv1.Kind("GatewayClassConfig"), Name: configObject.Name,
			},
		},
	}
	if err := kube.Create(ctx, class); err != nil {
		t.Fatal(err)
	}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "compat-gateway", Namespace: namespace.Name},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(class.Name),
			Listeners: []gatewayv1.Listener{{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80}},
		},
	}
	if err := kube.Create(ctx, gateway); err != nil {
		t.Fatal(err)
	}
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "compat-route", Namespace: namespace.Name},
		Spec: gatewayv1.HTTPRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gateway.Name)}}},
	}
	if err := kube.Create(ctx, route); err != nil {
		t.Fatal(err)
	}
	grant := &gatewayv1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "compat-grant", Namespace: namespace.Name},
		Spec: gatewayv1.ReferenceGrantSpec{
			From: []gatewayv1.ReferenceGrantFrom{{
				Group: gatewayv1.Group(gatewayv1.GroupName), Kind: gatewayv1.Kind("HTTPRoute"), Namespace: gatewayv1.Namespace(namespace.Name),
			}},
			To: []gatewayv1.ReferenceGrantTo{{Group: gatewayv1.Group(""), Kind: gatewayv1.Kind("Service")}},
		},
	}
	if err := kube.Create(ctx, grant); err != nil {
		t.Fatal(err)
	}
	wellKnown := gatewayv1.WellKnownCACertificatesType("System")
	policy := &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "compat-policy", Namespace: namespace.Name},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{Group: gatewayv1.Group(""), Kind: gatewayv1.Kind("Service"), Name: gatewayv1.ObjectName("backend")},
			}},
			Validation: gatewayv1.BackendTLSPolicyValidation{Hostname: gatewayv1.PreciseHostname("backend.example"), WellKnownCACertificates: &wellKnown},
		},
	}
	if err := kube.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}

	classReconciler := &GatewayClassReconciler{Client: kube, Scheme: scheme}
	if _, err := classReconciler.Reconcile(ctx, ctrlRequest(class.Name)); err != nil {
		t.Fatal(err)
	}
	gatewayReconciler := &GatewayReconciler{
		Client: kube, APIReader: kube, Scheme: scheme, Snapshots: newFakeSnapshotPublisher(),
	}
	if _, err := gatewayReconciler.Reconcile(ctx, ctrlRequest(namespace.Name, gateway.Name)); err != nil {
		t.Fatal(err)
	}

	var currentClass gatewayv1.GatewayClass
	if err := kube.Get(ctx, types.NamespacedName{Name: class.Name}, &currentClass); err != nil {
		t.Fatal(err)
	}
	if len(currentClass.Status.SupportedFeatures) != len(gatewayapi.SupportedFeatures()) {
		t.Fatalf("supportedFeatures = %d, want %d", len(currentClass.Status.SupportedFeatures), len(gatewayapi.SupportedFeatures()))
	}
	var currentGateway gatewayv1.Gateway
	if err := kube.Get(ctx, client.ObjectKeyFromObject(gateway), &currentGateway); err != nil {
		t.Fatal(err)
	}
	if len(currentGateway.Status.Conditions) == 0 {
		t.Fatal("Gateway status was not patched against v1.6.3 CRDs")
	}
}

func ctrlRequest(names ...string) ctrl.Request {
	if len(names) == 1 {
		return ctrl.Request{NamespacedName: types.NamespacedName{Name: names[0]}}
	}
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: names[0], Name: names[1]}}
}

func gatewayAPICRDDirectory(t *testing.T) string {
	t.Helper()
	output, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "sigs.k8s.io/gateway-api").Output()
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(strings.TrimSpace(string(output)), "config", "crd", "standard")
	if _, err := os.Stat(directory); err != nil {
		t.Fatal(err)
	}
	return directory
}

func gatewayAPIV163StandardCRDs(t *testing.T) []*apiextensionsv1.CustomResourceDefinition {
	t.Helper()
	entries, err := os.ReadDir(gatewayAPICRDDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	crds := make([]*apiextensionsv1.CustomResourceDefinition, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || (filepath.Ext(entry.Name()) != ".yaml" && filepath.Ext(entry.Name()) != ".yml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(gatewayAPICRDDirectory(t), entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := yaml.Unmarshal(data, crd); err != nil {
			t.Fatal(err)
		}
		if crd.Kind != "CustomResourceDefinition" || crd.Name == "" {
			continue
		}
		if crd.Annotations == nil {
			crd.Annotations = map[string]string{}
		}
		crd.Annotations["gateway.networking.k8s.io/bundle-version"] = "v1.6.3"
		if crd.Name == "httproutes.gateway.networking.k8s.io" {
			for i := range crd.Spec.Versions {
				schema := crd.Spec.Versions[i].Schema
				if schema == nil || schema.OpenAPIV3Schema == nil {
					continue
				}
				spec, ok := schema.OpenAPIV3Schema.Properties["spec"]
				if !ok {
					continue
				}
				rules, ok := spec.Properties["rules"]
				if !ok || rules.Items == nil || rules.Items.Schema == nil {
					continue
				}
				delete(rules.Items.Schema.Properties, "retry")
			}
		}
		crds = append(crds, crd)
	}
	return crds
}
