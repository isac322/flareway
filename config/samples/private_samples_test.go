/*
Copyright 2026 Byeonghoon Yoo.

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

package samples

import (
	"io"
	"os"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

func TestPrivateGatewaySampleAuthorizesOriginJWTDisableAndReferencesTLSSecret(t *testing.T) {
	objects := decodeSample(t, "gateway_v1_private_gateway.yaml")
	namespace := sampleByKind(t, objects, "Namespace")
	if namespace.GetLabels()["flareway.bhyoo.com/allow-origin-jwt-disable"] != "true" {
		t.Fatal("private Gateway namespace must explicitly approve originJWT Disabled")
	}
	gateway := sampleByKind(t, objects, "Gateway")
	listeners, found, err := unstructured.NestedSlice(gateway.Object, "spec", "listeners")
	if err != nil || !found || len(listeners) != 1 {
		t.Fatalf("private Gateway listeners = %#v, found=%t, err=%v", listeners, found, err)
	}
	listener := listeners[0].(map[string]any)
	certificateRefs, found, err := unstructured.NestedSlice(listener, "tls", "certificateRefs")
	if err != nil || !found || len(certificateRefs) != 1 {
		t.Fatalf("private listener certificateRefs = %#v, found=%t, err=%v", certificateRefs, found, err)
	}
	certificateRef := certificateRefs[0].(map[string]any)
	if certificateRef["kind"] != "Secret" || certificateRef["name"] != "cc-lb-private-tls" {
		t.Fatalf("private listener certificateRef = %#v", certificateRef)
	}
}

func TestPrivateAccessSamplesSeparateHTTPSAuthorizationFromL4Destination(t *testing.T) {
	objects := decodeSample(t, "flareway_v1alpha1_accessapplication_private.yaml")
	if len(objects) != 2 {
		t.Fatalf("private Access sample documents = %d, want 2", len(objects))
	}
	byName := map[string]*unstructured.Unstructured{}
	for _, object := range objects {
		byName[object.GetName()] = object
	}
	https := byName["cc-lb-private-https"]
	if https == nil {
		t.Fatal("missing targetRef-based private HTTPS AccessApplication")
	}
	targetRefs, found, err := unstructured.NestedSlice(https.Object, "spec", "targetRefs")
	if err != nil || !found || len(targetRefs) != 1 {
		t.Fatalf("private HTTPS targetRefs = %#v, found=%t, err=%v", targetRefs, found, err)
	}
	target := targetRefs[0].(map[string]any)
	if target["kind"] != "Gateway" || target["name"] != "cc-lb" || target["sectionName"] != "admin-private" {
		t.Fatalf("private HTTPS targetRef = %#v", target)
	}
	if _, found, err := unstructured.NestedSlice(https.Object, "spec", "privateDestinations"); err != nil || found {
		t.Fatalf("private HTTPS sample must not use route-backed privateDestinations; found=%t err=%v", found, err)
	}

	l4 := byName["cc-lb-private-l4"]
	if l4 == nil {
		t.Fatal("missing route-backed private L4 AccessApplication")
	}
	destinations, found, err := unstructured.NestedSlice(l4.Object, "spec", "privateDestinations")
	if err != nil || !found || len(destinations) != 1 {
		t.Fatalf("private L4 destinations = %#v, found=%t, err=%v", destinations, found, err)
	}
	destination := destinations[0].(map[string]any)
	networkRef, found, err := unstructured.NestedMap(destination, "networkRouteRef")
	if err != nil || !found || networkRef["name"] != "private-services" {
		t.Fatalf("private L4 networkRouteRef = %#v, found=%t, err=%v", networkRef, found, err)
	}
}

func decodeSample(t *testing.T, path string) []*unstructured.Unstructured {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close %s: %v", path, err)
		}
	}()
	decoder := utilyaml.NewYAMLOrJSONDecoder(file, 4096)
	objects := make([]*unstructured.Unstructured, 0)
	for {
		var object unstructured.Unstructured
		if err := decoder.Decode(&object); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("decode %s: %v", path, err)
		}
		if len(object.Object) != 0 {
			objects = append(objects, &object)
		}
	}
	return objects
}

func sampleByKind(t *testing.T, objects []*unstructured.Unstructured, kind string) *unstructured.Unstructured {
	t.Helper()
	for _, object := range objects {
		if object.GetKind() == kind {
			return object
		}
	}
	t.Fatalf("sample has no %s", kind)
	return nil
}
