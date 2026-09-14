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
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestGlobalSamplesRemainObserveOnlyAndOrphanByDefault(t *testing.T) {
	paths := []string{
		"flareway_v1alpha1_deviceprofile.yaml",
		"flareway_v1alpha1_devicesettings.yaml",
		"flareway_v1alpha1_zerotrustorganization.yaml",
		"flareway_v1alpha1_zerotrustgatewaypolicy.yaml",
		"flareway_v1alpha1_zerotrustlist.yaml",
	}
	seen := map[string]bool{}
	for _, path := range paths {
		for _, object := range decodeSample(t, path) {
			seen[object.GetKind()] = true
			management, found, err := unstructured.NestedString(object.Object, "spec", "managementPolicy")
			if err != nil || !found || management != "ObserveOnly" {
				t.Fatalf("%s %s managementPolicy=%q found=%t err=%v", object.GetKind(), object.GetName(), management, found, err)
			}
			deletion, found, err := unstructured.NestedString(object.Object, "spec", "deletionPolicy")
			if err != nil || !found || deletion != "Orphan" {
				t.Fatalf("%s %s deletionPolicy=%q found=%t err=%v", object.GetKind(), object.GetName(), deletion, found, err)
			}
		}
	}
	for _, kind := range []string{"DeviceProfile", "DeviceSettings", "ZeroTrustOrganization", "ZeroTrustGatewayPolicy", "ZeroTrustList"} {
		if !seen[kind] {
			t.Errorf("global samples have no %s", kind)
		}
	}
}

func TestSingletonGlobalSamplesUseDefaultName(t *testing.T) {
	for _, path := range []string{"flareway_v1alpha1_devicesettings.yaml", "flareway_v1alpha1_zerotrustorganization.yaml"} {
		objects := decodeSample(t, path)
		if len(objects) != 1 || objects[0].GetName() != "default" {
			t.Fatalf("%s singleton sample = %#v", path, objects)
		}
	}
}
