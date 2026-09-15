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
	tunnel := sampleByKind(t, objects, "CloudflareTunnel")
	mode, found, err := unstructured.NestedString(tunnel.Object, "spec", "configuration", "mode")
	if err != nil || !found || mode != "Gateway" {
		t.Fatalf("private tunnel configuration mode = %q, found=%t, err=%v", mode, found, err)
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
	if certificateRef["kind"] != "Secret" || certificateRef["name"] != "admin-internal-tls" {
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
	https := byName["private-https"]
	if https == nil {
		t.Fatal("missing targetRef-based private HTTPS AccessApplication")
	}
	targetRefs, found, err := unstructured.NestedSlice(https.Object, "spec", "targetRefs")
	if err != nil || !found || len(targetRefs) != 1 {
		t.Fatalf("private HTTPS targetRefs = %#v, found=%t, err=%v", targetRefs, found, err)
	}
	target := targetRefs[0].(map[string]any)
	if target["kind"] != "Gateway" || target["name"] != "private-gateway" || target["sectionName"] != "admin-private" {
		t.Fatalf("private HTTPS targetRef = %#v", target)
	}
	if _, found, err := unstructured.NestedSlice(https.Object, "spec", "destinations"); err != nil || found {
		t.Fatalf("private HTTPS sample must not use route-backed destinations; found=%t err=%v", found, err)
	}

	l4 := byName["private-l4"]
	if l4 == nil {
		t.Fatal("missing route-backed private L4 AccessApplication")
	}
	destinations, found, err := unstructured.NestedSlice(l4.Object, "spec", "destinations")
	if err != nil || !found || len(destinations) != 1 {
		t.Fatalf("private L4 destinations = %#v, found=%t, err=%v", destinations, found, err)
	}
	destination := destinations[0].(map[string]any)
	if destination["type"] != "Private" {
		t.Fatalf("private L4 destination type = %#v", destination["type"])
	}
	private, ok := destination["private"].(map[string]any)
	if !ok {
		t.Fatalf("private L4 destination payload = %#v", destination["private"])
	}
	networkRef, found, err := unstructured.NestedMap(private, "networkRouteRef")
	if err != nil || !found || networkRef["name"] != "private-services" {
		t.Fatalf("private L4 networkRouteRef = %#v, found=%t, err=%v", networkRef, found, err)
	}
}

func TestTunnelSamplesDeclareSingleWriterModesAndCompleteDirectConfiguration(t *testing.T) {
	gateway := sampleByKind(t, decodeSample(t, "flareway_v1alpha1_cloudflaretunnel.yaml"), "CloudflareTunnel")
	gatewayMode, found, err := unstructured.NestedString(gateway.Object, "spec", "configuration", "mode")
	if err != nil || !found || gatewayMode != "Gateway" {
		t.Fatalf("Gateway tunnel configuration mode = %q, found=%t, err=%v", gatewayMode, found, err)
	}
	gatewaySettings, found, err := unstructured.NestedMap(gateway.Object, "spec", "dns", "settings")
	if err != nil || !found || gatewaySettings["ipv4Only"] != false || gatewaySettings["ipv6Only"] != true {
		t.Fatalf("Gateway tunnel DNS settings = %#v, found=%t, err=%v", gatewaySettings, found, err)
	}

	direct := sampleByKind(t, decodeSample(t, "flareway_v1alpha1_cloudflaretunnel_direct.yaml"), "CloudflareTunnel")
	directMode, found, err := unstructured.NestedString(direct.Object, "spec", "configuration", "mode")
	if err != nil || !found || directMode != "Direct" {
		t.Fatalf("Direct tunnel configuration mode = %q, found=%t, err=%v", directMode, found, err)
	}
	if _, found, err := unstructured.NestedSlice(direct.Object, "spec", "listeners"); err != nil || found {
		t.Fatalf("Direct tunnel must not declare Gateway listeners; found=%t err=%v", found, err)
	}
	ingress, found, err := unstructured.NestedSlice(direct.Object, "spec", "configuration", "direct", "ingress")
	if err != nil || !found || len(ingress) != 11 {
		t.Fatalf("Direct tunnel ingress = %#v, found=%t, err=%v", ingress, found, err)
	}
	expectedServices := map[string]bool{
		"http": false, "https": false, "tcp": false, "ssh": false, "rdp": false, "smb": false,
		"unix": false, "unixTLS": false, "helloWorld": false, "httpStatus": false, "bastion": false,
	}
	for index, value := range ingress {
		rule := value.(map[string]any)
		service, ok := rule["service"].(map[string]any)
		if !ok || len(service) != 1 {
			t.Fatalf("Direct ingress[%d] service = %#v", index, rule["service"])
		}
		for name := range service {
			if _, expected := expectedServices[name]; !expected {
				t.Fatalf("Direct ingress[%d] has unsupported service form %q", index, name)
			}
			expectedServices[name] = true
		}
	}
	for service, found := range expectedServices {
		if !found {
			t.Errorf("Direct sample is missing %s service", service)
		}
	}
	finalRule := ingress[len(ingress)-1].(map[string]any)
	if _, hasHostname := finalRule["hostname"]; hasHostname {
		t.Fatalf("Direct final ingress rule has hostname: %#v", finalRule)
	}
	if _, hasPath := finalRule["path"]; hasPath {
		t.Fatalf("Direct final ingress rule has path: %#v", finalRule)
	}
	finalService := finalRule["service"].(map[string]any)
	if _, ok := finalService["httpStatus"]; !ok {
		t.Fatalf("Direct final ingress service = %#v, want httpStatus catch-all", finalService)
	}

	firstRule := ingress[0].(map[string]any)
	origin, ok := firstRule["originRequest"].(map[string]any)
	if !ok {
		t.Fatalf("Direct exhaustive originRequest = %#v", firstRule["originRequest"])
	}
	for _, field := range []string{
		"access", "caPool", "connectTimeout", "disableChunkedEncoding", "http2Origin", "httpHostHeader",
		"keepAliveConnections", "keepAliveTimeout", "matchSNIToHost", "noHappyEyeballs", "noTLSVerify",
		"originServerName", "proxyType", "tcpKeepAlive", "tlsTimeout", "ipRules",
	} {
		if _, present := origin[field]; !present {
			t.Errorf("Direct exhaustive originRequest is missing %s", field)
		}
	}
	if origin["proxyType"] != "SOCKS5" {
		t.Fatalf("Direct originRequest proxyType = %#v", origin["proxyType"])
	}
	access, ok := origin["access"].(map[string]any)
	if !ok || access["teamName"] == "" || access["required"] != true {
		t.Fatalf("Direct originRequest access = %#v", origin["access"])
	}
	audTags, ok := access["audTags"].([]any)
	if !ok || len(audTags) == 0 {
		t.Fatalf("Direct originRequest access audTags = %#v", access["audTags"])
	}
	ipRules, ok := origin["ipRules"].([]any)
	if !ok || len(ipRules) != 2 {
		t.Fatalf("Direct originRequest ipRules = %#v", origin["ipRules"])
	}
	warpRouting, found, err := unstructured.NestedMap(direct.Object, "spec", "configuration", "direct", "warpRouting")
	if err != nil || !found {
		t.Fatalf("Direct warpRouting = %#v, found=%t, err=%v", warpRouting, found, err)
	}
	for _, field := range []string{"enabled", "connectTimeout", "tcpKeepAlive", "maxActiveFlows"} {
		if _, present := warpRouting[field]; !present {
			t.Errorf("Direct warpRouting is missing %s", field)
		}
	}
	directSettings, found, err := unstructured.NestedMap(direct.Object, "spec", "dns", "settings")
	if err != nil || !found || directSettings["ipv4Only"] != true || directSettings["ipv6Only"] != false {
		t.Fatalf("Direct tunnel DNS settings = %#v, found=%t, err=%v", directSettings, found, err)
	}
}

func TestWARPConnectorSampleCoversHAModesTokenSecretAndDeclarativeFailover(t *testing.T) {
	objects := decodeSample(t, "flareway_v1alpha1_warpconnector.yaml")
	if len(objects) != 4 {
		t.Fatalf("WARPConnector sample documents = %d, want 4", len(objects))
	}
	for name, wantMode := range map[string]string{
		"branch-disabled": "Disabled",
		"branch-none":     "None",
		"branch-local":    "Local",
		"branch-aws":      "AWS",
	} {
		object := sampleByName(t, objects, name)
		if object.GetKind() != "WARPConnector" {
			t.Fatalf("%s kind = %q", name, object.GetKind())
		}
		mode, found, err := unstructured.NestedString(object.Object, "spec", "highAvailability", "mode")
		if err != nil || !found || mode != wantMode {
			t.Fatalf("%s highAvailability mode = %q, found=%t, err=%v", name, mode, found, err)
		}
		policy, found, err := unstructured.NestedString(object.Object, "spec", "managementPolicy")
		if err != nil || !found || policy != "Managed" {
			t.Fatalf("%s managementPolicy = %q, found=%t, err=%v; Managed is required for the token Secret", name, policy, found, err)
		}
	}

	local := sampleByName(t, objects, "branch-local")
	vips, found, err := unstructured.NestedSlice(local.Object, "spec", "highAvailability", "local", "vips")
	if err != nil || !found || len(vips) != 2 {
		t.Fatalf("Local WARPConnector VIPs = %#v, found=%t, err=%v", vips, found, err)
	}
	failover, found, err := unstructured.NestedMap(local.Object, "spec", "failover")
	if err != nil || !found || failover["clientId"] == "" || failover["requestId"] == "" {
		t.Fatalf("Local WARPConnector failover = %#v, found=%t, err=%v", failover, found, err)
	}
	aws := sampleByName(t, objects, "branch-aws")
	fnrID, found, err := unstructured.NestedString(aws.Object, "spec", "highAvailability", "aws", "fnrId")
	if err != nil || !found || fnrID == "" {
		t.Fatalf("AWS WARPConnector fnrId = %q, found=%t, err=%v", fnrID, found, err)
	}
}

func TestPrivateRouteSamplesUseTypedTunnelReferencesAndOptionalVirtualNetwork(t *testing.T) {
	networkRoutes := decodeSample(t, "flareway_v1alpha1_networkroute.yaml")
	if len(networkRoutes) != 2 {
		t.Fatalf("NetworkRoute sample documents = %d, want 2", len(networkRoutes))
	}
	cloudflareNetwork := sampleByName(t, networkRoutes, "private-services")
	assertTunnelReference(t, cloudflareNetwork, "CloudflareTunnel", "private-gateway")
	if virtualNetwork, found, err := unstructured.NestedMap(cloudflareNetwork.Object, "spec", "virtualNetworkRef"); err != nil || !found || virtualNetwork["name"] != "private-services" {
		t.Fatalf("CloudflareTunnel NetworkRoute virtualNetworkRef = %#v, found=%t, err=%v", virtualNetwork, found, err)
	}
	warpNetwork := sampleByName(t, networkRoutes, "branch-office")
	assertTunnelReference(t, warpNetwork, "WARPConnector", "branch-local")
	if _, found, err := unstructured.NestedMap(warpNetwork.Object, "spec", "virtualNetworkRef"); err != nil || found {
		t.Fatalf("WARPConnector NetworkRoute must demonstrate default virtual network; found=%t err=%v", found, err)
	}

	hostnameRoutes := decodeSample(t, "flareway_v1alpha1_hostnameroute.yaml")
	if len(hostnameRoutes) != 2 {
		t.Fatalf("HostnameRoute sample documents = %d, want 2", len(hostnameRoutes))
	}
	assertTunnelReference(t, sampleByName(t, hostnameRoutes, "private-admin"), "CloudflareTunnel", "private-gateway")
	assertTunnelReference(t, sampleByName(t, hostnameRoutes, "branch-dns"), "WARPConnector", "branch-local")
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

func sampleByName(t *testing.T, objects []*unstructured.Unstructured, name string) *unstructured.Unstructured {
	t.Helper()
	for _, object := range objects {
		if object.GetName() == name {
			return object
		}
	}
	t.Fatalf("sample has no object named %s", name)
	return nil
}

func assertTunnelReference(t *testing.T, object *unstructured.Unstructured, kind, name string) {
	t.Helper()
	reference, found, err := unstructured.NestedMap(object.Object, "spec", "tunnelRef")
	if err != nil || !found || reference["kind"] != kind || reference["name"] != name {
		t.Fatalf("%s/%s tunnelRef = %#v, found=%t, err=%v", object.GetKind(), object.GetName(), reference, found, err)
	}
}
