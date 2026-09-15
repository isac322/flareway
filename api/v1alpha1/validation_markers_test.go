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

package v1alpha1

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidationArtifactsUseASCIIQuotes(t *testing.T) {
	t.Parallel()

	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	crdFiles, err := filepath.Glob("../../config/crd/bases/*.yaml")
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range goFiles {
		assertNoUnicodeQuotes(t, path, true)
	}
	for _, path := range crdFiles {
		assertNoUnicodeQuotes(t, path, false)
	}
}

func TestAccessApplicationContractMarkers(t *testing.T) {
	t.Parallel()

	assertFileContainsAll(t, "accessapplication_types.go",
		`+kubebuilder:validation:XValidation:rule="self == oldSelf",message="type is immutable"`,
		`(has(self.selfHosted)?1:0)+(has(self.ssh)?1:0)+(has(self.vnc)?1:0)+(has(self.rdp)?1:0)+(has(self.mcp)?1:0)+(has(self.proxyEndpoint)?1:0) == 1`,
		`has(self.accountRef.name) && size(self.accountRef.name) > 0`,
		`!has(self.pathScope) || (has(self.targetRefs) && size(self.targetRefs) > 0)`,
		`!has(self.audienceScope) || self.audienceScope != 'Hostname' || !has(self.mode) || self.mode == 'Required'`,
		`+listMapKey=hostname`,
		`+listMapKey=path`,
		`ObserveOnly requires externalRef for every bypass child`,
		`L4Protocol *AccessL4Protocol`,
		`ProxyEndpoint requires targetRefs only; other types require targetRefs or destinations`,
		`RDP target criteria require RDP protocol`,
		`+kubebuilder:validation:MaxItems=4
	// +listType=atomic
	Multiple []AccessSCIMAuthenticationMethod`,
	)
}

func TestIdentityProviderContractMarkers(t *testing.T) {
	t.Parallel()

	assertFileContainsAll(t, "identityprovider_types.go",
		`SCIM secretRef is immutable once set`,
	)
}

func TestStandaloneApplicationContractMarkers(t *testing.T) {
	t.Parallel()

	assertFileContainsAll(t, "accessstandaloneapplication_types.go",
		`+kubebuilder:validation:XValidation:rule="self == oldSelf",message="type is immutable"`,
		`(has(self.saas)?1:0)+(has(self.bookmark)?1:0)+(has(self.infrastructure)?1:0)+(has(self.appLauncher)?1:0)+(has(self.warp)?1:0)+(has(self.biso)?1:0)+(has(self.dashSso)?1:0)+(has(self.mcpPortal)?1:0) == 1`,
		`has(self.accountRef.name) && size(self.accountRef.name) > 0`,
		`Infrastructure policies must be declared in infrastructure.policies`,
		`infrastructure target criteria require SSH protocol`,
		`+kubebuilder:validation:MaxItems=32
	// +listType=atomic
	Include []AccessRule`,
		`+kubebuilder:validation:MaxItems=32
	// +listType=atomic
	Require []AccessRule`,
		`+kubebuilder:validation:MaxItems=32
	// +listType=atomic
	Exclude         []AccessRule`,
		`+kubebuilder:validation:MaxItems=32
	// +listType=atomic
	TargetCriteria []AccessTargetCriterion`,
		`+kubebuilder:validation:MaxItems=16
	// +listType=atomic
	Policies []AccessInfrastructureApplicationPolicy`,
	)
}

func TestInfrastructureTargetContractMarkers(t *testing.T) {
	t.Parallel()

	assertFileContainsAll(t, "accessinfrastructuretarget_types.go",
		`has(self.accountRef.name) && size(self.accountRef.name) > 0`,
		`has(self.ipv4) || has(self.ipv6)`,
		`virtualNetworkRef and virtualNetworkId are mutually exclusive`,
	)
}

func TestCloudflareAccountReferenceGrantMarkers(t *testing.T) {
	t.Parallel()

	assertFileContainsAll(t, "cloudflareaccount_types.go",
		`AccessCustomPageRefs GrantPermission`,
		`DevicePostureIntegrationRefs GrantPermission`,
		`AccessStandaloneApplicationRefs GrantPermission`,
	)
}

func TestCloudflareTunnelContractMarkers(t *testing.T) {
	t.Parallel()

	assertFileContainsAll(t, "cloudflaretunnel_types.go",
		`+kubebuilder:validation:Enum=Gateway;Direct`,
		`!has(self.mode) || self.mode != 'Direct' || has(self.direct)`,
		`!has(self.configuration.mode) || self.configuration.mode != 'Direct' || (!has(self.connector) && !has(self.proxy) && !has(self.privateDNS) && !has(self.originRequest) && (!has(self.listeners) || size(self.listeners) == 0))`,
		`(has(self.http)?1:0)+(has(self.https)?1:0)+(has(self.tcp)?1:0)+(has(self.ssh)?1:0)+(has(self.rdp)?1:0)+(has(self.smb)?1:0)+(has(self.unix)?1:0)+(has(self.unixTLS)?1:0)+(has(self.helloWorld)?1:0)+(has(self.httpStatus)?1:0)+(has(self.bastion)?1:0) == 1`,
		`the final ingress rule must be a catch-all`,
		`originRequest.access is only valid for HTTP origins`,
		`originRequest.ipRules requires Bastion or SOCKS5 proxy service`,
		`has(self.accountRef.name) && size(self.accountRef.name) > 0`,
		`ipv4Only or ipv6Only requires proxied=true`,
		`TunnelType TunnelRemoteType`,
		`ConfigSource TunnelConfigSource`,
		`+kubebuilder:validation:MaxItems=25
	// +listType=map
	// +listMapKey=id
	Clients []CloudflareTunnelClientStatus`,
		`ManagementToken *CloudflareTunnelManagementTokenRequest`,
		`ConnectorTokenSecretRef  *corev1.LocalObjectReference`,
	)
}

func TestPrivateNetworkContractMarkers(t *testing.T) {
	t.Parallel()

	assertFileContainsAll(t, "private_network_types.go",
		`+kubebuilder:validation:Enum=CloudflareTunnel;WARPConnector`,
		`Kind TunnelReferenceKind`,
		`VirtualNetworkRef *corev1.LocalObjectReference`,
		`virtualNetworkRef and defaultVirtualNetworkFallback are mutually exclusive`,
		`IPLookup *NetworkRouteIPLookupSpec`,
		`IPLookup           *NetworkRouteIPLookupStatus`,
		`has(self.accountRef.name) && size(self.accountRef.name) > 0`,
		`TunnelType         TunnelRemoteType`,
		`CreatedAt          *metav1.Time`,
		`DeletedAt          *metav1.Time`,
	)
	assertFileDoesNotContainAny(t, "private_network_types.go", `type NamespacedObjectReference struct`)
}

func TestWARPConnectorContractMarkers(t *testing.T) {
	t.Parallel()

	assertFileContainsAll(t, "warpconnector_types.go",
		`+kubebuilder:validation:XValidation:rule="self == oldSelf",message="enabled is immutable"`,
		`!has(self.mode) || self.mode != 'AWS' || (has(self.aws) && !has(self.local))`,
		`!has(self.mode) || self.mode != 'Local' || (has(self.local) && !has(self.aws))`,
		`TunnelID             string`,
		`has(self.accountRef.name) && size(self.accountRef.name) > 0`,
		`Failover *WARPConnectorFailoverRequest`,
		`TokenSecretRef *corev1.LocalObjectReference`,
		`+kubebuilder:validation:MaxItems=25
	// +listType=map
	// +listMapKey=id
	Clients []WARPConnectorClientStatus`,
	)
	assertFileDoesNotContainAny(t, "warpconnector_types.go", `Foo *string`, `INSERT ADDITIONAL SPEC FIELDS`)
}

func TestGatewayTunnelDefaultsContractMarkers(t *testing.T) {
	t.Parallel()

	assertFileContainsAll(t, "gatewayclassconfig_types.go",
		`+kubebuilder:validation:Enum=Auto;QUIC;HTTP2`,
		`type GatewayOriginRequestSpec struct`,
		`ConnectTimeout         *metav1.Duration`,
		`DisableChunkedEncoding *bool`,
		`HTTP2Origin            *bool`,
		`ipv4Only or ipv6Only requires proxied=true`,
		`self.conformanceMode || (has(self.accountRef) && has(self.accountRef.name) && size(self.accountRef.name) > 0)`,
	)
}

func assertNoUnicodeQuotes(t *testing.T, path string, validationMarkersOnly bool) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close %s: %v", path, err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := scanner.Text()
		if validationMarkersOnly && !strings.Contains(line, "kubebuilder:validation:XValidation") {
			continue
		}
		if strings.ContainsAny(line, "“”‘’") {
			t.Errorf("%s:%d contains a Unicode quote in validation source: %q", path, lineNumber, line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func assertFileContainsAll(t *testing.T, path string, values ...string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	normalized := strings.Join(strings.Fields(text), " ")
	for _, value := range values {
		if !strings.Contains(text, value) && !strings.Contains(normalized, strings.Join(strings.Fields(value), " ")) {
			t.Errorf("%s does not contain %q", path, value)
		}
	}
}

func assertFileDoesNotContainAny(t *testing.T, path string, values ...string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		if strings.Contains(string(content), value) {
			t.Errorf("%s unexpectedly contains %q", path, value)
		}
	}
}
