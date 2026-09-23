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

package dataplane

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

func TestBuildDeploymentConformanceContract(t *testing.T) {
	gw := testGateway(true)
	cfg := testConfig(true)
	configHash := strings.Repeat("a", 64)

	deployment := BuildDeployment(gw, cfg, BootstrapConfigMapName(gw), configHash)
	if deployment.APIVersion != "apps/v1" || deployment.Kind != "Deployment" {
		t.Fatalf("unexpected type metadata: %s %s", deployment.APIVersion, deployment.Kind)
	}
	if deployment.Name != "flareway-gw-example" || deployment.Namespace != "apps" {
		t.Fatalf("unexpected object key: %s/%s", deployment.Namespace, deployment.Name)
	}
	assertGatewayOwner(t, deployment.OwnerReferences, gw.UID)
	if got := *deployment.Spec.Replicas; got != 1 {
		t.Fatalf("replicas = %d, want 1", got)
	}
	if got := deployment.Spec.Template.Labels[ConfigHashKey]; len(got) > 63 || got == "" {
		t.Fatalf("config hash label = %q, want a non-empty valid label value", got)
	}
	if got := deployment.Spec.Template.Annotations[ConfigHashKey]; got != configHash {
		t.Fatalf("full config hash annotation = %q, want %q", got, configHash)
	}
	if deployment.Spec.Template.Spec.AutomountServiceAccountToken == nil || *deployment.Spec.Template.Spec.AutomountServiceAccountToken {
		t.Fatal("service account token must not be mounted")
	}
	if got := deployment.Spec.Template.Spec.TerminationGracePeriodSeconds; got == nil || *got != 90 {
		t.Fatalf("termination grace = %v, want 90", got)
	}
	assertPodSecurity(t, deployment.Spec.Template.Spec.SecurityContext)

	containers := deployment.Spec.Template.Spec.Containers
	if len(containers) != 1 || containers[0].Name != "envoy" {
		t.Fatalf("conformance containers = %v, want Envoy only", containerNames(containers))
	}
	envoy := containers[0]
	assertContainerSecurity(t, envoy.SecurityContext, 65532)
	for _, arg := range []string{"-c", "/etc/envoy/bootstrap.yaml", "--service-node", "$(POD_NAMESPACE)/$(GATEWAY_NAME)/$(POD_UID)", "--service-cluster", "apps/example", "--concurrency", "1", "--disable-hot-restart", "--drain-time-s", "30"} {
		if !slices.Contains(envoy.Args, arg) {
			t.Errorf("Envoy args do not contain %q: %v", arg, envoy.Args)
		}
	}
	if envoy.ReadinessProbe == nil || envoy.ReadinessProbe.HTTPGet == nil || envoy.ReadinessProbe.HTTPGet.Path != "/healthz" || envoy.ReadinessProbe.HTTPGet.Port.StrVal != "health" {
		t.Fatalf("unexpected Envoy readiness probe: %#v", envoy.ReadinessProbe)
	}
	if !hasContainerPort(envoy, 10080) || !hasContainerPort(envoy, 10443) || !hasContainerPort(envoy, EnvoyHealthPort) {
		t.Fatalf("Envoy ports = %v, want listener target ports and health", envoy.Ports)
	}
	if !hasMount(envoy, bootstrapVolumeName, "/etc/envoy", true) || !hasMount(envoy, xdsVolumeName, "/etc/flareway/xds", true) {
		t.Fatalf("Envoy mounts = %v, want bootstrap and xDS mounts", envoy.VolumeMounts)
	}
	if got := envoy.Resources.Requests.Cpu().String(); got != "10m" {
		t.Fatalf("Envoy CPU request = %q, want measured-baseline 10m", got)
	}
	if got := envoy.Resources.Requests.Memory().String(); got != "32Mi" {
		t.Fatalf("Envoy memory request = %q, want measured-baseline 32Mi", got)
	}
	assertXDSProjection(t, deployment.Spec.Template.Spec.Volumes, BootstrapConfigMapName(gw), XDSClientSecretName(gw))
}

func TestBuildDeploymentCloudflareReadyContract(t *testing.T) {
	gw := testGateway(false)
	gw.Cloudflare = &ir.Cloudflare{TokenSecretName: "flareway-tunnel-explicit"}
	cfg := testConfig(false)

	deployment := BuildDeployment(gw, cfg, BootstrapConfigMapName(gw), "hash")
	if got := containerNames(deployment.Spec.Template.Spec.Containers); !slices.Equal(got, []string{"cloudflared", "envoy"}) {
		t.Fatalf("containers = %v, want cloudflared and Envoy", got)
	}
	cloudflared := deployment.Spec.Template.Spec.Containers[0]
	assertContainerSecurity(t, cloudflared.SecurityContext, 65532)
	if !slices.Equal(cloudflared.Args, []string{"tunnel", "run"}) {
		t.Fatalf("cloudflared args = %v", cloudflared.Args)
	}
	token := envVar(cloudflared, "TUNNEL_TOKEN")
	if token == nil || token.ValueFrom == nil || token.ValueFrom.SecretKeyRef == nil || token.ValueFrom.SecretKeyRef.Name != "flareway-tunnel-explicit" || token.ValueFrom.SecretKeyRef.Key != "token" {
		t.Fatalf("unexpected tunnel token source: %#v", token)
	}
	policy := BuildNetworkPolicy(gw, cfg, "operator-system")
	if policyHasIngressPort(policy.Spec.Ingress, 18080) || policyHasIngressPort(policy.Spec.Ingress, 443) {
		t.Fatalf("Cloudflare-mode NetworkPolicy exposed loopback Envoy listeners: %#v", policy.Spec.Ingress)
	}
	if !policyHasIngressPort(policy.Spec.Ingress, CloudflaredMetricsPort) || !policyHasIngressPort(policy.Spec.Ingress, EnvoyHealthPort) {
		t.Fatalf("Cloudflare-mode probe ports are missing: %#v", policy.Spec.Ingress)
	}
	if cloudflared.ReadinessProbe == nil || cloudflared.ReadinessProbe.HTTPGet.Path != "/ready" {
		t.Fatalf("unexpected cloudflared readiness probe: %#v", cloudflared.ReadinessProbe)
	}
	if cloudflared.LivenessProbe == nil || cloudflared.LivenessProbe.HTTPGet.Path != "/healthcheck" {
		t.Fatalf("unexpected cloudflared liveness probe: %#v", cloudflared.LivenessProbe)
	}
}

func TestBuildCloudflaredTransportProtocolUsesWireValues(t *testing.T) {
	for _, test := range []struct {
		protocol v1alpha1.ConnectorProtocol
		want     string
	}{
		{protocol: v1alpha1.ConnectorProtocolAuto, want: "auto"},
		{protocol: v1alpha1.ConnectorProtocolQUIC, want: "quic"},
		{protocol: v1alpha1.ConnectorProtocolHTTP2, want: "http2"},
	} {
		t.Run(string(test.protocol), func(t *testing.T) {
			gw := testGateway(false)
			gw.Cloudflare = &ir.Cloudflare{TokenSecretName: "flareway-tunnel-explicit"}
			cfg := testConfig(false)
			cfg.Spec.Connector.Protocol = test.protocol
			deployment := BuildDeployment(gw, cfg, BootstrapConfigMapName(gw), "hash")
			transport := envVar(deployment.Spec.Template.Spec.Containers[0], "TUNNEL_TRANSPORT_PROTOCOL")
			if transport == nil || transport.Value != test.want {
				t.Fatalf("cloudflared transport protocol = %#v, want %q", transport, test.want)
			}
		})
	}
}

func TestBuildPrivateDNSDataplaneIsPodLocal(t *testing.T) {
	gw := testGateway(false)
	gw.Cloudflare = &ir.Cloudflare{TokenSecretName: "flareway-tunnel-private"}
	gw.Listeners = []ir.Listener{
		{Name: "exact", Hostname: "admin.internal.example", Port: 443, EnvoyPort: 443, Protocol: "HTTPS", Exposure: ir.ExposurePrivate, Binding: ir.ListenerBindingLoopback},
		{Name: "wildcard", Hostname: "*.apps.internal.example", Port: 443, EnvoyPort: 443, Protocol: "HTTPS", Exposure: ir.ExposurePrivate, Binding: ir.ListenerBindingLoopback},
	}
	cfg := testConfig(false)

	configMap := BuildPrivateDNSConfigMap(gw)
	if configMap == nil {
		t.Fatal("private DNS ConfigMap was not built")
	}
	corefile := configMap.Data["Corefile"]
	for _, want := range []string{
		"bind 127.0.0.1",
		"127.0.0.1 admin.internal.example",
		`match "^[^.]+[.]apps[.]internal[.]example[.]?$"`,
		`answer "{{ .Name }} 30 IN A 127.0.0.1"`,
		"forward . /etc/resolv.conf",
	} {
		if !strings.Contains(corefile, want) {
			t.Errorf("Corefile does not contain %q:\n%s", want, corefile)
		}
	}

	deployment := BuildDeployment(gw, cfg, BootstrapConfigMapName(gw), "hash")
	if got := containerNames(deployment.Spec.Template.Spec.Containers); !slices.Equal(got, []string{"cloudflared", "envoy", "dns"}) {
		t.Fatalf("containers = %v, want cloudflared, Envoy, and DNS", got)
	}
	envoy := deployment.Spec.Template.Spec.Containers[1]
	if envoy.SecurityContext == nil || envoy.SecurityContext.Capabilities == nil ||
		!slices.Contains(envoy.SecurityContext.Capabilities.Add, corev1.Capability("NET_BIND_SERVICE")) {
		t.Fatalf("private Envoy capabilities = %#v", envoy.SecurityContext)
	}
	cloudflared := deployment.Spec.Template.Spec.Containers[0]
	if resolver := envVar(cloudflared, "TUNNEL_DNS_RESOLVER_ADDRS"); resolver == nil || resolver.Value != "127.0.0.1:53" {
		t.Fatalf("cloudflared DNS resolver = %#v", resolver)
	}
	dns := deployment.Spec.Template.Spec.Containers[2]
	if !hasMount(dns, privateDNSVolumeName, "/etc/coredns", true) {
		t.Fatalf("DNS mounts = %v", dns.VolumeMounts)
	}
	if dns.SecurityContext == nil || dns.SecurityContext.Capabilities == nil ||
		!slices.Contains(dns.SecurityContext.Capabilities.Add, corev1.Capability("NET_BIND_SERVICE")) {
		t.Fatalf("DNS capabilities = %#v", dns.SecurityContext)
	}
	policy := BuildNetworkPolicy(gw, cfg, "operator-system")
	if policyHasIngressPort(policy.Spec.Ingress, 443) {
		t.Fatalf("private listener ports escaped pod isolation: %#v", policy.Spec.Ingress)
	}
}

func TestBuildPrivateDNSPodIPFallbackRequiresRecordedBinding(t *testing.T) {
	gw := testGateway(false)
	gw.Listeners = []ir.Listener{{
		Name: "private", Hostname: "admin.internal.example", Port: 443, EnvoyPort: 443,
		Protocol: "HTTPS", Exposure: ir.ExposurePrivate, Binding: ir.ListenerBindingPodIP,
	}}
	configMap := BuildPrivateDNSConfigMap(gw)
	if configMap == nil || !strings.Contains(configMap.Data["Corefile"], "{$POD_IP} admin.internal.example") {
		t.Fatalf("PodIP fallback Corefile = %#v", configMap)
	}
	gw.Listeners[0].Binding = ir.ListenerBindingLoopback
	configMap = BuildPrivateDNSConfigMap(gw)
	if strings.Contains(configMap.Data["Corefile"], "{$POD_IP}") {
		t.Fatal("PodIP fallback activated without the recorded PodIP binding")
	}
}

func TestBuildServiceMapsListenerPorts(t *testing.T) {
	gw := testGateway(true)
	gw.Listeners = append(gw.Listeners, ir.Listener{Name: "http-other", Port: 80, EnvoyPort: 10080, Protocol: "HTTP", Exposure: ir.ExposurePublic})
	cfg := testConfig(true)
	service := BuildService(gw, cfg)

	if service.APIVersion != "v1" || service.Kind != "Service" {
		t.Fatalf("unexpected type metadata: %s %s", service.APIVersion, service.Kind)
	}
	assertGatewayOwner(t, service.OwnerReferences, gw.UID)
	if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
		t.Fatalf("service type = %s, want LoadBalancer", service.Spec.Type)
	}
	if len(service.Spec.Ports) != 2 {
		t.Fatalf("service ports = %v, want 2", service.Spec.Ports)
	}
	if service.Spec.Ports[0].Port != 80 || service.Spec.Ports[0].TargetPort.IntVal != 10080 {
		t.Fatalf("HTTP service port = %#v", service.Spec.Ports[0])
	}
	if service.Spec.Ports[1].Port != 443 || service.Spec.Ports[1].TargetPort.IntVal != 10443 {
		t.Fatalf("HTTPS service port = %#v", service.Spec.Ports[1])
	}

	cfg.Spec.Conformance.ServiceType = corev1.ServiceTypeClusterIP
	if got := BuildService(gw, cfg).Spec.Type; got != corev1.ServiceTypeClusterIP {
		t.Fatalf("configured service type = %s, want ClusterIP", got)
	}
}

func TestBuildServiceSkipsNonPositiveListenerPorts(t *testing.T) {
	gw := testGateway(true)
	gw.Listeners = []ir.Listener{
		{Name: "https", Port: 443, EnvoyPort: 10443, Protocol: "HTTPS", Exposure: ir.ExposurePublic},
		{Name: "stale", Port: 0, EnvoyPort: 10080, Protocol: "HTTP", Exposure: ir.ExposurePublic},
	}

	service := BuildService(gw, testConfig(true))
	if len(service.Spec.Ports) != 1 {
		t.Fatalf("service ports = %v, want only the valid listener port", service.Spec.Ports)
	}
	port := service.Spec.Ports[0]
	if port.Port != 443 || port.TargetPort.IntVal != 10443 {
		t.Fatalf("service port = %#v, want 443 -> 10443", port)
	}
	if service.Spec.Selector == nil {
		t.Fatal("service selector = nil, want pod selector for the valid listener")
	}
}

func TestGatewayInfrastructureMetadataPropagation(t *testing.T) {
	gw := testGateway(true)
	gw.InfrastructureLabels = map[string]string{
		"example.com/team":      "platform",
		GatewayLabelKey:         "user-value",
		ManagedByLabelKey:       "user-value",
		StandardGatewayLabelKey: "user-value",
		ConfigHashKey:           "user-value",
	}
	gw.InfrastructureAnnotations = map[string]string{
		"example.com/note": "from-gateway",
		ManagedByLabelKey:  "user-value",
		ConfigHashKey:      "user-value",
	}
	const configHash = "operator-config-hash"

	deployment := BuildDeployment(gw, testConfig(true), BootstrapConfigMapName(gw), configHash)
	service := BuildService(gw, testConfig(true))

	for target, labels := range map[string]map[string]string{
		"Deployment":   deployment.Labels,
		"Pod template": deployment.Spec.Template.Labels,
		"Service":      service.Labels,
	} {
		if labels["example.com/team"] != "platform" {
			t.Errorf("%s did not receive infrastructure label: %v", target, labels)
		}
		if labels[GatewayLabelKey] != gatewayLabelValue(gw) ||
			labels[ManagedByLabelKey] != "flareway" ||
			labels[StandardGatewayLabelKey] != gw.Key.Name {
			t.Errorf("%s operator identity labels did not win conflicts: %v", target, labels)
		}
	}
	if deployment.Labels[ConfigHashKey] != configHashLabel(configHash) ||
		deployment.Spec.Template.Labels[ConfigHashKey] != configHashLabel(configHash) {
		t.Fatalf("operator config hash label did not win conflict: deployment=%q pod=%q", deployment.Labels[ConfigHashKey], deployment.Spec.Template.Labels[ConfigHashKey])
	}
	if service.Labels[ConfigHashKey] != "user-value" {
		t.Fatalf("Service non-required config hash label = %q, want propagated user value", service.Labels[ConfigHashKey])
	}
	for target, annotations := range map[string]map[string]string{
		"Deployment":   deployment.Annotations,
		"Pod template": deployment.Spec.Template.Annotations,
		"Service":      service.Annotations,
	} {
		if annotations["example.com/note"] != "from-gateway" {
			t.Errorf("%s did not receive infrastructure annotation: %v", target, annotations)
		}
		if annotations[ManagedByLabelKey] != managedByValue(gw) {
			t.Errorf("%s managed-by annotation did not win conflict: %v", target, annotations)
		}
	}
	if deployment.Annotations[ConfigHashKey] != configHash ||
		deployment.Spec.Template.Annotations[ConfigHashKey] != configHash {
		t.Fatalf("operator config hash annotation did not win conflict: deployment=%q pod=%q", deployment.Annotations[ConfigHashKey], deployment.Spec.Template.Annotations[ConfigHashKey])
	}
	if service.Annotations[ConfigHashKey] != "user-value" {
		t.Fatalf("Service non-required config hash annotation = %q, want propagated user value", service.Annotations[ConfigHashKey])
	}
	if _, exists := deployment.Spec.Selector.MatchLabels[StandardGatewayLabelKey]; exists {
		t.Fatal("standard Gateway label must not enter immutable Deployment selector")
	}
	if _, exists := deployment.Spec.Selector.MatchLabels["example.com/team"]; exists {
		t.Fatal("infrastructure labels must not enter immutable Deployment selector")
	}
	if _, exists := service.Spec.Selector[StandardGatewayLabelKey]; exists {
		t.Fatal("standard Gateway label must not enter Service selector")
	}
	if _, exists := service.Spec.Selector["example.com/team"]; exists {
		t.Fatal("infrastructure labels must not enter Service selector")
	}
}

func TestBuildServiceWithNoValidListenersIsFailClosed(t *testing.T) {
	gw := testGateway(true)
	gw.Listeners = nil

	service := BuildService(gw, testConfig(true))
	if service.Spec.Type != corev1.ServiceTypeClusterIP {
		t.Fatalf("service type = %s, want fail-closed ClusterIP", service.Spec.Type)
	}
	if service.Spec.Selector != nil {
		t.Fatalf("service selector = %v, want nil so no endpoints are selected", service.Spec.Selector)
	}
	if len(service.Spec.Ports) != 1 {
		t.Fatalf("service ports = %v, want one structurally valid fail-closed port", service.Spec.Ports)
	}
	port := service.Spec.Ports[0]
	if port.Name != "health" || port.Port != EnvoyHealthPort || port.TargetPort.IntVal != EnvoyHealthPort {
		t.Fatalf("fail-closed service port = %#v", port)
	}
}

func TestBuildServiceWithOnlyNonPositiveListenerPortsIsFailClosed(t *testing.T) {
	gw := testGateway(true)
	gw.Listeners = []ir.Listener{
		{Name: "stale-zero", Port: 0, EnvoyPort: 10080, Protocol: "HTTP", Exposure: ir.ExposurePublic},
		{Name: "stale-negative", Port: -1, EnvoyPort: 10443, Protocol: "HTTPS", Exposure: ir.ExposurePublic},
	}

	service := BuildService(gw, testConfig(true))
	if service.Spec.Selector != nil {
		t.Fatalf("service selector = %v, want nil so no endpoints are selected", service.Spec.Selector)
	}
	if service.Spec.Type != corev1.ServiceTypeClusterIP {
		t.Fatalf("service type = %s, want %s for all-invalid listeners", service.Spec.Type, corev1.ServiceTypeClusterIP)
	}
	if len(service.Spec.Ports) != 1 {
		t.Fatalf("service ports = %v, want one structurally valid fail-closed port", service.Spec.Ports)
	}
	port := service.Spec.Ports[0]
	if port.Name != "health" || port.Port != EnvoyHealthPort || port.TargetPort.IntVal != EnvoyHealthPort {
		t.Fatalf("fail-closed service port = %#v", port)
	}
}

func TestBuildBootstrapConfigMapContainsDeltaMTLSAndHealth(t *testing.T) {
	gw := testGateway(true)
	configMap, err := BuildBootstrapConfigMap(gw, testConfig(true))
	if err != nil {
		t.Fatalf("BuildBootstrapConfigMap() error = %v", err)
	}
	if configMap.APIVersion != "v1" || configMap.Kind != "ConfigMap" {
		t.Fatalf("unexpected type metadata: %s %s", configMap.APIVersion, configMap.Kind)
	}
	assertGatewayOwner(t, configMap.OwnerReferences, gw.UID)

	bootstrapYAML := configMap.Data["bootstrap.yaml"]
	for _, want := range []string{
		`cluster: "apps/example"`,
		"address: 127.0.0.1\n      port_value: 19000",
		"address: 0.0.0.0\n        port_value: 19001",
		"exact: \"/healthz\"",
		"api_type: DELTA_GRPC",
		"flareway-xds.flareway-system.svc.cluster.local",
		"path: /etc/flareway/xds/client-secret.yaml",
		"path: /etc/flareway/xds/ca-secret.yaml",
	} {
		if !strings.Contains(bootstrapYAML, want) {
			t.Errorf("bootstrap does not contain %q", want)
		}
	}
	for key, want := range map[string][]string{
		"client-secret.yaml": {"name: xds-client", "/etc/flareway/xds/tls.crt", "/etc/flareway/xds/tls.key", "watched_directory"},
		"ca-secret.yaml":     {"name: xds-ca", "/etc/flareway/xds/ca.crt", "watched_directory"},
	} {
		for _, fragment := range want {
			if !strings.Contains(configMap.Data[key], fragment) {
				t.Errorf("%s does not contain %q", key, fragment)
			}
		}
	}
}

func TestBuildPDBAndNetworkPolicyContract(t *testing.T) {
	gw := testGateway(true)
	cfg := testConfig(true)

	pdb := BuildPDB(gw, cfg)
	if pdb.APIVersion != "policy/v1" || pdb.Kind != "PodDisruptionBudget" {
		t.Fatalf("unexpected PDB type metadata: %s %s", pdb.APIVersion, pdb.Kind)
	}
	if pdb.Spec.MinAvailable == nil || pdb.Spec.MinAvailable.IntVal != 1 {
		t.Fatalf("PDB minAvailable = %#v, want 1", pdb.Spec.MinAvailable)
	}
	assertGatewayOwner(t, pdb.OwnerReferences, gw.UID)

	policy := BuildNetworkPolicy(gw, cfg, "operator-system")
	if policy.APIVersion != "networking.k8s.io/v1" || policy.Kind != "NetworkPolicy" {
		t.Fatalf("unexpected NetworkPolicy type metadata: %s %s", policy.APIVersion, policy.Kind)
	}
	assertGatewayOwner(t, policy.OwnerReferences, gw.UID)

	if len(policy.Spec.PolicyTypes) != 2 || string(policy.Spec.PolicyTypes[0]) != "Ingress" || string(policy.Spec.PolicyTypes[1]) != "Egress" {
		t.Fatalf("policy types = %v", policy.Spec.PolicyTypes)
	}
	if !policyHasIngressPort(policy.Spec.Ingress, 10080) || !policyHasIngressPort(policy.Spec.Ingress, 10443) || !policyHasIngressPort(policy.Spec.Ingress, EnvoyHealthPort) {
		t.Fatalf("ingress rules do not expose listener and health ports: %#v", policy.Spec.Ingress)
	}
	for _, port := range []int32{53, XDSPort, 8080} {
		if !policyHasEgressPort(policy.Spec.Egress, port) {
			t.Errorf("egress rules do not allow port %d", port)
		}
	}
	if policyHasEgressPort(policy.Spec.Egress, 80) {
		t.Error("egress allows Service port 80 instead of EndpointSlice target port 8080")
	}
}

func TestBuildDeploymentDefaultSchedulingContract(t *testing.T) {
	for _, test := range []struct {
		name string
		gw   *ir.Gateway
		cfg  *v1alpha1.GatewayClassConfig
	}{
		{name: "nil config", gw: testGateway(false), cfg: nil},
		{name: "config without scheduling", gw: testGateway(false), cfg: testConfig(false)},
		{name: "conformance mode", gw: testGateway(true), cfg: testConfig(true)},
	} {
		t.Run(test.name, func(t *testing.T) {
			deployment := BuildDeployment(test.gw, test.cfg, BootstrapConfigMapName(test.gw), "hash")
			podSpec := deployment.Spec.Template.Spec
			assertDefaultAntiAffinity(t, test.gw, podSpec.Affinity)
			if podSpec.NodeSelector != nil || podSpec.Tolerations != nil || podSpec.TopologySpreadConstraints != nil {
				t.Fatalf("unexpected placement fields: nodeSelector=%v tolerations=%v topologySpread=%v", podSpec.NodeSelector, podSpec.Tolerations, podSpec.TopologySpreadConstraints)
			}
		})
	}
}

func TestBuildDeploymentAppliesConfiguredScheduling(t *testing.T) {
	gw := testGateway(false)
	cfg := testConfig(false)
	toleration := corev1.Toleration{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "dataplane", Effect: corev1.TaintEffectNoSchedule}
	spread := corev1.TopologySpreadConstraint{
		MaxSkew:           1,
		TopologyKey:       "topology.kubernetes.io/zone",
		WhenUnsatisfiable: corev1.ScheduleAnyway,
		LabelSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "flareway-gateway"}},
	}
	nodeAffinity := &corev1.NodeAffinity{
		RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{{
				MatchExpressions: []corev1.NodeSelectorRequirement{{
					Key:      "node.kubernetes.io/instance-type",
					Operator: corev1.NodeSelectorOpIn,
					Values:   []string{"dataplane"},
				}},
			}},
		},
	}
	cfg.Spec.Scheduling = v1alpha1.DataplaneSchedulingSpec{
		NodeSelector:              map[string]string{"kubernetes.io/os": "linux"},
		Tolerations:               []corev1.Toleration{toleration},
		Affinity:                  &corev1.Affinity{NodeAffinity: nodeAffinity},
		TopologySpreadConstraints: []corev1.TopologySpreadConstraint{spread},
	}

	podSpec := BuildDeployment(gw, cfg, BootstrapConfigMapName(gw), "hash").Spec.Template.Spec
	if !reflect.DeepEqual(podSpec.NodeSelector, cfg.Spec.Scheduling.NodeSelector) {
		t.Fatalf("nodeSelector = %v, want %v", podSpec.NodeSelector, cfg.Spec.Scheduling.NodeSelector)
	}
	if !reflect.DeepEqual(podSpec.Tolerations, cfg.Spec.Scheduling.Tolerations) {
		t.Fatalf("tolerations = %v, want %v", podSpec.Tolerations, cfg.Spec.Scheduling.Tolerations)
	}
	if !reflect.DeepEqual(podSpec.TopologySpreadConstraints, cfg.Spec.Scheduling.TopologySpreadConstraints) {
		t.Fatalf("topologySpreadConstraints = %v, want %v", podSpec.TopologySpreadConstraints, cfg.Spec.Scheduling.TopologySpreadConstraints)
	}
	if podSpec.Affinity == nil || !reflect.DeepEqual(podSpec.Affinity.NodeAffinity, nodeAffinity) {
		t.Fatalf("nodeAffinity = %#v, want configured term", podSpec.Affinity)
	}
	assertDefaultAntiAffinity(t, gw, podSpec.Affinity)
}

func TestBuildDeploymentUserPodAntiAffinityReplacesDefault(t *testing.T) {
	gw := testGateway(false)
	cfg := testConfig(false)
	cfg.Spec.Scheduling.Affinity = &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{{
				TopologyKey:   "topology.kubernetes.io/zone",
				LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "edge"}},
			}},
		},
	}

	affinity := BuildDeployment(gw, cfg, BootstrapConfigMapName(gw), "hash").Spec.Template.Spec.Affinity
	if affinity == nil || affinity.PodAntiAffinity == nil {
		t.Fatalf("podAntiAffinity missing: %#v", affinity)
	}
	antiAffinity := affinity.PodAntiAffinity
	if len(antiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) != 1 || antiAffinity.RequiredDuringSchedulingIgnoredDuringExecution[0].TopologyKey != "topology.kubernetes.io/zone" {
		t.Fatalf("required terms = %#v, want the configured zone term", antiAffinity.RequiredDuringSchedulingIgnoredDuringExecution)
	}
	if len(antiAffinity.PreferredDuringSchedulingIgnoredDuringExecution) != 0 {
		t.Fatalf("preferred terms = %#v, want none (user anti-affinity replaces the default)", antiAffinity.PreferredDuringSchedulingIgnoredDuringExecution)
	}
}

func TestBuildDeploymentPodAntiAffinityOptOut(t *testing.T) {
	nodeAffinity := &corev1.NodeAffinity{
		RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{{
				MatchExpressions: []corev1.NodeSelectorRequirement{{
					Key:      "node.kubernetes.io/instance-type",
					Operator: corev1.NodeSelectorOpIn,
					Values:   []string{"dataplane"},
				}},
			}},
		},
	}
	for _, test := range []struct {
		name         string
		affinity     *corev1.Affinity
		wantAffinity bool
		wantTerm     bool
	}{
		{name: "empty podAntiAffinity opts out", affinity: &corev1.Affinity{PodAntiAffinity: &corev1.PodAntiAffinity{}}, wantAffinity: false},
		{name: "empty preferred list opts out", affinity: &corev1.Affinity{PodAntiAffinity: &corev1.PodAntiAffinity{PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{}}}, wantAffinity: false},
		{name: "opt out keeps other affinity", affinity: &corev1.Affinity{NodeAffinity: nodeAffinity, PodAntiAffinity: &corev1.PodAntiAffinity{}}, wantAffinity: true},
		{name: "empty affinity still gets default", affinity: &corev1.Affinity{}, wantAffinity: true, wantTerm: true},
		{name: "empty nodeAffinity normalized", affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{}}, wantAffinity: true, wantTerm: true},
		{name: "empty podAffinity normalized", affinity: &corev1.Affinity{PodAffinity: &corev1.PodAffinity{}}, wantAffinity: true, wantTerm: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			gw := testGateway(false)
			cfg := testConfig(false)
			cfg.Spec.Scheduling.Affinity = test.affinity

			affinity := BuildDeployment(gw, cfg, BootstrapConfigMapName(gw), "hash").Spec.Template.Spec.Affinity
			if !test.wantAffinity {
				if affinity != nil {
					t.Fatalf("affinity = %#v, want nil so SSA removes applied anti-affinity", affinity)
				}
				return
			}
			if affinity == nil {
				t.Fatal("affinity missing")
			}
			if test.wantTerm {
				assertDefaultAntiAffinity(t, gw, affinity)
				if affinity.NodeAffinity != nil || affinity.PodAffinity != nil {
					t.Fatalf("empty affinity fields must be normalized to nil: %#v", affinity)
				}
				return
			}
			if affinity.PodAntiAffinity != nil {
				t.Fatalf("podAntiAffinity = %#v, want nil (opt-out)", affinity.PodAntiAffinity)
			}
			if !reflect.DeepEqual(affinity.NodeAffinity, nodeAffinity) {
				t.Fatalf("nodeAffinity = %#v, want configured term", affinity.NodeAffinity)
			}
		})
	}
}

func TestBuildDeploymentSharedConfigIsNotMutated(t *testing.T) {
	gw1 := testGateway(false)
	gw2 := testGateway(false)
	gw2.Key.Name = "other"
	cfg := testConfig(false)
	cfg.Spec.Scheduling = v1alpha1.DataplaneSchedulingSpec{
		NodeSelector: map[string]string{"kubernetes.io/os": "linux"},
		Affinity: &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchExpressions: []corev1.NodeSelectorRequirement{{
							Key:      "node.kubernetes.io/instance-type",
							Operator: corev1.NodeSelectorOpIn,
							Values:   []string{"dataplane"},
						}},
					}},
				},
			},
		},
	}
	snapshot := cfg.DeepCopy()

	first := BuildDeployment(gw1, cfg, BootstrapConfigMapName(gw1), "hash")
	second := BuildDeployment(gw2, cfg, BootstrapConfigMapName(gw2), "hash")

	if !reflect.DeepEqual(cfg, snapshot) {
		t.Fatalf("shared GatewayClassConfig mutated: %#v", cfg.Spec.Scheduling)
	}
	firstAffinity := first.Spec.Template.Spec.Affinity
	secondAffinity := second.Spec.Template.Spec.Affinity
	if firstAffinity == nil || firstAffinity.PodAntiAffinity == nil || secondAffinity == nil || secondAffinity.PodAntiAffinity == nil {
		t.Fatalf("default pod anti-affinity missing: first=%#v second=%#v", firstAffinity, secondAffinity)
	}
	firstSelector := firstAffinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0].PodAffinityTerm.LabelSelector.MatchLabels
	secondSelector := secondAffinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0].PodAffinityTerm.LabelSelector.MatchLabels
	if firstSelector[GatewayLabelKey] != gatewayLabelValue(gw1) || secondSelector[GatewayLabelKey] != gatewayLabelValue(gw2) {
		t.Fatalf("anti-affinity selectors not scoped per Gateway: %v vs %v", firstSelector, secondSelector)
	}
}

// assertDefaultAntiAffinity verifies the injected soft hostname-spread term:
// weight 100, the stable selector labels (never the config-hash label), and
// matchLabelKeys scoping the term to the pod's own revision.
func assertDefaultAntiAffinity(t *testing.T, gw *ir.Gateway, affinity *corev1.Affinity) {
	t.Helper()
	if affinity == nil || affinity.PodAntiAffinity == nil {
		t.Fatalf("default pod anti-affinity missing: %#v", affinity)
	}
	terms := affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution
	if len(terms) != 1 || terms[0].Weight != 100 {
		t.Fatalf("preferred anti-affinity terms = %#v, want a single weight-100 term", terms)
	}
	term := terms[0].PodAffinityTerm
	if term.TopologyKey != corev1.LabelHostname {
		t.Fatalf("topologyKey = %q, want %q", term.TopologyKey, corev1.LabelHostname)
	}
	if term.LabelSelector == nil {
		t.Fatal("anti-affinity term has no label selector")
	}
	if !reflect.DeepEqual(term.LabelSelector.MatchLabels, selectorLabels(gw)) {
		t.Fatalf("anti-affinity matchLabels = %v, want stable selector labels %v", term.LabelSelector.MatchLabels, selectorLabels(gw))
	}
	if _, exists := term.LabelSelector.MatchLabels[ConfigHashKey]; exists {
		t.Fatal("anti-affinity selector must not include the config-hash label")
	}
	if !slices.Equal(term.MatchLabelKeys, []string{appsv1.DefaultDeploymentUniqueLabelKey}) {
		t.Fatalf("matchLabelKeys = %v, want [%s]", term.MatchLabelKeys, appsv1.DefaultDeploymentUniqueLabelKey)
	}
}

func testGateway(conformance bool) *ir.Gateway {
	return &ir.Gateway{
		Key:             types.NamespacedName{Namespace: "apps", Name: "example"},
		UID:             types.UID("gateway-uid"),
		ConformanceMode: conformance,
		Listeners: []ir.Listener{
			{Name: "http", Port: 80, EnvoyPort: 10080, Protocol: "HTTP", Exposure: ir.ExposurePublic},
			{Name: "https", Port: 443, EnvoyPort: 10443, Protocol: "HTTPS", Exposure: ir.ExposurePublic},
		},
		Clusters: []ir.Cluster{{
			Name:      "backend",
			Namespace: "apps",
			Service:   "backend",
			Port:      80,
			Endpoints: []ir.Endpoint{{Address: "10.0.0.8", Port: 8080}},
		}},
	}
}

func testConfig(conformance bool) *v1alpha1.GatewayClassConfig {
	return &v1alpha1.GatewayClassConfig{
		Spec: v1alpha1.GatewayClassConfigSpec{
			ConformanceMode: conformance,
			Conformance:     v1alpha1.ConformanceSpec{ServiceType: corev1.ServiceTypeLoadBalancer},
			Connector: v1alpha1.ConnectorSpec{
				Replicas: ptr.To[int32](1),
				Protocol: v1alpha1.ConnectorProtocolAuto,
			},
			Proxy: v1alpha1.ProxySpec{Concurrency: ptr.To[int32](1)},
		},
	}
}

func assertGatewayOwner(t *testing.T, refs []metav1.OwnerReference, uid types.UID) {
	t.Helper()
	if len(refs) != 1 {
		t.Fatalf("owner references = %v, want one", refs)
	}
	ref := refs[0]
	if ref.APIVersion != "gateway.networking.k8s.io/v1" || ref.Kind != "Gateway" || ref.Name != "example" || ref.UID != uid || ref.Controller == nil || !*ref.Controller || ref.BlockOwnerDeletion == nil || !*ref.BlockOwnerDeletion {
		t.Fatalf("unexpected Gateway owner reference: %#v", ref)
	}
}

func assertPodSecurity(t *testing.T, security *corev1.PodSecurityContext) {
	t.Helper()
	if security == nil || security.RunAsNonRoot == nil || !*security.RunAsNonRoot || security.RunAsUser != nil || security.RunAsGroup != nil || security.FSGroup == nil || *security.FSGroup != 65532 || security.SeccompProfile == nil || security.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("unexpected Pod security context: %#v", security)
	}
}

func assertContainerSecurity(t *testing.T, security *corev1.SecurityContext, uid int64) {
	t.Helper()
	if security == nil || security.AllowPrivilegeEscalation == nil || *security.AllowPrivilegeEscalation || security.ReadOnlyRootFilesystem == nil || !*security.ReadOnlyRootFilesystem || security.RunAsNonRoot == nil || !*security.RunAsNonRoot || security.RunAsUser == nil || *security.RunAsUser != uid || security.RunAsGroup == nil || *security.RunAsGroup != uid || security.SeccompProfile == nil || security.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault || security.Capabilities == nil || !slices.Equal(security.Capabilities.Drop, []corev1.Capability{"ALL"}) {
		t.Fatalf("unexpected container security context: %#v", security)
	}
}

func assertXDSProjection(t *testing.T, volumes []corev1.Volume, configMapName, secretName string) {
	t.Helper()
	for _, volume := range volumes {
		if volume.Name != xdsVolumeName {
			continue
		}
		if volume.Projected == nil || len(volume.Projected.Sources) != 2 {
			t.Fatalf("unexpected xDS projected volume: %#v", volume)
		}
		secret := volume.Projected.Sources[0].Secret
		configMap := volume.Projected.Sources[1].ConfigMap
		if secret == nil || secret.Name != secretName || len(secret.Items) != 3 {
			t.Fatalf("unexpected xDS Secret projection: %#v", secret)
		}
		if configMap == nil || configMap.Name != configMapName || len(configMap.Items) != 2 {
			t.Fatalf("unexpected xDS ConfigMap projection: %#v", configMap)
		}
		return
	}
	t.Fatal("xDS projected volume not found")
}

func containerNames(containers []corev1.Container) []string {
	names := make([]string, 0, len(containers))
	for _, container := range containers {
		names = append(names, container.Name)
	}
	return names
}

func hasContainerPort(container corev1.Container, port int32) bool {
	return slices.ContainsFunc(container.Ports, func(candidate corev1.ContainerPort) bool { return candidate.ContainerPort == port })
}

func hasMount(container corev1.Container, name, path string, readOnly bool) bool {
	return slices.ContainsFunc(container.VolumeMounts, func(mount corev1.VolumeMount) bool {
		return mount.Name == name && mount.MountPath == path && mount.ReadOnly == readOnly
	})
}

func envVar(container corev1.Container, name string) *corev1.EnvVar {
	for i := range container.Env {
		if container.Env[i].Name == name {
			return &container.Env[i]
		}
	}
	return nil
}

func policyHasIngressPort(rules []networkingv1.NetworkPolicyIngressRule, port int32) bool {
	return slices.ContainsFunc(rules, func(rule networkingv1.NetworkPolicyIngressRule) bool {
		return networkPolicyPortsContain(rule.Ports, port)
	})
}

func policyHasEgressPort(rules []networkingv1.NetworkPolicyEgressRule, port int32) bool {
	return slices.ContainsFunc(rules, func(rule networkingv1.NetworkPolicyEgressRule) bool {
		return networkPolicyPortsContain(rule.Ports, port)
	})
}

func networkPolicyPortsContain(ports []networkingv1.NetworkPolicyPort, port int32) bool {
	return slices.ContainsFunc(ports, func(candidate networkingv1.NetworkPolicyPort) bool {
		return candidate.Port != nil && candidate.Port.Type == intstr.Int && candidate.Port.IntVal == port
	})
}
