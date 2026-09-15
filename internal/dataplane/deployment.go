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
	"strconv"
	"time"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/ir"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	bootstrapVolumeName  = "envoy-bootstrap"
	xdsVolumeName        = "xds-client"
	tmpVolumeName        = "envoy-tmp"
	privateDNSVolumeName = "private-dns"
)

// BuildDeployment returns the desired dataplane Deployment. Conformance mode
// runs Envoy directly; Cloudflare mode also runs the cloudflared connector.
func BuildDeployment(gw *ir.Gateway, cfg *v1alpha1.GatewayClassConfig, bootstrapName, configHash string) *appsv1.Deployment {
	if bootstrapName == "" {
		bootstrapName = BootstrapConfigMapName(gw)
	}
	requiredLabels := resourceLabels(gw)
	labels := mergeMetadata(gw.InfrastructureLabels, requiredLabels)
	requiredAnnotations := map[string]string{ManagedByLabelKey: managedByValue(gw)}
	annotations := mergeMetadata(gw.InfrastructureAnnotations, requiredAnnotations)
	podLabels := mergeMetadata(gw.InfrastructureLabels, requiredLabels)
	podAnnotations := mergeMetadata(gw.InfrastructureAnnotations, requiredAnnotations)
	if configHash != "" {
		hashLabel := configHashLabel(configHash)
		labels[ConfigHashKey] = hashLabel
		podLabels[ConfigHashKey] = hashLabel
		annotations[ConfigHashKey] = configHash
		podAnnotations[ConfigHashKey] = configHash
	}

	replicas := connectorReplicas(cfg)
	containers := []corev1.Container{buildEnvoyContainer(gw, cfg)}
	if !conformanceMode(gw, cfg) {
		containers = append([]corev1.Container{buildCloudflaredContainer(gw, cfg)}, containers...)
	}
	privateDNS := hasPrivateListeners(gw)
	if privateDNS {
		containers = append(containers, buildPrivateDNSContainer(gw, cfg))
	}
	volumes := []corev1.Volume{
		{
			Name: bootstrapVolumeName,
			VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: bootstrapName},
				Items:                []corev1.KeyToPath{{Key: "bootstrap.yaml", Path: "bootstrap.yaml"}},
			}},
		},
		{
			Name: xdsVolumeName,
			VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
				DefaultMode: ptr.To[int32](0440),
				Sources: []corev1.VolumeProjection{
					{Secret: &corev1.SecretProjection{
						LocalObjectReference: corev1.LocalObjectReference{Name: XDSClientSecretName(gw)},
						Items: []corev1.KeyToPath{
							{Key: corev1.TLSCertKey, Path: "tls.crt"},
							{Key: corev1.TLSPrivateKeyKey, Path: "tls.key"},
							{Key: "ca.crt", Path: "ca.crt"},
						},
					}},
					{ConfigMap: &corev1.ConfigMapProjection{
						LocalObjectReference: corev1.LocalObjectReference{Name: bootstrapName},
						Items: []corev1.KeyToPath{
							{Key: "client-secret.yaml", Path: "client-secret.yaml"},
							{Key: "ca-secret.yaml", Path: "ca-secret.yaml"},
						},
					}},
				},
			}},
		},
		{Name: tmpVolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}},
	}
	if privateDNS {
		volumes = append(volumes, corev1.Volume{
			Name: privateDNSVolumeName,
			VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: PrivateDNSConfigMapName(gw)},
				Items:                []corev1.KeyToPath{{Key: "Corefile", Path: "Corefile"}},
			}},
		})
	}

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            ResourceName(gw),
			Namespace:       gw.Key.Namespace,
			Labels:          labels,
			Annotations:     annotations,
			OwnerReferences: gatewayOwnerReferences(gw),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(replicas),
			Selector: &metav1.LabelSelector{MatchLabels: selectorLabels(gw)},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: ptr.To(intstr.FromInt32(0)),
					MaxSurge:       ptr.To(intstr.FromInt32(1)),
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels, Annotations: podAnnotations},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: ptr.To(false),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:        ptr.To(true),
						FSGroup:             ptr.To(EnvoyRuntimeUID),
						FSGroupChangePolicy: ptr.To(corev1.FSGroupChangeOnRootMismatch),
						SeccompProfile:      &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					TerminationGracePeriodSeconds: ptr.To[int64](90),
					Containers:                    containers,
					Volumes:                       volumes,
				},
			},
		},
	}
}

func buildEnvoyContainer(gw *ir.Gateway, cfg *v1alpha1.GatewayClassConfig) corev1.Container {
	concurrency := int32(1)
	image := v1alpha1.DefaultProxyImage
	resources := defaultEnvoyResources()
	if cfg != nil {
		if cfg.Spec.Proxy.Concurrency != nil {
			concurrency = *cfg.Spec.Proxy.Concurrency
		}
		if cfg.Spec.Proxy.Image != "" {
			image = cfg.Spec.Proxy.Image
		}
		if len(cfg.Spec.Proxy.Resources.Requests) > 0 || len(cfg.Spec.Proxy.Resources.Limits) > 0 {
			resources = cfg.Spec.Proxy.Resources
		}
	}

	ports := []corev1.ContainerPort{{Name: "health", ContainerPort: EnvoyHealthPort, Protocol: corev1.ProtocolTCP}}
	if conformanceMode(gw, cfg) {
		for i, port := range listenerEnvoyPorts(gw) {
			ports = append(ports, corev1.ContainerPort{
				Name:          listenerPortName(i),
				ContainerPort: port,
				Protocol:      corev1.ProtocolTCP,
			})
		}
	}

	return corev1.Container{
		Name:            "envoy",
		Image:           image,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Args: []string{
			"-c", "/etc/envoy/bootstrap.yaml",
			"--service-node", "$(POD_NAMESPACE)/$(GATEWAY_NAME)/$(POD_UID)",
			"--service-cluster", gw.Key.String(),
			"--concurrency", strconv.FormatInt(int64(concurrency), 10),
			"--disable-hot-restart",
			"--drain-time-s", "30",
		},
		Env: []corev1.EnvVar{
			{Name: "POD_NAMESPACE", ValueFrom: downwardAPIField("metadata.namespace")},
			{Name: "POD_UID", ValueFrom: downwardAPIField("metadata.uid")},
			{Name: "GATEWAY_NAME", Value: gw.Key.Name},
		},
		Ports:           ports,
		ReadinessProbe:  httpProbe("/healthz", "health", 1, 2, 3),
		LivenessProbe:   httpProbe("/healthz", "health", 10, 10, 3),
		Resources:       resources,
		SecurityContext: envoySecurityContext(gw),
		VolumeMounts: []corev1.VolumeMount{
			{Name: bootstrapVolumeName, MountPath: "/etc/envoy", ReadOnly: true},
			{Name: xdsVolumeName, MountPath: "/etc/flareway/xds", ReadOnly: true},
			{Name: tmpVolumeName, MountPath: "/tmp"},
		},
	}
}

func buildCloudflaredContainer(gw *ir.Gateway, cfg *v1alpha1.GatewayClassConfig) corev1.Container {
	image := v1alpha1.DefaultConnectorImage
	protocol := v1alpha1.ConnectorProtocolAuto
	gracePeriod := time.Minute
	resources := corev1.ResourceRequirements{}
	if cfg != nil {
		if cfg.Spec.Connector.Image != "" {
			image = cfg.Spec.Connector.Image
		}
		if cfg.Spec.Connector.Protocol != "" {
			protocol = cfg.Spec.Connector.Protocol
		}
		if cfg.Spec.Connector.GracePeriod.Duration > 0 {
			gracePeriod = cfg.Spec.Connector.GracePeriod.Duration
		}
		resources = cfg.Spec.Connector.Resources
	}
	env := []corev1.EnvVar{
		{Name: "TUNNEL_TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: TunnelTokenSecretName(gw)}, Key: "token"}}},
		{Name: "TUNNEL_METRICS", Value: "0.0.0.0:2000"},
		{Name: "TUNNEL_TRANSPORT_PROTOCOL", Value: string(protocol)},
		{Name: "TUNNEL_GRACE_PERIOD", Value: gracePeriod.String()},
		{Name: "TUNNEL_LOGLEVEL", Value: "info"},
		{Name: "TUNNEL_EDGE_IP_VERSION", Value: "auto"},
	}
	if hasPrivateListeners(gw) {
		env = append(env, corev1.EnvVar{Name: "TUNNEL_DNS_RESOLVER_ADDRS", Value: "127.0.0.1:53"})
	}

	return corev1.Container{
		Name:            "cloudflared",
		Image:           image,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Args:            []string{"tunnel", "run"},
		Env:             env,
		Ports:           []corev1.ContainerPort{{Name: "metrics", ContainerPort: CloudflaredMetricsPort, Protocol: corev1.ProtocolTCP}},
		ReadinessProbe:  httpProbe("/ready", "metrics", 1, 5, 3),
		LivenessProbe:   httpProbe("/healthcheck", "metrics", 10, 10, 3),
		Resources:       resources,
		SecurityContext: hardenedContainerSecurityContext(CloudflaredRuntimeUID),
		VolumeMounts:    []corev1.VolumeMount{{Name: tmpVolumeName, MountPath: "/tmp"}},
	}
}

func buildPrivateDNSContainer(_ *ir.Gateway, cfg *v1alpha1.GatewayClassConfig) corev1.Container {
	image := v1alpha1.DefaultPrivateDNSImage
	resources := corev1.ResourceRequirements{}
	if cfg != nil {
		if cfg.Spec.PrivateDNS.Image != "" {
			image = cfg.Spec.PrivateDNS.Image
		}
		resources = cfg.Spec.PrivateDNS.Resources
	}
	securityContext := hardenedContainerSecurityContext(PrivateDNSRuntimeUID)
	securityContext.Capabilities.Add = []corev1.Capability{"NET_BIND_SERVICE"}
	return corev1.Container{
		Name:            "dns",
		Image:           image,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Args:            []string{"-conf", "/etc/coredns/Corefile"},
		Env: []corev1.EnvVar{{
			Name:      "POD_IP",
			ValueFrom: downwardAPIField("status.podIP"),
		}},
		Resources:       resources,
		SecurityContext: securityContext,
		VolumeMounts: []corev1.VolumeMount{{
			Name: privateDNSVolumeName, MountPath: "/etc/coredns", ReadOnly: true,
		}},
	}
}

func hasPrivateListeners(gw *ir.Gateway) bool {
	for _, listener := range gw.Listeners {
		if listener.Exposure == ir.ExposurePrivate {
			return true
		}
	}
	return false
}

func envoySecurityContext(gw *ir.Gateway) *corev1.SecurityContext {
	securityContext := hardenedContainerSecurityContext(EnvoyRuntimeUID)
	for _, listener := range gw.Listeners {
		if listener.Exposure == ir.ExposurePrivate && listener.Port > 0 && listener.Port < 1024 {
			securityContext.Capabilities.Add = []corev1.Capability{"NET_BIND_SERVICE"}
			break
		}
	}
	return securityContext
}

func hardenedContainerSecurityContext(uid int64) *corev1.SecurityContext {
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr.To(false),
		ReadOnlyRootFilesystem:   ptr.To(true),
		RunAsNonRoot:             ptr.To(true),
		RunAsUser:                ptr.To(uid),
		RunAsGroup:               ptr.To(uid),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

func defaultEnvoyResources() corev1.ResourceRequirements {
	// The M0 idle measurement was 0.170% CPU and 17.340 MiB RSS. Requests
	// retain headroom without carrying the former unmeasured 100m/128Mi values.
	return corev1.ResourceRequirements{Requests: corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse("10m"),
		corev1.ResourceMemory: resource.MustParse("32Mi"),
	}}
}

func httpProbe(path, port string, initialDelay, period, failureThreshold int32) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
			Path: path,
			Port: intstr.FromString(port),
		}},
		InitialDelaySeconds: initialDelay,
		PeriodSeconds:       period,
		TimeoutSeconds:      1,
		FailureThreshold:    failureThreshold,
	}
}

func downwardAPIField(fieldPath string) *corev1.EnvVarSource {
	return &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: fieldPath}}
}

func connectorReplicas(cfg *v1alpha1.GatewayClassConfig) int32 {
	if cfg != nil && cfg.Spec.Connector.Replicas != nil {
		return *cfg.Spec.Connector.Replicas
	}
	return 2
}

func conformanceMode(gw *ir.Gateway, cfg *v1alpha1.GatewayClassConfig) bool {
	return gw.ConformanceMode || (cfg != nil && cfg.Spec.ConformanceMode)
}

func gatewayOwnerReferences(gw *ir.Gateway) []metav1.OwnerReference {
	if gw.UID == "" {
		return nil
	}
	return []metav1.OwnerReference{{
		APIVersion:         gatewayv1.GroupVersion.String(),
		Kind:               "Gateway",
		Name:               gw.Key.Name,
		UID:                gw.UID,
		Controller:         ptr.To(true),
		BlockOwnerDeletion: ptr.To(true),
	}}
}
