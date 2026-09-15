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

// Package envtesthelpers creates status and workload fixtures that a real
// kubelet or controller would normally provide to envtest.
package envtesthelpers

import (
	"context"
	"fmt"
	"net/netip"
	"sort"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	appsapplyv1 "k8s.io/client-go/applyconfigurations/apps/v1"
	coreapplyv1 "k8s.io/client-go/applyconfigurations/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const fieldOwner = "envtest"

// MarkDeploymentAvailable applies the status a healthy Deployment controller
// would report for key.
func MarkDeploymentAvailable(ctx context.Context, c client.Client, key types.NamespacedName) error {
	var deployment appsv1.Deployment
	if err := c.Get(ctx, key, &deployment); err != nil {
		return fmt.Errorf("get Deployment %s: %w", key, err)
	}

	replicas := int32(1)
	if deployment.Spec.Replicas != nil {
		replicas = *deployment.Spec.Replicas
	}
	now := metav1.Now()
	status := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: appsv1.SchemeGroupVersion.String(),
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      deployment.Name,
			Namespace: deployment.Namespace,
		},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration:  deployment.Generation,
			Replicas:            replicas,
			UpdatedReplicas:     replicas,
			ReadyReplicas:       replicas,
			AvailableReplicas:   replicas,
			UnavailableReplicas: 0,
			Conditions: []appsv1.DeploymentCondition{{
				Type:               appsv1.DeploymentAvailable,
				Status:             corev1.ConditionTrue,
				Reason:             "MinimumReplicasAvailable",
				Message:            "Deployment has minimum availability.",
				LastUpdateTime:     now,
				LastTransitionTime: now,
			}},
		},
	}
	applyStatus := appsapplyv1.Deployment(status.Name, status.Namespace).WithStatus(
		appsapplyv1.DeploymentStatus().
			WithObservedGeneration(status.Status.ObservedGeneration).
			WithReplicas(status.Status.Replicas).
			WithUpdatedReplicas(status.Status.UpdatedReplicas).
			WithReadyReplicas(status.Status.ReadyReplicas).
			WithAvailableReplicas(status.Status.AvailableReplicas).
			WithUnavailableReplicas(status.Status.UnavailableReplicas).
			WithConditions(appsapplyv1.DeploymentCondition().
				WithType(appsv1.DeploymentAvailable).
				WithStatus(corev1.ConditionTrue).
				WithReason("MinimumReplicasAvailable").
				WithMessage("Deployment has minimum availability.").
				WithLastUpdateTime(status.Status.Conditions[0].LastUpdateTime).
				WithLastTransitionTime(status.Status.Conditions[0].LastTransitionTime)))
	if err := c.Status().Apply(ctx, applyStatus, client.FieldOwner(fieldOwner), client.ForceOwnership); err != nil {
		return fmt.Errorf("apply available status to Deployment %s: %w", key, err)
	}
	return nil
}

// CreateDataplanePods creates n deterministic running Pods from deploy's Pod
// template and applies Ready status with TEST-NET-1 addresses.
func CreateDataplanePods(ctx context.Context, c client.Client, deploy *appsv1.Deployment, n int) ([]corev1.Pod, error) {
	if deploy == nil {
		return nil, fmt.Errorf("deployment is nil")
	}
	if n < 0 || n > 200 {
		return nil, fmt.Errorf("pod count must be between 0 and 200, got %d", n)
	}

	pods := make([]corev1.Pod, 0, n)
	for index := range n {
		name := fmt.Sprintf("%s-envtest-%03d", deploy.Name, index)
		ip := fmt.Sprintf("192.0.2.%d", index+10)
		labels := make(map[string]string, len(deploy.Spec.Template.Labels))
		for key, value := range deploy.Spec.Template.Labels {
			labels[key] = value
		}
		annotations := make(map[string]string, len(deploy.Spec.Template.Annotations))
		for key, value := range deploy.Spec.Template.Annotations {
			annotations[key] = value
		}

		pod := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Namespace:   deploy.Namespace,
				Labels:      labels,
				Annotations: annotations,
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(deploy, appsv1.SchemeGroupVersion.WithKind("Deployment")),
				},
			},
			Spec: *deploy.Spec.Template.Spec.DeepCopy(),
		}
		if err := c.Create(ctx, &pod); err != nil {
			return nil, fmt.Errorf("create Pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}

		status := readyPodStatus(&pod, ip)
		condition := status.Status.Conditions[0]
		startTime := metav1.Now()
		if status.Status.StartTime != nil {
			startTime = *status.Status.StartTime
		}
		applyStatus := coreapplyv1.Pod(status.Name, status.Namespace).WithStatus(
			coreapplyv1.PodStatus().WithPhase(status.Status.Phase).WithPodIP(status.Status.PodIP).
				WithStartTime(startTime).WithConditions(coreapplyv1.PodCondition().
				WithType(condition.Type).WithStatus(condition.Status).WithReason(condition.Reason).
				WithMessage(condition.Message).WithLastTransitionTime(condition.LastTransitionTime)))
		if err := c.Status().Apply(ctx, applyStatus, client.FieldOwner(fieldOwner), client.ForceOwnership); err != nil {
			return nil, fmt.Errorf("apply ready status to Pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
		pod.Status = status.Status
		pod.ResourceVersion = status.ResourceVersion
		pods = append(pods, pod)
	}
	return pods, nil
}

// CreateEndpointSlice creates a deterministic EndpointSlice for svc. Addresses
// are validated, deduplicated, and sorted.
func CreateEndpointSlice(ctx context.Context, c client.Client, svc *corev1.Service, ips ...string) (*discoveryv1.EndpointSlice, error) {
	if svc == nil {
		return nil, fmt.Errorf("service is nil")
	}

	addresses, addressType, err := normalizeAddresses(ips)
	if err != nil {
		return nil, err
	}
	ports := endpointPorts(svc.Spec.Ports)
	endpoints := make([]discoveryv1.Endpoint, 0, len(addresses))
	for _, address := range addresses {
		endpoints = append(endpoints, discoveryv1.Endpoint{
			Addresses: []string{address},
			Conditions: discoveryv1.EndpointConditions{
				Ready:       new(true),
				Serving:     new(true),
				Terminating: new(false),
			},
		})
	}

	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svc.Name + "-envtest",
			Namespace: svc.Namespace,
			Labels: map[string]string{
				discoveryv1.LabelServiceName: svc.Name,
				discoveryv1.LabelManagedBy:   "flareway-envtest",
			},
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(svc, corev1.SchemeGroupVersion.WithKind("Service")),
			},
		},
		AddressType: addressType,
		Endpoints:   endpoints,
		Ports:       ports,
	}
	if err := c.Create(ctx, slice); err != nil {
		return nil, fmt.Errorf("create EndpointSlice %s/%s: %w", slice.Namespace, slice.Name, err)
	}
	return slice, nil
}

func readyPodStatus(pod *corev1.Pod, ip string) *corev1.Pod {
	now := metav1.Now()
	containerStatuses := make([]corev1.ContainerStatus, 0, len(pod.Spec.Containers))
	for _, container := range pod.Spec.Containers {
		containerStatuses = append(containerStatuses, corev1.ContainerStatus{
			Name:         container.Name,
			Ready:        true,
			RestartCount: 0,
			Image:        container.Image,
			ImageID:      "envtest://" + container.Name,
			ContainerID:  "containerd://envtest-" + container.Name,
			State: corev1.ContainerState{
				Running: &corev1.ContainerStateRunning{StartedAt: now},
			},
		})
	}

	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: corev1.SchemeGroupVersion.String(),
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      pod.Name,
			Namespace: pod.Namespace,
		},
		Status: corev1.PodStatus{
			Phase:             corev1.PodRunning,
			PodIP:             ip,
			PodIPs:            []corev1.PodIP{{IP: ip}},
			HostIP:            "192.0.2.1",
			StartTime:         new(now),
			ContainerStatuses: containerStatuses,
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodInitialized, Status: corev1.ConditionTrue, LastTransitionTime: now},
				{Type: corev1.ContainersReady, Status: corev1.ConditionTrue, LastTransitionTime: now},
				{Type: corev1.PodReady, Status: corev1.ConditionTrue, LastTransitionTime: now},
				{Type: corev1.PodScheduled, Status: corev1.ConditionTrue, LastTransitionTime: now},
			},
		},
	}
}

func normalizeAddresses(ips []string) ([]string, discoveryv1.AddressType, error) {
	if len(ips) == 0 {
		return nil, discoveryv1.AddressTypeIPv4, nil
	}

	unique := make(map[netip.Addr]struct{}, len(ips))
	var ipv6 *bool
	for _, value := range ips {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return nil, "", fmt.Errorf("parse endpoint address %q: %w", value, err)
		}
		isIPv6 := address.Is6()
		if ipv6 != nil && *ipv6 != isIPv6 {
			return nil, "", fmt.Errorf("endpointslice cannot mix IPv4 and IPv6 addresses")
		}
		if ipv6 == nil {
			ipv6 = new(isIPv6)
		}
		unique[address] = struct{}{}
	}

	parsed := make([]netip.Addr, 0, len(unique))
	for address := range unique {
		parsed = append(parsed, address)
	}
	sort.Slice(parsed, func(i, j int) bool { return parsed[i].Less(parsed[j]) })
	addresses := make([]string, 0, len(parsed))
	for _, address := range parsed {
		addresses = append(addresses, address.String())
	}
	if ipv6 != nil && *ipv6 {
		return addresses, discoveryv1.AddressTypeIPv6, nil
	}
	return addresses, discoveryv1.AddressTypeIPv4, nil
}

func endpointPorts(servicePorts []corev1.ServicePort) []discoveryv1.EndpointPort {
	ports := append([]corev1.ServicePort(nil), servicePorts...)
	sort.SliceStable(ports, func(i, j int) bool {
		if ports[i].Name != ports[j].Name {
			return ports[i].Name < ports[j].Name
		}
		return ports[i].Port < ports[j].Port
	})

	result := make([]discoveryv1.EndpointPort, 0, len(ports))
	for _, servicePort := range ports {
		port := servicePort.Port
		if servicePort.TargetPort.Type == intstr.Int && servicePort.TargetPort.IntVal > 0 {
			port = servicePort.TargetPort.IntVal
		}
		endpointPort := discoveryv1.EndpointPort{
			Protocol:    new(servicePort.Protocol),
			Port:        new(port),
			AppProtocol: servicePort.AppProtocol,
		}
		if servicePort.Name != "" {
			endpointPort.Name = new(servicePort.Name)
		}
		result = append(result, endpointPort)
	}
	return result
}
