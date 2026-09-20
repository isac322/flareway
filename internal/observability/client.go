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

package observability

import (
	"context"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// EventingClient observes successful status writes and emits transition-only
// Events. It preserves the complete client.Client behavior by delegation.
type EventingClient struct {
	client.Client
	reader   client.Reader
	recorder record.EventRecorder
}

// NewEventingClient wraps a controller-runtime client. Reader should bypass
// the cache so transition checks compare against the persisted pre-write state.
// A nil recorder leaves writes unchanged and disables Events.
func NewEventingClient(base client.Client, reader client.Reader, recorder record.EventRecorder) client.Client {
	if reader == nil {
		reader = base
	}
	return &EventingClient{Client: base, reader: reader, recorder: recorder}
}

// Status returns the transition-aware status writer.
func (eventing *EventingClient) Status() client.SubResourceWriter {
	return &eventingStatusWriter{
		SubResourceWriter: eventing.Client.Status(),
		reader:            eventing.reader,
		recorder:          eventing.recorder,
	}
}

// SubResource preserves transition observation when callers request the status
// client through the generic subresource API.
func (eventing *EventingClient) SubResource(name string) client.SubResourceClient {
	base := eventing.Client.SubResource(name)
	if name != "status" {
		return base
	}
	return &eventingSubResourceClient{
		SubResourceClient: base,
		eventingStatusWriter: eventingStatusWriter{
			SubResourceWriter: base,
			reader:            eventing.reader,
			recorder:          eventing.recorder,
		},
	}
}

type eventingStatusWriter struct {
	client.SubResourceWriter
	reader   client.Reader
	recorder record.EventRecorder
}

func (writer *eventingStatusWriter) Update(ctx context.Context, object client.Object, options ...client.SubResourceUpdateOption) error {
	before := writer.readCurrent(ctx, object)
	if err := writer.SubResourceWriter.Update(ctx, object, options...); err != nil {
		return err
	}
	writer.emit(object, before)
	return nil
}

func (writer *eventingStatusWriter) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.SubResourcePatchOption) error {
	before := writer.readCurrent(ctx, object)
	if err := writer.SubResourceWriter.Patch(ctx, object, patch, options...); err != nil {
		return err
	}
	writer.emit(object, before)
	return nil
}

func (writer *eventingStatusWriter) emit(after client.Object, before runtime.Object) {
	if before == nil {
		return
	}
	target := after
	if previous, ok := before.(client.Object); ok {
		target = previous
	}
	EmitConditionTransitions(writer.recorder, target, before, after)
}

func (writer *eventingStatusWriter) Apply(ctx context.Context, object runtime.ApplyConfiguration, options ...client.SubResourceApplyOption) error {
	before := writer.readApplyCurrent(ctx, object)
	if err := writer.SubResourceWriter.Apply(ctx, object, options...); err != nil {
		return err
	}
	after := writer.readApplyCurrent(ctx, object)
	if before == nil || after == nil {
		return nil
	}
	EmitConditionTransitions(writer.recorder, after, before, after)
	return nil
}

func (writer *eventingStatusWriter) readCurrent(ctx context.Context, object client.Object) runtime.Object {
	if writer.reader == nil || object == nil {
		return nil
	}
	current, ok := object.DeepCopyObject().(client.Object)
	if !ok {
		return nil
	}
	if err := writer.reader.Get(ctx, client.ObjectKeyFromObject(object), current); err != nil {
		return nil
	}
	return current
}

type pointerApplyConfigurationMeta interface {
	GetName() *string
	GetNamespace() *string
	GetKind() *string
	GetAPIVersion() *string
}

type stringApplyConfigurationMeta interface {
	GetName() string
	GetNamespace() string
	GetKind() string
	GetAPIVersion() string
}

func (writer *eventingStatusWriter) readApplyCurrent(ctx context.Context, object runtime.ApplyConfiguration) *unstructured.Unstructured {
	name, namespace, kind, apiVersion, ok := applyConfigurationMetadata(object)
	if !ok {
		return nil
	}
	groupVersion, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return nil
	}
	current := &unstructured.Unstructured{}
	current.SetGroupVersionKind(groupVersion.WithKind(kind))
	if err := writer.reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, current); err != nil {
		return nil
	}
	return current
}

func applyConfigurationMetadata(object runtime.ApplyConfiguration) (name, namespace, kind, apiVersion string, ok bool) {
	switch meta := object.(type) {
	case pointerApplyConfigurationMeta:
		if meta.GetName() == nil || meta.GetKind() == nil || meta.GetAPIVersion() == nil {
			return "", "", "", "", false
		}
		namespaceValue := ""
		if meta.GetNamespace() != nil {
			namespaceValue = *meta.GetNamespace()
		}
		return *meta.GetName(), namespaceValue, *meta.GetKind(), *meta.GetAPIVersion(), true
	case stringApplyConfigurationMeta:
		if meta.GetName() == "" || meta.GetKind() == "" || meta.GetAPIVersion() == "" {
			return "", "", "", "", false
		}
		return meta.GetName(), meta.GetNamespace(), meta.GetKind(), meta.GetAPIVersion(), true
	default:
		return "", "", "", "", false
	}
}

type eventingSubResourceClient struct {
	client.SubResourceClient
	eventingStatusWriter
}

func (eventing *eventingSubResourceClient) Update(ctx context.Context, object client.Object, options ...client.SubResourceUpdateOption) error {
	return eventing.eventingStatusWriter.Update(ctx, object, options...)
}

func (eventing *eventingSubResourceClient) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.SubResourcePatchOption) error {
	return eventing.eventingStatusWriter.Patch(ctx, object, patch, options...)
}

func (eventing *eventingSubResourceClient) Apply(ctx context.Context, object runtime.ApplyConfiguration, options ...client.SubResourceApplyOption) error {
	return eventing.eventingStatusWriter.Apply(ctx, object, options...)
}
