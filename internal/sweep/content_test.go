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

package sweep

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/isac322/flareway/internal/freshness"
)

type contentRemote struct {
	id      string
	name    string
	content string
}

// contentSweep is one target whose pass lists the given remotes and checks
// them through the same hooks every real target uses.
func contentSweep(refs []localRef, remotes *[]contentRemote) TargetDescriptor {
	return TargetDescriptor{
		Kind:  "Widget",
		Grade: freshness.GradeAuthz,
		SweepFunc: func(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
			return classify(refs, *remotes, classifyOptions[contentRemote]{
				kind:    "Widget",
				content: contentCheck[contentRemote](ctx, as),
				idOf:    func(r contentRemote) string { return r.id },
				listed:  func(localRef) bool { return true },
				nameOf:  func(r contentRemote) string { return r.name },
			}), nil
		},
	}
}

// The sweep may count a listing as a fresh verify only when the listed object
// passed the identity checks and still matches the content its reconciler
// verified; anything else is drift that closes the gate and wakes the object.
func TestSweepConfirmsContentAndReportsContentDrift(t *testing.T) {
	ctx := context.Background()
	key := types.NamespacedName{Namespace: "ns", Name: "a"}
	refs := []localRef{{kind: "Widget", key: key, remoteID: "r1", expectedName: "w-a"}}
	remotes := []contentRemote{{id: "r1", name: "w-a", content: "desired"}}
	latch := freshness.NewLatch()
	events := make(chan event.GenericEvent, 4)
	as := NewAccountSweeper(AccountSweeperOptions{Invalidator: latch, Events: events, Logger: logr.Discard()})
	target := contentSweep(refs, &remotes)

	matcherCalls := 0
	latch.SetBaseline("Widget", key, "h1", func(observed any) bool {
		matcherCalls++
		remote, ok := observed.(contentRemote)
		return ok && remote.content == "desired"
	})

	before := time.Now()
	items, result, err := as.RunTargetOnce(ctx, target)
	after := time.Now()
	if err != nil || result != "ok" || len(items) != 0 {
		t.Fatalf("matching pass = %v, %q, %v; want no drift", items, result, err)
	}
	confirmed, ok := latch.ConfirmedAt("Widget", key, "h1")
	if !ok || confirmed.Before(before) || confirmed.After(after) {
		t.Fatalf("confirmation = %v, %v; want the pass start in [%v, %v]", confirmed, ok, before, after)
	}

	// Identity drift is reported as before and never reaches the content
	// check, so a renamed object is not confirmed by accident.
	remotes[0].name = "renamed"
	matcherCalls = 0
	items, _, _ = as.RunTargetOnce(ctx, target)
	if len(items) != 1 || items[0].Case != DriftCaseMismatch || items[0].Reason == contentMismatchReason || matcherCalls != 0 {
		t.Fatalf("identity drift = %#v (matcher calls %d); want the name mismatch only", items, matcherCalls)
	}

	// A missing object is reported as missing, not as changed content.
	remotes = nil
	items, _, _ = as.RunTargetOnce(ctx, target)
	if len(items) != 1 || items[0].Case != DriftCaseMissing || matcherCalls != 0 {
		t.Fatalf("missing remote = %#v (matcher calls %d); want one missing item", items, matcherCalls)
	}

	// Content drift: the identity still matches but the content does not.
	remotes = []contentRemote{{id: "r1", name: "w-a", content: "changed out of band"}}
	as.runTarget(ctx, target)
	if !latch.IsInvalidated("Widget", key) {
		t.Fatal("content drift did not close the object's gate")
	}
	if _, ok := latch.ConfirmedAt("Widget", key, "h1"); ok {
		t.Fatal("content drift left the earlier confirmation in place")
	}
	select {
	case wake := <-events:
		if wake.Object.GetName() != "a" || wake.Object.GetNamespace() != "ns" {
			t.Fatalf("woke %s/%s, want ns/a", wake.Object.GetNamespace(), wake.Object.GetName())
		}
	default:
		t.Fatal("content drift did not wake the owning reconciler")
	}
	items, _, _ = as.RunTargetOnce(ctx, target)
	if len(items) != 1 || items[0].Case != DriftCaseMismatch || items[0].Reason != contentMismatchReason {
		t.Fatalf("content drift = %#v; want one content mismatch", items)
	}
}

// Without a content confirmer, or when the pass start is unknown, the sweep
// keeps identity-only checks: it must never confirm an object it cannot date.
func TestContentCheckRequiresConfirmerAndPassStart(t *testing.T) {
	ctx := context.WithValue(context.Background(), passStartKey{}, time.Now())
	if contentCheck[contentRemote](ctx, NewAccountSweeper(AccountSweeperOptions{Invalidator: identityOnlyInvalidator{}})) != nil {
		t.Fatal("an invalidator without ConfirmContent got a content check")
	}
	if contentCheck[contentRemote](context.Background(), NewAccountSweeper(AccountSweeperOptions{Invalidator: freshness.NewLatch()})) != nil {
		t.Fatal("a pass without a start time got a content check")
	}
}

type identityOnlyInvalidator struct{}

func (identityOnlyInvalidator) Invalidate(string, types.NamespacedName, string) {}
func (identityOnlyInvalidator) IsInvalidated(string, types.NamespacedName) bool { return false }
func (identityOnlyInvalidator) Clear(string, types.NamespacedName)              {}
