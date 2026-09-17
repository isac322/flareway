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

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

func TestAccessTagsAndCustomPagesClientParity(t *testing.T) {
	const paginationPageSize = 1000
	tagFirstPage := make([]map[string]any, paginationPageSize)
	for index := range tagFirstPage {
		tagFirstPage[index] = map[string]any{"name": fmt.Sprintf("tag-%04d", paginationPageSize-1-index)}
	}
	var customPageWrites, tagListRequests, customPageListRequests int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		write := func(result any, resultInfo map[string]int) {
			envelope := map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result}
			if resultInfo != nil {
				envelope["result_info"] = resultInfo
			}
			if err := json.NewEncoder(response).Encode(envelope); err != nil {
				t.Errorf("encode response: %v", err)
			}
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/accounts/account/access/tags":
			tagListRequests++
			if request.URL.Query().Get("per_page") != fmt.Sprint(paginationPageSize) {
				t.Errorf("tag per_page = %q", request.URL.Query().Get("per_page"))
			}
			switch request.URL.Query().Get("page") {
			case "1":
				write(tagFirstPage, map[string]int{"page": 1, "per_page": paginationPageSize, "count": paginationPageSize, "total_count": paginationPageSize + 1, "total_pages": 2})
			case "2":
				write([]map[string]any{{"name": "old-tag"}}, map[string]int{"page": 2, "per_page": paginationPageSize, "count": 1, "total_count": paginationPageSize + 1, "total_pages": 2})
			default:
				t.Errorf("unexpected tag page %q", request.URL.Query().Get("page"))
				write([]any{}, nil)
			}
		case request.Method == http.MethodPut && request.URL.Path == "/accounts/account/access/tags/old-tag":
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode tag update: %v", err)
			}
			if body["name"] != "new-tag" {
				t.Errorf("tag update body = %#v", body)
			}
			write(map[string]any{"name": "new-tag"}, nil)
		case request.Method == http.MethodPost && request.URL.Path == "/accounts/account/access/custom_pages":
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode custom page create: %v", err)
			}
			if body["type"] != "identity_denied" {
				t.Errorf("custom page type was not translated: %#v", body)
			}
			if _, found := body["contract_version"]; found {
				t.Errorf("unset contract version was serialized: %#v", body)
			}
			customPageWrites++
			write(map[string]any{
				"uid": "page-id", "name": body["name"], "type": body["type"], "contract_version": 0,
				"warnings": []map[string]any{{"tier": "html", "ref": "line:1", "message": "advisory"}},
			}, nil)
		case request.Method == http.MethodGet && request.URL.Path == "/accounts/account/access/custom_pages/page-id":
			write(map[string]any{"uid": "page-id", "name": "page", "type": "identity_denied", "contract_version": 0, "custom_html": "<main>page</main>"}, nil)
		case request.Method == http.MethodGet && request.URL.Path == "/accounts/account/access/custom_pages":
			customPageListRequests++
			if request.URL.Query().Get("page") != "1" || request.URL.Query().Get("per_page") != fmt.Sprint(paginationPageSize) {
				t.Errorf("custom page pagination query = %q", request.URL.RawQuery)
			}
			write([]map[string]any{{"uid": "page-id", "name": "page", "type": "identity_denied", "contract_version": 0, "warnings": []any{}}}, map[string]int{"page": 1, "per_page": paginationPageSize, "count": 1, "total_count": 1, "total_pages": 1})
		case request.Method == http.MethodPut && request.URL.Path == "/accounts/account/access/custom_pages/page-id":
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode custom page update: %v", err)
			}
			if body["contract_version"] != float64(1) {
				t.Errorf("contract version update body = %#v", body)
			}
			customPageWrites++
			write(map[string]any{"uid": "page-id", "name": body["name"], "type": body["type"], "contract_version": 1, "warnings": []any{}}, nil)
		case request.Method == http.MethodDelete && request.URL.Path == "/accounts/account/access/custom_pages/page-id":
			write(map[string]any{"id": "page-id"}, nil)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	api := flarecloudflare.New(
		"token", "account", logr.Discard(),
		flarecloudflare.WithBaseURL(server.URL),
		flarecloudflare.WithLimiter(rate.NewLimiter(rate.Inf, 0)),
	)
	ctx := context.Background()
	tags, err := api.ListAccessTags(ctx)
	if err != nil || len(tags) != paginationPageSize+1 || tags[0].Name != "old-tag" || tags[len(tags)-1].Name != "tag-0999" ||
		!slices.IsSortedFunc(tags, func(left, right flarecloudflare.AccessTag) int { return strings.Compare(left.Name, right.Name) }) ||
		tagListRequests != 2 {
		t.Fatalf("ListAccessTags returned %d tags, requests=%d, %v", len(tags), tagListRequests, err)
	}
	updatedTag, err := api.UpdateAccessTag(ctx, "old-tag", "new-tag")
	if err != nil || updatedTag.Name != "new-tag" {
		t.Fatalf("UpdateAccessTag = %#v, %v", updatedTag, err)
	}

	created, err := api.CreateAccessCustomPage(ctx, flarecloudflare.AccessCustomPageInput{
		Name: "page", Type: v1alpha1.AccessCustomPageTypeIdentityDenied, HTML: "<main>page</main>",
	})
	if err != nil || created.ID != "page-id" || created.Type != v1alpha1.AccessCustomPageTypeIdentityDenied || len(created.Warnings) != 1 {
		t.Fatalf("CreateAccessCustomPage = %#v, %v", created, err)
	}
	observed, err := api.GetAccessCustomPage(ctx, created.ID)
	if err != nil || observed.HTML != "<main>page</main>" {
		t.Fatalf("GetAccessCustomPage = %#v, %v", observed, err)
	}
	pages, err := api.ListAccessCustomPages(ctx)
	if err != nil || len(pages) != 1 || pages[0].ID != created.ID || customPageListRequests != 1 {
		t.Fatalf("ListAccessCustomPages = %#v, requests=%d, %v", pages, customPageListRequests, err)
	}
	contractVersion := int64(1)
	updated, err := api.UpdateAccessCustomPage(ctx, created.ID, flarecloudflare.AccessCustomPageInput{
		Name: "page", Type: v1alpha1.AccessCustomPageTypeIdentityDenied, HTML: "<main>page</main>", ContractVersion: &contractVersion,
	})
	if err != nil || updated.ContractVersion != contractVersion {
		t.Fatalf("UpdateAccessCustomPage = %#v, %v", updated, err)
	}
	deletedID, err := api.DeleteAccessCustomPage(ctx, created.ID)
	if err != nil || deletedID != created.ID || customPageWrites != 2 {
		t.Fatalf("DeleteAccessCustomPage = %q, writes=%d, %v", deletedID, customPageWrites, err)
	}
}

func TestAccessListPaginationRejectsNonAdvancingPages(t *testing.T) {
	const paginationPageSize = 1000
	tags := make([]map[string]any, paginationPageSize)
	pages := make([]map[string]any, paginationPageSize)
	for index := range paginationPageSize {
		tags[index] = map[string]any{"name": fmt.Sprintf("tag-%04d", index)}
		pages[index] = map[string]any{
			"uid": fmt.Sprintf("page-%04d", index), "name": fmt.Sprintf("page-%04d", index),
			"type": "identity_denied", "contract_version": 0, "warnings": []any{},
		}
	}
	var tagRequestedPages, customPageRequestedPages []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		envelope := map[string]any{
			"success": true, "errors": []any{}, "messages": []any{},
			"result_info": map[string]int{"page": 1, "per_page": paginationPageSize, "count": paginationPageSize, "total_count": paginationPageSize, "total_pages": 1},
		}
		switch request.URL.Path {
		case "/accounts/account/access/tags":
			tagRequestedPages = append(tagRequestedPages, request.URL.Query().Get("page"))
			envelope["result"] = tags
		case "/accounts/account/access/custom_pages":
			customPageRequestedPages = append(customPageRequestedPages, request.URL.Query().Get("page"))
			envelope["result"] = pages
		default:
			http.NotFound(response, request)
			return
		}
		if err := json.NewEncoder(response).Encode(envelope); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer server.Close()

	api := flarecloudflare.New(
		"token", "account", logr.Discard(),
		flarecloudflare.WithBaseURL(server.URL),
		flarecloudflare.WithLimiter(rate.NewLimiter(rate.Inf, 0)),
	)
	if _, err := api.ListAccessTags(context.Background()); err == nil || !strings.Contains(err.Error(), "pagination did not advance at page 2") ||
		!slices.Equal(tagRequestedPages, []string{"1", "2"}) {
		t.Fatalf("ListAccessTags error = %v, requested pages = %v", err, tagRequestedPages)
	}
	if _, err := api.ListAccessCustomPages(context.Background()); err == nil || !strings.Contains(err.Error(), "pagination did not advance at page 2") ||
		!slices.Equal(customPageRequestedPages, []string{"1", "2"}) {
		t.Fatalf("ListAccessCustomPages error = %v, requested pages = %v", err, customPageRequestedPages)
	}
}

func TestAccessCustomPageLifecycleWarningsDriftAndSafeDelete(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.September, 14, 12, 0, 0, 0, time.UTC)
	remote := newFakeCustomPageCloudflare()
	remote.warnings = []flarecloudflare.AccessCustomPageWarning{{Tier: "liquid", Ref: "line:1", Message: "unknown variable"}}
	recorder := events.NewFakeRecorder(10)
	kube, reconciler, page := newCustomPageTestReconciler(t, remote, recorder, clock)
	if err := kube.Create(ctx, page); err != nil {
		t.Fatal(err)
	}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(page)}

	reconcileCustomPage(ctx, t, reconciler, request, "add finalizer")
	reconcileCustomPage(ctx, t, reconciler, request, "create custom page")

	var current v1alpha1.AccessCustomPage
	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	if current.Status.CustomPageID == "" || !current.Status.OwnershipVerified {
		t.Fatalf("custom page ownership was not recorded: %#v", current.Status)
	}
	if condition := meta.FindStatusCondition(current.Status.Conditions, v1alpha1.AccessCustomPageConditionAccepted); condition == nil || condition.Status != metav1.ConditionTrue {
		t.Fatalf("Accepted condition = %#v", condition)
	}
	if condition := meta.FindStatusCondition(current.Status.Conditions, v1alpha1.AccessCustomPageConditionDegraded); condition == nil || condition.Status != metav1.ConditionTrue || condition.Reason != "TemplateWarnings" {
		t.Fatalf("Degraded condition = %#v", condition)
	}
	statusJSON, err := json.Marshal(current.Status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(statusJSON), page.Spec.HTML) || strings.Contains(string(statusJSON), `"html"`) {
		t.Fatalf("custom HTML was duplicated into status: %s", statusJSON)
	}
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "TemplateWarning") || !strings.Contains(event, "unknown variable") {
			t.Fatalf("warning event = %q", event)
		}
	default:
		t.Fatal("expected a template warning event")
	}

	observed := remote.pages[current.Status.CustomPageID]
	observed.HTML = "<main>changed outside Flareway</main>"
	remote.pages[current.Status.CustomPageID] = observed
	reconcileCustomPage(ctx, t, reconciler, request, "repair custom page drift")
	if remote.updates != 1 || remote.pages[current.Status.CustomPageID].HTML != page.Spec.HTML {
		t.Fatalf("drift repair = updates %d, remote %#v", remote.updates, remote.pages[current.Status.CustomPageID])
	}
	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}

	application := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "consumer", Namespace: page.Namespace},
		Spec:       v1alpha1.AccessApplicationSpec{Application: v1alpha1.AccessApplicationSettings{CustomPageRefs: []v1alpha1.AccessCustomPageReference{{ObjectRef: &v1alpha1.NamespacedLocalObjectReference{Name: page.Name}}}}},
	}
	if err := kube.Create(ctx, application); err != nil {
		t.Fatal(err)
	}
	if err := kube.Delete(ctx, &current); err != nil {
		t.Fatal(err)
	}
	reconcileCustomPage(ctx, t, reconciler, request, "block referenced deletion")
	if _, found := remote.pages[current.Status.CustomPageID]; !found {
		t.Fatal("referenced remote custom page was deleted")
	}
	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	if condition := meta.FindStatusCondition(current.Status.Conditions, v1alpha1.AccessCustomPageConditionCleanupBlocked); condition == nil || condition.Status != metav1.ConditionTrue {
		t.Fatalf("CleanupBlocked condition = %#v", condition)
	}

	if err := kube.Delete(ctx, application); err != nil {
		t.Fatal(err)
	}
	reconcileCustomPage(ctx, t, reconciler, request, "delete unreferenced custom page")
	if _, found := remote.pages[current.Status.CustomPageID]; found {
		t.Fatal("unreferenced remote custom page was retained under Delete policy")
	}
	if err := kube.Get(ctx, request.NamespacedName, &current); !apierrors.IsNotFound(err) {
		t.Fatalf("deleted AccessCustomPage still exists: %v", err)
	}
}

func TestAccessCustomPageObserveOnlyReportsHTMLDriftWithoutMutation(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.September, 14, 12, 0, 0, 0, time.UTC)
	remote := newFakeCustomPageCloudflare()
	remote.pages["external-page"] = flarecloudflare.AccessCustomPage{
		AccessCustomPageSummary: flarecloudflare.AccessCustomPageSummary{
			ID: "external-page", Name: "flareway/cluster-id/tenant/observed", Type: v1alpha1.AccessCustomPageTypeForbidden,
		},
		HTML: "<main>remote</main>",
	}
	kube, reconciler, page := newCustomPageTestReconciler(t, remote, nil, clock)
	page.Name = "observed"
	page.Spec.Name = "observed"
	page.Spec.ManagementPolicy = v1alpha1.ManagementPolicyObserveOnly
	page.Spec.ExternalRef = &v1alpha1.AccessCustomPageExternalReference{CustomPageID: "external-page"}
	if err := kube.Create(ctx, page); err != nil {
		t.Fatal(err)
	}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(page)}

	reconcileCustomPage(ctx, t, reconciler, request, "add ObserveOnly finalizer")
	reconcileCustomPage(ctx, t, reconciler, request, "observe custom page")

	var current v1alpha1.AccessCustomPage
	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	if remote.updates != 0 || current.Status.OwnershipVerified {
		t.Fatalf("ObserveOnly mutated ownership: updates=%d status=%#v", remote.updates, current.Status)
	}
	condition := meta.FindStatusCondition(current.Status.Conditions, v1alpha1.AccessCustomPageConditionDegraded)
	if condition == nil || condition.Status != metav1.ConditionTrue || condition.Reason != "DriftDetected" || !strings.Contains(condition.Message, "html") {
		t.Fatalf("drift condition = %#v", condition)
	}
}

func TestAccessCustomPageAdoptByIDVerifiesNameAndUpdatesDrift(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.September, 14, 12, 0, 0, 0, time.UTC)
	remote := newFakeCustomPageCloudflare()
	remote.pages["adopted-page"] = flarecloudflare.AccessCustomPage{
		AccessCustomPageSummary: flarecloudflare.AccessCustomPageSummary{
			ID: "adopted-page", Name: "existing-page", Type: v1alpha1.AccessCustomPageTypeForbidden,
		},
		HTML: "<main>old template</main>",
	}
	kube, reconciler, page := newCustomPageTestReconciler(t, remote, nil, clock)
	page.Name = "adopted"
	page.Spec.Name = "adopted"
	page.Spec.ExternalRef = &v1alpha1.AccessCustomPageExternalReference{CustomPageID: "adopted-page"}
	page.Spec.Adoption = v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID, Expect: v1alpha1.AdoptionExpect{Name: "existing-page"}}
	if err := kube.Create(ctx, page); err != nil {
		t.Fatal(err)
	}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(page)}

	reconcileCustomPage(ctx, t, reconciler, request, "add adoption finalizer")
	reconcileCustomPage(ctx, t, reconciler, request, "adopt custom page")

	var current v1alpha1.AccessCustomPage
	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	if current.Status.CustomPageID != "adopted-page" || !current.Status.OwnershipVerified || remote.updates != 1 {
		t.Fatalf("adoption result: status=%#v updates=%d", current.Status, remote.updates)
	}
	if remote.pages["adopted-page"].Name != "flareway/cluster-id/tenant/adopted" || remote.pages["adopted-page"].HTML != page.Spec.HTML {
		t.Fatalf("adopted page was not reconciled: %#v", remote.pages["adopted-page"])
	}
}

func TestAccessCustomPageRejectsOversizedHTMLBeforeRemoteMutation(t *testing.T) {
	ctx := context.Background()
	remote := newFakeCustomPageCloudflare()
	_, reconciler, page := newCustomPageTestReconciler(t, remote, nil, time.Now())
	page.Spec.HTML = strings.Repeat("x", accessCustomPageHTMLMaxLength+1)
	if _, err := reconciler.customPageInput(ctx, page); err == nil || !strings.Contains(err.Error(), "size") && !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized HTML error = %v", err)
	}
	if len(remote.pages) != 0 {
		t.Fatalf("oversized HTML reached Cloudflare: %#v", remote.pages)
	}
}

func TestResolveCustomPagesEnforcesGrantExistenceAndTypeUniqueness(t *testing.T) {
	ctx := context.Background()
	remote := newFakeCustomPageCloudflare()
	remote.pages["page-one"] = flarecloudflare.AccessCustomPage{
		AccessCustomPageSummary: flarecloudflare.AccessCustomPageSummary{ID: "page-one", Name: "page-one", Type: v1alpha1.AccessCustomPageTypeForbidden},
		HTML:                    "<main>forbidden</main>",
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	page := &v1alpha1.AccessCustomPage{
		ObjectMeta: metav1.ObjectMeta{Name: "forbidden", Namespace: "platform"},
		Spec:       v1alpha1.AccessCustomPageSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}},
		Status: v1alpha1.AccessCustomPageStatus{
			CustomPageID: "page-one",
			Conditions:   []metav1.Condition{{Type: v1alpha1.AccessCustomPageConditionAccepted, Status: metav1.ConditionTrue, Reason: "Ready", LastTransitionTime: metav1.NewTime(time.Now())}},
		},
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1alpha1.AccessCustomPage{}).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "true"}}}, page,
	).Build()
	account := &v1alpha1.CloudflareAccount{ObjectMeta: metav1.ObjectMeta{Name: "account"}, Spec: v1alpha1.CloudflareAccountSpec{Grants: []v1alpha1.CloudflareAccountGrant{{NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}}}}}}
	application := &v1alpha1.AccessApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant"},
		Spec:       v1alpha1.AccessApplicationSpec{Application: v1alpha1.AccessApplicationSettings{CustomPageRefs: []v1alpha1.AccessCustomPageReference{{ObjectRef: &v1alpha1.NamespacedLocalObjectReference{Name: page.Name, Namespace: page.Namespace}}}}},
	}
	reconciler := &AccessApplicationReconciler{Client: kube}

	if _, err := reconciler.resolveCustomPages(ctx, application, account, remote); err == nil || accessValidationReason(err) != "RefNotPermitted" {
		t.Fatalf("denied grant error = %v", err)
	}
	account.Spec.Grants[0].AccessCustomPageRefs = v1alpha1.GrantPermissionAllowed
	account.Spec.Grants[0].PlatformObjects = v1alpha1.GrantPermissionAllowed
	ids, err := reconciler.resolveCustomPages(ctx, application, account, remote)
	if err != nil || !slices.Equal(ids, []string{"page-one"}) {
		t.Fatalf("resolved custom pages = %v, %v", ids, err)
	}

	application.Spec.Application.CustomPageRefs = append(application.Spec.Application.CustomPageRefs, v1alpha1.AccessCustomPageReference{ExternalID: "page-two"})
	remote.pages["page-two"] = flarecloudflare.AccessCustomPage{
		AccessCustomPageSummary: flarecloudflare.AccessCustomPageSummary{ID: "page-two", Name: "page-two", Type: v1alpha1.AccessCustomPageTypeForbidden},
	}
	if _, err := reconciler.resolveCustomPages(ctx, application, account, remote); err == nil || accessValidationReason(err) != "Conflict" {
		t.Fatalf("duplicate page type error = %v", err)
	}
	delete(remote.pages, "page-one")
	application.Spec.Application.CustomPageRefs = application.Spec.Application.CustomPageRefs[:1]
	if _, err := reconciler.resolveCustomPages(ctx, application, account, remote); err == nil || accessValidationReason(err) != "TargetNotFound" {
		t.Fatalf("missing remote page error = %v", err)
	}
}

func TestEnsureAccessTagsListsOnceAndRejectsUnsafeBounds(t *testing.T) {
	ctx := context.Background()
	remote := newFakeCustomPageCloudflare()
	remote.tags[accessManagedTag] = flarecloudflare.AccessTag{Name: accessManagedTag}
	if err := ensureAccessTags(ctx, remote, "team-payments", accessManagedTag, "team-payments"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(remote.tagCalls, []string{"ListTags", "CreateTag:team-payments"}) {
		t.Fatalf("tag calls = %v", remote.tagCalls)
	}

	before := slices.Clone(remote.tagCalls)
	tooMany := make([]string, flarecloudflare.AccessApplicationTagLimit+1)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("tag-%d", index)
	}
	if err := ensureAccessTags(ctx, remote, tooMany...); err == nil || !strings.Contains(err.Error(), "at most 25") {
		t.Fatalf("too-many-tags error = %v", err)
	}
	if err := ensureAccessTags(ctx, remote, strings.Repeat("a", flarecloudflare.AccessTagNameMaxLength+1)); err == nil || !strings.Contains(err.Error(), "35-character") {
		t.Fatalf("long-tag error = %v", err)
	}
	if !slices.Equal(before, remote.tagCalls) {
		t.Fatalf("invalid tags reached Cloudflare: before=%v after=%v", before, remote.tagCalls)
	}
}

func newCustomPageTestReconciler(t *testing.T, remote *fakeCustomPageCloudflare, recorder *events.FakeRecorder, now time.Time) (client.Client, *AccessCustomPageReconciler, *v1alpha1.AccessCustomPage) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: "tenant", Name: "api-token", Key: "token"}},
			Grants: []v1alpha1.CloudflareAccountGrant{{
				NamespaceSelector:    metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}},
				PlatformObjects:      v1alpha1.GrantPermissionAllowed,
				AccessCustomPageRefs: v1alpha1.GrantPermissionAllowed,
			}},
		},
		Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{
			{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: metav1.NewTime(now)},
			{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid", LastTransitionTime: metav1.NewTime(now)},
		}},
	}
	page := &v1alpha1.AccessCustomPage{
		ObjectMeta: metav1.ObjectMeta{Name: "login-page", Namespace: "tenant", UID: types.UID("login-page")},
		Spec: v1alpha1.AccessCustomPageSpec{
			AccountRef:       corev1.LocalObjectReference{Name: account.Name},
			Name:             "login-page",
			Type:             v1alpha1.AccessCustomPageTypeForbidden,
			HTML:             "<main>Access denied</main>",
			ContractVersion:  1,
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
			DeletionPolicy:   v1alpha1.DeletionPolicyDelete,
		},
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1alpha1.AccessCustomPage{}).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster-id")}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "true"}}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "api-token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("api-token")}},
		account,
	).Build()
	reconciler := &AccessCustomPageReconciler{
		Client: kube, Scheme: scheme, Recorder: recorder,
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) { return remote, nil },
		Now:                 func() time.Time { return now },
	}
	return kube, reconciler, page
}

func reconcileCustomPage(ctx context.Context, t *testing.T, reconciler *AccessCustomPageReconciler, request ctrl.Request, action string) {
	t.Helper()
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("%s: %v", action, err)
	}
}

type fakeCustomPageCloudflare struct {
	flarecloudflare.AccessAPI
	pages    map[string]flarecloudflare.AccessCustomPage
	tags     map[string]flarecloudflare.AccessTag
	warnings []flarecloudflare.AccessCustomPageWarning
	next     int
	updates  int
	tagCalls []string
}

func newFakeCustomPageCloudflare() *fakeCustomPageCloudflare {
	return &fakeCustomPageCloudflare{pages: make(map[string]flarecloudflare.AccessCustomPage), tags: make(map[string]flarecloudflare.AccessTag)}
}

func (f *fakeCustomPageCloudflare) CreateAccessCustomPage(_ context.Context, input flarecloudflare.AccessCustomPageInput) (flarecloudflare.AccessCustomPage, error) {
	f.next++
	id := fmt.Sprintf("page-%d", f.next)
	page := fakeCustomPageFromInput(id, input, f.warnings)
	f.pages[id] = page
	return page, nil
}

func (f *fakeCustomPageCloudflare) UpdateAccessCustomPage(_ context.Context, id string, input flarecloudflare.AccessCustomPageInput) (flarecloudflare.AccessCustomPage, error) {
	if _, found := f.pages[id]; !found {
		return flarecloudflare.AccessCustomPage{}, &cloudflaresdk.Error{StatusCode: http.StatusNotFound}
	}
	f.updates++
	page := fakeCustomPageFromInput(id, input, f.warnings)
	f.pages[id] = page
	return page, nil
}

func (f *fakeCustomPageCloudflare) GetAccessCustomPage(_ context.Context, id string) (flarecloudflare.AccessCustomPage, error) {
	page, found := f.pages[id]
	if !found {
		return flarecloudflare.AccessCustomPage{}, &cloudflaresdk.Error{StatusCode: http.StatusNotFound}
	}
	return page, nil
}

func (f *fakeCustomPageCloudflare) ListAccessCustomPages(context.Context) ([]flarecloudflare.AccessCustomPageSummary, error) {
	result := make([]flarecloudflare.AccessCustomPageSummary, 0, len(f.pages))
	for _, page := range f.pages {
		result = append(result, page.AccessCustomPageSummary)
	}
	return result, nil
}

func (f *fakeCustomPageCloudflare) DeleteAccessCustomPage(_ context.Context, id string) (string, error) {
	if _, found := f.pages[id]; !found {
		return "", &cloudflaresdk.Error{StatusCode: http.StatusNotFound}
	}
	delete(f.pages, id)
	return id, nil
}

func (f *fakeCustomPageCloudflare) ListAccessTags(context.Context) ([]flarecloudflare.AccessTag, error) {
	f.tagCalls = append(f.tagCalls, "ListTags")
	result := make([]flarecloudflare.AccessTag, 0, len(f.tags))
	for _, tag := range f.tags {
		result = append(result, tag)
	}
	return result, nil
}

func (f *fakeCustomPageCloudflare) GetAccessTag(_ context.Context, name string) (flarecloudflare.AccessTag, error) {
	f.tagCalls = append(f.tagCalls, "GetTag:"+name)
	tag, found := f.tags[name]
	if !found {
		return flarecloudflare.AccessTag{}, &cloudflaresdk.Error{StatusCode: http.StatusNotFound}
	}
	return tag, nil
}

func (f *fakeCustomPageCloudflare) CreateAccessTag(_ context.Context, name string) (flarecloudflare.AccessTag, error) {
	f.tagCalls = append(f.tagCalls, "CreateTag:"+name)
	if _, found := f.tags[name]; found {
		return flarecloudflare.AccessTag{}, &cloudflaresdk.Error{StatusCode: http.StatusConflict}
	}
	tag := flarecloudflare.AccessTag{Name: name}
	f.tags[name] = tag
	return tag, nil
}

func (f *fakeCustomPageCloudflare) UpdateAccessTag(_ context.Context, oldName, newName string) (flarecloudflare.AccessTag, error) {
	tag, found := f.tags[oldName]
	if !found {
		return flarecloudflare.AccessTag{}, &cloudflaresdk.Error{StatusCode: http.StatusNotFound}
	}
	delete(f.tags, oldName)
	tag.Name = newName
	f.tags[newName] = tag
	return tag, nil
}

func (f *fakeCustomPageCloudflare) DeleteAccessTag(_ context.Context, name string) error {
	delete(f.tags, name)
	return nil
}

func fakeCustomPageFromInput(id string, input flarecloudflare.AccessCustomPageInput, warnings []flarecloudflare.AccessCustomPageWarning) flarecloudflare.AccessCustomPage {
	contractVersion := int64(0)
	if input.ContractVersion != nil {
		contractVersion = *input.ContractVersion
	}
	return flarecloudflare.AccessCustomPage{
		AccessCustomPageSummary: flarecloudflare.AccessCustomPageSummary{
			ID: id, Name: input.Name, Type: input.Type, ContractVersion: contractVersion, Warnings: slices.Clone(warnings),
		},
		HTML: input.HTML,
	}
}

func TestAccessCustomPageOrphanDeletionRetainsRemotePage(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, time.September, 14, 12, 0, 0, 0, time.UTC)
	remote := newFakeCustomPageCloudflare()
	kube, reconciler, page := newCustomPageTestReconciler(t, remote, nil, clock)
	page.Spec.DeletionPolicy = v1alpha1.DeletionPolicyOrphan
	if err := kube.Create(ctx, page); err != nil {
		t.Fatal(err)
	}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(page)}

	reconcileCustomPage(ctx, t, reconciler, request, "add finalizer")
	reconcileCustomPage(ctx, t, reconciler, request, "create custom page")

	var current v1alpha1.AccessCustomPage
	if err := kube.Get(ctx, request.NamespacedName, &current); err != nil {
		t.Fatal(err)
	}
	pageID := current.Status.CustomPageID
	if pageID == "" || !current.Status.OwnershipVerified {
		t.Fatalf("custom page was not programmed: %#v", current.Status)
	}
	if err := kube.Delete(ctx, &current); err != nil {
		t.Fatal(err)
	}
	reconcileCustomPage(ctx, t, reconciler, request, "orphan custom page")
	if _, found := remote.pages[pageID]; !found {
		t.Fatal("Orphan deletion removed the remote custom page")
	}
	if err := kube.Get(ctx, request.NamespacedName, &v1alpha1.AccessCustomPage{}); !apierrors.IsNotFound(err) {
		t.Fatalf("orphaned AccessCustomPage still exists: %v", err)
	}
}
