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

package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
)

type gatewayAdapterCall struct {
	method string
	path   string
	body   any
}

func TestGatewayAdaptersUseTypedRulesAndWholeListReplacement(t *testing.T) {
	var mu sync.Mutex
	var calls []gatewayAdapterCall
	listCleared := false
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body any
		if request.Body != nil {
			_ = json.NewDecoder(request.Body).Decode(&body)
		}
		mu.Lock()
		calls = append(calls, gatewayAdapterCall{method: request.Method, path: request.URL.Path, body: body})
		mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.URL.Path == "/accounts/account/gateway/rules" && request.Method == http.MethodPost:
			if _, err := fmt.Fprint(response, gatewayRuleEnvelope); err != nil {
				t.Error(err)
			}
		case request.URL.Path == "/accounts/account/gateway/rules/rule-id" && request.Method == http.MethodPut:
			if _, err := fmt.Fprint(response, gatewayRuleEnvelope); err != nil {
				t.Error(err)
			}
		case request.URL.Path == "/accounts/account/gateway/rules/rule-id" && request.Method == http.MethodGet:
			if _, err := fmt.Fprint(response, gatewayRuleEnvelope); err != nil {
				t.Error(err)
			}
		case request.URL.Path == "/accounts/account/gateway/rules/rule-id" && request.Method == http.MethodDelete:
			if _, err := fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":null}`); err != nil {
				t.Error(err)
			}
		case request.URL.Path == "/accounts/account/gateway/lists" && request.Method == http.MethodPost:
			if _, err := fmt.Fprint(response, gatewayListNewEnvelope); err != nil {
				t.Error(err)
			}
		case request.URL.Path == "/accounts/account/gateway/lists/list-id" && request.Method == http.MethodPut:
			if _, err := fmt.Fprint(response, gatewayListEnvelope); err != nil {
				t.Error(err)
			}
		case request.URL.Path == "/accounts/account/gateway/lists/list-id" && request.Method == http.MethodPatch:
			listCleared = true
			if _, err := fmt.Fprint(response, gatewayListEmptyEnvelope); err != nil {
				t.Error(err)
			}
		case request.URL.Path == "/accounts/account/gateway/lists/list-id" && request.Method == http.MethodGet:
			if listCleared {
				if _, err := fmt.Fprint(response, gatewayListEmptyEnvelope); err != nil {
					t.Error(err)
				}
			} else {
				if _, err := fmt.Fprint(response, gatewayListEnvelope); err != nil {
					t.Error(err)
				}
			}
		case request.URL.Path == "/accounts/account/gateway/lists/list-id/items" && request.Method == http.MethodGet:
			if listCleared {
				if _, err := fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"page":1,"per_page":100,"count":0,"total_count":0,"total_pages":1}}`); err != nil {
					t.Error(err)
				}
			} else {
				if _, err := fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":[{"value":"203.0.113.0/24","description":"egress"}],"result_info":{"page":1,"per_page":100,"count":1,"total_count":1,"total_pages":1}}`); err != nil {
					t.Error(err)
				}
			}
		case request.URL.Path == "/accounts/account/gateway/lists/list-id" && request.Method == http.MethodDelete:
			if _, err := fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":null}`); err != nil {
				t.Error(err)
			}
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)

	client := New("token", "account", logr.Discard(), WithBaseURL(server.URL), WithLimiter(rate.NewLimiter(rate.Inf, 0)), WithListLimiter(rate.NewLimiter(rate.Inf, 0)))
	ctx := context.Background()
	falseValue := false
	enforce := true
	duration := "8h"
	rule, err := client.CreateGatewayRule(ctx, GatewayRuleInput{
		Name: "private", Enabled: &falseValue, Filters: []GatewayRuleFilter{GatewayRuleFilterL4}, Action: "allow", Traffic: "net.dst.ip in {10.0.0.0/8}",
		RuleSettings: &GatewayRuleSettings{CheckSession: &GatewayRuleCheckSession{Enforce: &enforce, Duration: &duration}},
	})
	if err != nil || rule.ID != "rule-id" || rule.Enabled {
		t.Fatalf("CreateGatewayRule() = %#v, %v", rule, err)
	}
	if _, err = client.UpdateGatewayRule(ctx, "rule-id", GatewayRuleInput{Name: "private", Filters: []GatewayRuleFilter{GatewayRuleFilterL4}, Action: "allow", Traffic: "net.dst.ip in {10.0.0.0/8}"}); err != nil {
		t.Fatal(err)
	}
	if _, err = client.GetGatewayRule(ctx, "rule-id"); err != nil {
		t.Fatal(err)
	}
	if err = client.DeleteGatewayRule(ctx, "rule-id"); err != nil {
		t.Fatal(err)
	}

	list, err := client.CreateGatewayList(ctx, GatewayListInput{Name: "trusted-egress", Type: GatewayListTypeIP, Items: []GatewayListItem{{Value: "203.0.113.0/24", Description: "egress"}}})
	if err != nil || list.ID != "list-id" || list.Type != GatewayListTypeIP {
		t.Fatalf("CreateGatewayList() = %#v, %v", list, err)
	}
	if _, err = client.UpdateGatewayList(ctx, "list-id", "trusted-egress"); err != nil {
		t.Fatal(err)
	}
	replaced, err := client.ReplaceGatewayListItems(ctx, "list-id", "trusted-egress", []GatewayListItem{})
	if err != nil || len(replaced.Items) != 0 {
		t.Fatalf("ReplaceGatewayListItems() = %#v, %v", replaced, err)
	}
	got, err := client.GetGatewayList(ctx, "list-id")
	if err != nil || len(got.Items) != 0 {
		t.Fatalf("GetGatewayList() = %#v, %v", got, err)
	}
	if err = client.DeleteGatewayList(ctx, "list-id"); err != nil {
		t.Fatal(err)
	}

	ruleBody := findGatewayCall(t, calls, http.MethodPost, "/accounts/account/gateway/rules")
	assertJSONKeys(t, ruleBody, map[string]any{"enabled": false, "filters": []any{"l4"}, "action": "allow", "traffic": "net.dst.ip in {10.0.0.0/8}"}, []string{"identity", "device_posture", "precedence"})
	nameOnlyBody := findGatewayCall(t, calls, http.MethodPut, "/accounts/account/gateway/lists/list-id")
	assertJSONKeys(t, nameOnlyBody, map[string]any{"name": "trusted-egress"}, []string{"items"})
	clearBody := findGatewayCall(t, calls, http.MethodPatch, "/accounts/account/gateway/lists/list-id")
	assertJSONKeys(t, clearBody, map[string]any{"remove": []any{"203.0.113.0/24"}}, []string{"append"})
}

func findGatewayCall(t *testing.T, calls []gatewayAdapterCall, method, path string) any {
	t.Helper()
	return findNthGatewayCall(t, calls, method, path, 0)
}

func findNthGatewayCall(t *testing.T, calls []gatewayAdapterCall, method, path string, ordinal int) any {
	t.Helper()
	for _, call := range calls {
		if call.method == method && call.path == path {
			if ordinal == 0 {
				return call.body
			}
			ordinal--
		}
	}
	t.Fatalf("missing requested %s %s call; calls = %#v", method, path, calls)
	return nil
}

const gatewayRuleEnvelope = `{"success":true,"errors":[],"messages":[],"result":{"id":"rule-id","name":"private","description":"","enabled":false,"precedence":100,"filters":["l4"],"action":"allow","traffic":"net.dst.ip in {10.0.0.0/8}","identity":"","device_posture":"","rule_settings":{"check_session":{"enforce":true,"duration":"8h"}},"read_only":false,"version":1}}`
const gatewayListNewEnvelope = `{"success":true,"errors":[],"messages":[],"result":{"id":"list-id","name":"trusted-egress","type":"IP","items":[{"value":"203.0.113.0/24","description":"egress"}]}}`
const gatewayListEnvelope = `{"success":true,"errors":[],"messages":[],"result":{"id":"list-id","name":"trusted-egress","type":"IP","count":1,"items":[{"value":"203.0.113.0/24","description":"egress"}]}}`
const gatewayListEmptyEnvelope = `{"success":true,"errors":[],"messages":[],"result":{"id":"list-id","name":"trusted-egress","type":"IP","count":0,"items":[]}}`
