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
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

func TestIdentityProviderCloudflareProviderParity(t *testing.T) {
	trueValue, falseValue := true, false
	maxURL := int64(4096)
	samlConfig := v1alpha1.IdentityProviderConfig{
		Attributes:         []string{"department"},
		EmailAttributeName: "mail",
		EnableEncryption:   &trueValue,
		ForceAuthn:         &falseValue,
		HeaderAttributes:   []v1alpha1.IdentityProviderSAMLHeaderAttribute{{Name: "X-Department", AttributeName: "department"}},
		IDPPublicCerts:     []string{"certificate"},
		IssuerURL:          "https://idp.example/issuer",
		MaxSSOURLLength:    &maxURL,
		SignRequest:        &trueValue,
		SSOTargetURL:       "https://idp.example/sso",
	}
	tests := []struct {
		providerType v1alpha1.IdentityProviderType
		wireType     string
		config       v1alpha1.IdentityProviderConfig
		keys         []string
		verify       func(*testing.T, flarecloudflare.IdentityProvider)
	}{
		{v1alpha1.IdentityProviderTypeOneTimePIN, "onetimepin", v1alpha1.IdentityProviderConfig{}, []string{}, nil},
		{v1alpha1.IdentityProviderTypeAzureAD, "azureAD", v1alpha1.IdentityProviderConfig{Claims: []string{"groups"}, ClientID: "client", DirectoryID: "directory", EmailClaimName: "email", ConditionalAccessEnabled: &falseValue, SupportGroups: &trueValue, Prompt: v1alpha1.IdentityProviderPromptLogin}, []string{"claims", "client_id", "client_secret", "conditional_access_enabled", "directory_id", "email_claim_name", "prompt", "support_groups"}, func(t *testing.T, got flarecloudflare.IdentityProvider) {
			if got.Config.DirectoryID != "directory" || got.Config.Prompt != v1alpha1.IdentityProviderPromptLogin || got.Config.ConditionalAccessEnabled == nil || *got.Config.ConditionalAccessEnabled {
				t.Fatalf("AzureAD config = %#v", got.Config)
			}
		}},
		{v1alpha1.IdentityProviderTypeSAML, "saml", samlConfig, []string{"attributes", "email_attribute_name", "enable_encryption", "force_authn", "header_attributes", "idp_public_certs", "issuer_url", "max_sso_url_length", "sign_request", "sso_target_url"}, func(t *testing.T, got flarecloudflare.IdentityProvider) {
			if !reflect.DeepEqual(got.Config, samlConfig) {
				t.Fatalf("SAML config = %#v, want %#v", got.Config, samlConfig)
			}
			if got.SAMLCertificateSetID != "certificate-set" {
				t.Fatalf("SAML certificate set ID = %q", got.SAMLCertificateSetID)
			}
		}},
		{v1alpha1.IdentityProviderTypeCentrify, "centrify", v1alpha1.IdentityProviderConfig{CentrifyAccount: "tenant.centrify.com", CentrifyAppID: "app", Claims: []string{"groups"}, ClientID: "client", EmailClaimName: "email"}, []string{"centrify_account", "centrify_app_id", "claims", "client_id", "client_secret", "email_claim_name"}, nil},
		{v1alpha1.IdentityProviderTypeFacebook, "facebook", v1alpha1.IdentityProviderConfig{ClientID: "client"}, []string{"client_id", "client_secret"}, nil},
		{v1alpha1.IdentityProviderTypeGitHub, "github", v1alpha1.IdentityProviderConfig{ClientID: "client"}, []string{"client_id", "client_secret"}, nil},
		{v1alpha1.IdentityProviderTypeGoogleApps, "google-apps", v1alpha1.IdentityProviderConfig{AppsDomain: "example.com", Claims: []string{"groups"}, ClientID: "client", EmailClaimName: "email", Prompt: v1alpha1.IdentityProviderPromptSelectAccount}, []string{"apps_domain", "claims", "client_id", "client_secret", "email_claim_name", "prompt"}, nil},
		{v1alpha1.IdentityProviderTypeGoogle, "google", v1alpha1.IdentityProviderConfig{Claims: []string{"groups"}, ClientID: "client", EmailClaimName: "email"}, []string{"claims", "client_id", "client_secret", "email_claim_name"}, nil},
		{v1alpha1.IdentityProviderTypeLinkedIn, "linkedin", v1alpha1.IdentityProviderConfig{ClientID: "client"}, []string{"client_id", "client_secret"}, nil},
		{v1alpha1.IdentityProviderTypeOIDC, "oidc", v1alpha1.IdentityProviderConfig{AuthURL: "https://idp.example/auth", CertsURL: "https://idp.example/certs", Claims: []string{"groups"}, ClientID: "client", EmailClaimName: "email", PKCEEnabled: &falseValue, Scopes: []string{"openid", "email"}, TokenURL: "https://idp.example/token"}, []string{"auth_url", "certs_url", "claims", "client_id", "client_secret", "email_claim_name", "pkce_enabled", "scopes", "token_url"}, nil},
		{v1alpha1.IdentityProviderTypeOkta, "okta", v1alpha1.IdentityProviderConfig{AuthorizationServerID: "default", Claims: []string{"groups"}, ClientID: "client", EmailClaimName: "email", OktaAccount: "example.okta.com"}, []string{"authorization_server_id", "claims", "client_id", "client_secret", "email_claim_name", "okta_account"}, nil},
		{v1alpha1.IdentityProviderTypeOneLogin, "onelogin", v1alpha1.IdentityProviderConfig{Claims: []string{"groups"}, ClientID: "client", EmailClaimName: "email", OneloginAccount: "example.onelogin.com"}, []string{"claims", "client_id", "client_secret", "email_claim_name", "onelogin_account"}, nil},
		{v1alpha1.IdentityProviderTypePingOne, "pingone", v1alpha1.IdentityProviderConfig{Claims: []string{"groups"}, ClientID: "client", EmailClaimName: "email", PingEnvironmentID: "environment"}, []string{"claims", "client_id", "client_secret", "email_claim_name", "ping_env_id"}, nil},
		{v1alpha1.IdentityProviderTypeYandex, "yandex", v1alpha1.IdentityProviderConfig{ClientID: "client"}, []string{"client_id", "client_secret"}, nil},
		{v1alpha1.IdentityProviderTypeCloudflare, "cloudflare", v1alpha1.IdentityProviderConfig{RestrictToAccountMembers: &falseValue}, []string{"restrict_to_account_members"}, func(t *testing.T, got flarecloudflare.IdentityProvider) {
			if !got.ReadOnly || got.Config.RestrictToAccountMembers == nil || *got.Config.RestrictToAccountMembers {
				t.Fatalf("Cloudflare provider = %#v", got)
			}
		}},
	}

	call := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/accounts/account/access/identity_providers" {
			http.NotFound(response, request)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if call >= len(tests) {
			t.Errorf("unexpected request %d", call)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		test := tests[call]
		call++
		if body["type"] != test.wireType {
			t.Errorf("type = %#v, want %q", body["type"], test.wireType)
		}
		config, ok := body["config"].(map[string]any)
		if !ok {
			t.Errorf("config = %#v", body["config"])
			config = map[string]any{}
		}
		if got := sortedMapKeys(config); !reflect.DeepEqual(got, test.keys) {
			t.Errorf("%s config keys = %v, want %v", test.providerType, got, test.keys)
		}
		for key, value := range config {
			if text, ok := value.(string); ok && text == "" {
				t.Errorf("%s config serialized empty %q", test.providerType, key)
			}
		}
		if _, exists := body["scim_config"]; exists {
			t.Errorf("%s serialized an empty SCIM block", test.providerType)
		}
		config["redirect_url"] = "https://example.cloudflareaccess.com/cdn-cgi/access/login"
		body["id"] = fmt.Sprintf("id-%d", call)
		body["read_only"] = test.providerType == v1alpha1.IdentityProviderTypeCloudflare
		if test.providerType == v1alpha1.IdentityProviderTypeSAML {
			body["saml_certificate_set"] = map[string]any{
				"uid": "certificate-set", "created_at": "2026-09-14T00:00:00Z", "updated_at": "2026-09-14T00:00:00Z",
				"current_certificate":  map[string]any{"uid": "certificate", "is_current": true, "not_after": "2027-09-14T00:00:00Z", "public_certificate": "PUBLIC"},
				"previous_certificate": nil,
			}
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": body})
	}))
	defer server.Close()

	api := flarecloudflare.New("token", "account", logr.Discard(), flarecloudflare.WithBaseURL(server.URL), flarecloudflare.WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	for _, test := range tests {
		input := flarecloudflare.IdentityProviderInput{Name: "provider", Type: test.providerType, Config: test.config, ClientSecret: "client-secret"}
		if test.providerType == v1alpha1.IdentityProviderTypeSAML {
			input.SAMLCertificateSetID = "certificate-set"
		}
		got, err := api.CreateIdentityProvider(context.Background(), input)
		if err != nil {
			t.Fatalf("create %s: %v", test.providerType, err)
		}
		if got.Type != test.providerType || got.Name != input.Name {
			t.Fatalf("create %s returned %#v", test.providerType, got)
		}
		if !identityProviderConfigMatches(got.Config, test.config) {
			t.Fatalf("%s response config = %#v, want %#v", test.providerType, got.Config, test.config)
		}
		wantRedirectURL := ""
		switch test.providerType {
		case v1alpha1.IdentityProviderTypeOneTimePIN, v1alpha1.IdentityProviderTypeCloudflare:
			wantRedirectURL = "https://example.cloudflareaccess.com/cdn-cgi/access/login"
		}
		if got.RedirectURL != wantRedirectURL {
			t.Fatalf("%s response redirect URL = %q, want %q", test.providerType, got.RedirectURL, wantRedirectURL)
		}
		if test.verify != nil {
			test.verify(t, got)
		}
	}
	if call != len(tests) {
		t.Fatalf("requests = %d, want %d", call, len(tests))
	}
}

func TestIdentityProviderCloudflareRedirectURLReadParity(t *testing.T) {
	const redirectURL = "https://example.cloudflareaccess.com/cdn-cgi/access/login"
	providers := []map[string]any{
		{"id": "otp", "name": "otp", "type": "onetimepin", "config": map[string]any{"redirect_url": redirectURL}},
		{"id": "cloudflare", "name": "cloudflare", "type": "cloudflare", "read_only": true, "config": map[string]any{"redirect_url": redirectURL}},
		{"id": "oidc", "name": "oidc", "type": "oidc", "config": map[string]any{"redirect_url": redirectURL}},
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/accounts/account/access/identity_providers/"):
			id := strings.TrimPrefix(request.URL.Path, "/accounts/account/access/identity_providers/")
			for _, provider := range providers {
				if provider["id"] == id {
					_ = json.NewEncoder(response).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": provider})
					return
				}
			}
			http.NotFound(response, request)
		case request.Method == http.MethodGet && request.URL.Path == "/accounts/account/access/identity_providers":
			_ = json.NewEncoder(response).Encode(map[string]any{
				"success": true, "errors": []any{}, "messages": []any{}, "result": providers,
				"result_info": map[string]any{"page": 1, "per_page": len(providers), "count": len(providers), "total_count": len(providers), "total_pages": 1},
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	api := flarecloudflare.New("token", "account", logr.Discard(), flarecloudflare.WithBaseURL(server.URL), flarecloudflare.WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	for _, test := range []struct {
		id      string
		wantURL string
	}{
		{id: "otp", wantURL: redirectURL},
		{id: "cloudflare", wantURL: redirectURL},
		{id: "oidc"},
	} {
		got, err := api.GetIdentityProvider(context.Background(), test.id)
		if err != nil {
			t.Fatalf("get %s provider: %v", test.id, err)
		}
		if got.RedirectURL != test.wantURL {
			t.Fatalf("get %s redirect URL = %q, want %q", test.id, got.RedirectURL, test.wantURL)
		}
	}

	listed, err := api.ListIdentityProviders(context.Background())
	if err != nil {
		t.Fatalf("list identity providers: %v", err)
	}
	if len(listed) != len(providers) {
		t.Fatalf("listed providers = %d, want %d", len(listed), len(providers))
	}
	byID := make(map[string]flarecloudflare.IdentityProvider, len(listed))
	for _, provider := range listed {
		byID[provider.ID] = provider
	}
	if byID["otp"].RedirectURL != redirectURL || byID["cloudflare"].RedirectURL != redirectURL {
		t.Fatalf("listed redirect URLs: otp=%q cloudflare=%q", byID["otp"].RedirectURL, byID["cloudflare"].RedirectURL)
	}
	if byID["oidc"].RedirectURL != "" {
		t.Fatalf("listed OIDC redirect URL = %q, want omitted", byID["oidc"].RedirectURL)
	}
}

func TestIdentityProviderCloudflareRejectsNullResponseConfig(t *testing.T) {
	const clientSecret = "sensitive-client-secret"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		body["id"] = "id"
		body["config"] = nil
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": body})
	}))
	defer server.Close()

	api := flarecloudflare.New("token", "account", logr.Discard(), flarecloudflare.WithBaseURL(server.URL), flarecloudflare.WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	_, err := api.CreateIdentityProvider(context.Background(), flarecloudflare.IdentityProviderInput{
		Name:         "oidc",
		Type:         v1alpha1.IdentityProviderTypeOIDC,
		Config:       v1alpha1.IdentityProviderConfig{ClientID: "client"},
		ClientSecret: clientSecret,
	})
	if err == nil {
		t.Fatal("create OIDC provider with null response config succeeded")
	}
	if !strings.Contains(err.Error(), "decode created Access identity provider") || !strings.Contains(err.Error(), "oidc identity provider config is null") {
		t.Fatalf("create OIDC provider error = %v", err)
	}
	if strings.Contains(err.Error(), clientSecret) {
		t.Fatalf("create OIDC provider error exposed the client secret: %v", err)
	}
}

func TestIdentityProviderCloudflareSCIMParity(t *testing.T) {
	trueValue, falseValue := true, false
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		scim, ok := body["scim_config"].(map[string]any)
		if !ok {
			t.Errorf("scim_config = %#v", body["scim_config"])
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, found := scim["secretRef"]; found {
			t.Errorf("Kubernetes secretRef crossed the Cloudflare boundary")
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, found := scim["secret_ref"]; found {
			t.Errorf("Kubernetes secret_ref crossed the Cloudflare boundary")
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if got := sortedMapKeys(scim); !reflect.DeepEqual(got, []string{"enabled", "identity_update_behavior", "seat_deprovision", "user_deprovision"}) {
			t.Errorf("SCIM keys = %v", got)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		scim["scim_base_url"] = "https://example.cloudflareaccess.com/scim/v2"
		scim["secret"] = "one-time-secret"
		body["id"] = "idp"
		body["read_only"] = false
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": body})
	}))
	defer server.Close()
	api := flarecloudflare.New("token", "account", logr.Discard(), flarecloudflare.WithBaseURL(server.URL), flarecloudflare.WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	got, err := api.CreateIdentityProvider(context.Background(), flarecloudflare.IdentityProviderInput{
		Name: "SCIM", Type: v1alpha1.IdentityProviderTypeAzureAD,
		Config: v1alpha1.IdentityProviderConfig{ClientID: "client"}, ClientSecret: "client-secret",
		SCIMConfig: &v1alpha1.IdentityProviderSCIMConfig{Enabled: &trueValue, IdentityUpdateBehavior: v1alpha1.IdentityProviderSCIMIdentityUpdateAutomatic, SeatDeprovision: &falseValue, UserDeprovision: &trueValue, SecretRef: &corev1.LocalObjectReference{Name: "scim"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.SCIMConfig == nil || got.SCIMConfig.Enabled == nil || !*got.SCIMConfig.Enabled || got.SCIMConfig.SecretRef != nil || got.SCIMBaseURL == "" || got.SCIMSecret != "one-time-secret" {
		t.Fatalf("SCIM response = %#v", got)
	}
}
func TestIdentityProviderCloudflareSAMLCertificateParity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/accounts/account/access/identity_providers/idp/saml_certificate" {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"success": true, "errors": []any{}, "messages": []any{},
			"result": map[string]any{
				"uid": "certificate-set", "created_at": "2026-09-14T00:00:00Z", "updated_at": "2026-09-14T00:00:00Z",
				"current_certificate":  map[string]any{"uid": "current", "is_current": true, "not_after": "2027-09-14T00:00:00Z", "public_certificate": "CURRENT"},
				"previous_certificate": map[string]any{"uid": "previous", "is_current": false, "not_after": "2026-10-14T00:00:00Z", "public_certificate": "PREVIOUS"},
			},
		})
	}))
	defer server.Close()
	api := flarecloudflare.New("token", "account", logr.Discard(), flarecloudflare.WithBaseURL(server.URL), flarecloudflare.WithLimiter(rate.NewLimiter(rate.Inf, 0)))
	got, err := api.CreateIdentityProviderSAMLCertificate(context.Background(), "idp")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "certificate-set" || got.Current == nil || got.Current.PublicCertificate != "CURRENT" || got.Previous == nil || got.Previous.PublicCertificate != "PREVIOUS" {
		t.Fatalf("certificate set = %#v", got)
	}
}

func sortedMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

type parityIdentityProviderCloudflare struct {
	flarecloudflare.AccessAPI
	providers           map[string]flarecloudflare.IdentityProvider
	next                int
	creates             int
	updates             int
	deletes             int
	certificates        int
	createErrAfterStore error
}

func newParityIdentityProviderCloudflare() *parityIdentityProviderCloudflare {
	return &parityIdentityProviderCloudflare{providers: make(map[string]flarecloudflare.IdentityProvider)}
}

func (f *parityIdentityProviderCloudflare) CreateIdentityProvider(_ context.Context, input flarecloudflare.IdentityProviderInput) (flarecloudflare.IdentityProvider, error) {
	f.next++
	f.creates++
	remote := parityIdentityProviderFromInput(fmt.Sprintf("idp-%d", f.next), input)
	stored := remote
	if identityProviderSCIMEnabled(input.SCIMConfig) {
		remote.SCIMSecret = "one-time-scim-secret"
		remote.SCIMBaseURL = "https://example.cloudflareaccess.com/scim/v2"
		stored.SCIMBaseURL = remote.SCIMBaseURL
	}
	f.providers[remote.ID] = stored
	if f.createErrAfterStore != nil {
		err := f.createErrAfterStore
		f.createErrAfterStore = nil
		return flarecloudflare.IdentityProvider{}, err
	}
	return remote, nil
}

func (f *parityIdentityProviderCloudflare) UpdateIdentityProvider(_ context.Context, id string, input flarecloudflare.IdentityProviderInput) (flarecloudflare.IdentityProvider, error) {
	previous, found := f.providers[id]
	if !found {
		return flarecloudflare.IdentityProvider{}, fmt.Errorf("identity provider %q not found", id)
	}
	f.updates++
	remote := parityIdentityProviderFromInput(id, input)
	remote.SAMLCertificateSet = previous.SAMLCertificateSet
	remote.SAMLCertificateSetID = input.SAMLCertificateSetID
	remote.SCIMBaseURL = previous.SCIMBaseURL
	if !identityProviderRemoteSCIMEnabled(previous.SCIMConfig) && identityProviderSCIMEnabled(input.SCIMConfig) {
		remote.SCIMSecret = "one-time-scim-secret"
		remote.SCIMBaseURL = "https://example.cloudflareaccess.com/scim/v2"
	}
	stored := remote
	stored.SCIMSecret = ""
	f.providers[id] = stored
	return remote, nil
}

func parityIdentityProviderFromInput(id string, input flarecloudflare.IdentityProviderInput) flarecloudflare.IdentityProvider {
	config := input.Config
	config.ClientSecretRef = nil
	var scim *v1alpha1.IdentityProviderSCIMConfig
	if input.SCIMConfig != nil {
		scimConfigCopy := *input.SCIMConfig
		scimConfigCopy.SecretRef = nil
		scim = &scimConfigCopy
	}
	remote := flarecloudflare.IdentityProvider{ID: id, Name: input.Name, Type: input.Type, Config: config, SCIMConfig: scim, SAMLCertificateSetID: input.SAMLCertificateSetID}
	switch input.Type {
	case v1alpha1.IdentityProviderTypeOneTimePIN, v1alpha1.IdentityProviderTypeCloudflare:
		remote.RedirectURL = "https://example.cloudflareaccess.com/cdn-cgi/access/login"
	}
	return remote
}

func (f *parityIdentityProviderCloudflare) GetIdentityProvider(_ context.Context, id string) (flarecloudflare.IdentityProvider, error) {
	remote, found := f.providers[id]
	if !found {
		return remote, fmt.Errorf("identity provider %q not found", id)
	}
	return remote, nil
}

func (f *parityIdentityProviderCloudflare) ListIdentityProviders(context.Context) ([]flarecloudflare.IdentityProvider, error) {
	result := make([]flarecloudflare.IdentityProvider, 0, len(f.providers))
	for _, remote := range f.providers {
		result = append(result, remote)
	}
	return result, nil
}

func (f *parityIdentityProviderCloudflare) DeleteIdentityProvider(_ context.Context, id string) error {
	f.deletes++
	delete(f.providers, id)
	return nil
}

func (f *parityIdentityProviderCloudflare) CreateIdentityProviderSAMLCertificate(_ context.Context, id string) (flarecloudflare.IdentityProviderSAMLCertificateSet, error) {
	remote, found := f.providers[id]
	if !found {
		return flarecloudflare.IdentityProviderSAMLCertificateSet{}, fmt.Errorf("identity provider %q not found", id)
	}
	f.certificates++
	certificate := flarecloudflare.IdentityProviderSAMLCertificateSet{ID: "certificate-set", Current: &flarecloudflare.IdentityProviderSAMLCertificate{ID: "certificate", Current: true, NotAfter: time.Date(2027, time.September, 14, 0, 0, 0, 0, time.UTC), PublicCertificate: "PUBLIC"}}
	remote.SAMLCertificateSetID = certificate.ID
	remote.SAMLCertificateSet = &certificate
	f.providers[id] = remote
	return certificate, nil
}

func (f *parityIdentityProviderCloudflare) ListIdentityProviderSCIMUsers(context.Context, string, int64) ([]flarecloudflare.IdentityProviderSCIMUser, bool, error) {
	users := make([]flarecloudflare.IdentityProviderSCIMUser, identityProviderSCIMLimit)
	for i := range users {
		users[i] = flarecloudflare.IdentityProviderSCIMUser{ID: fmt.Sprintf("user-%02d", i), ExternalID: fmt.Sprintf("external-user-%02d", i), DisplayName: fmt.Sprintf("User %02d", i), Active: true, Emails: []string{fmt.Sprintf("user-%02d@example.com", i)}}
	}
	return users, true, nil
}

func (f *parityIdentityProviderCloudflare) ListIdentityProviderSCIMGroups(context.Context, string, int64) ([]flarecloudflare.IdentityProviderSCIMGroup, bool, error) {
	groups := make([]flarecloudflare.IdentityProviderSCIMGroup, identityProviderSCIMLimit)
	for i := range groups {
		groups[i] = flarecloudflare.IdentityProviderSCIMGroup{ID: fmt.Sprintf("group-%02d", i), ExternalID: fmt.Sprintf("external-group-%02d", i), DisplayName: fmt.Sprintf("Group %02d", i)}
	}
	return groups, true, nil
}

func TestIdentityProviderReconcilerSAMLAndSCIMParity(t *testing.T) {
	trueValue := true
	api := newParityIdentityProviderCloudflare()
	saml := &v1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "saml", Namespace: "tenant", UID: types.UID("saml-uid"), Finalizers: []string{v1alpha1.IdentityProviderFinalizer}},
		Spec:       v1alpha1.IdentityProviderSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}, Name: "saml", Type: v1alpha1.IdentityProviderTypeSAML, Config: v1alpha1.IdentityProviderConfig{EnableEncryption: &trueValue, IssuerURL: "https://idp.example/issuer", SSOTargetURL: "https://idp.example/sso", IDPPublicCerts: []string{"IDP"}}, ManagementPolicy: v1alpha1.ManagementPolicyManaged},
	}
	scim := &v1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "scim", Namespace: "tenant", UID: types.UID("scim-uid"), Finalizers: []string{v1alpha1.IdentityProviderFinalizer}},
		Spec:       v1alpha1.IdentityProviderSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}, Name: "scim", Type: v1alpha1.IdentityProviderTypeAzureAD, Config: v1alpha1.IdentityProviderConfig{ClientID: "client"}, SCIMConfig: &v1alpha1.IdentityProviderSCIMConfig{Enabled: &trueValue, IdentityUpdateBehavior: v1alpha1.IdentityProviderSCIMIdentityUpdateAutomatic, SecretRef: &corev1.LocalObjectReference{Name: "scim-secret"}}, ManagementPolicy: v1alpha1.ManagementPolicyManaged},
	}
	reconciler, kube := newIdentityProviderParityReconciler(t, api, saml, scim)
	ctx := context.Background()
	for _, name := range []string{saml.Name, scim.Name} {
		if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "tenant", Name: name}}); err != nil {
			t.Fatalf("reconcile %s: %v", name, err)
		}
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "tenant", Name: scim.Name}}); err != nil {
		t.Fatalf("enable SCIM after identity checkpoint: %v", err)
	}
	if api.creates != 2 || api.certificates != 1 || api.updates != 2 {
		t.Fatalf("calls create=%d certificate=%d update=%d", api.creates, api.certificates, api.updates)
	}
	var observedSAML v1alpha1.IdentityProvider
	if err := kube.Get(ctx, client.ObjectKeyFromObject(saml), &observedSAML); err != nil {
		t.Fatal(err)
	}
	if observedSAML.Status.SAMLCertificateSet == nil || observedSAML.Status.SAMLCertificateSet.ID != "certificate-set" || observedSAML.Status.SAMLCertificateSet.Current == nil || observedSAML.Status.SAMLCertificateSet.Current.PublicCertificate != "PUBLIC" {
		t.Fatalf("SAML status = %#v", observedSAML.Status.SAMLCertificateSet)
	}
	var secret corev1.Secret
	if err := kube.Get(ctx, types.NamespacedName{Namespace: "tenant", Name: "scim-secret"}, &secret); err != nil {
		t.Fatal(err)
	}
	if string(secret.Data[v1alpha1.IdentityProviderSCIMSecretKey]) != "one-time-scim-secret" ||
		secret.Type != corev1.SecretTypeOpaque ||
		secret.Annotations[v1alpha1.IdentityProviderIDAnnotation] != "idp-2" ||
		len(secret.OwnerReferences) != 1 ||
		secret.OwnerReferences[0].APIVersion != v1alpha1.GroupVersion.String() ||
		secret.OwnerReferences[0].Kind != "IdentityProvider" ||
		secret.OwnerReferences[0].Name != scim.Name ||
		secret.OwnerReferences[0].UID != scim.UID ||
		secret.OwnerReferences[0].Controller == nil || !*secret.OwnerReferences[0].Controller ||
		secret.OwnerReferences[0].BlockOwnerDeletion == nil || !*secret.OwnerReferences[0].BlockOwnerDeletion {
		t.Fatalf("SCIM Secret = %#v", secret)
	}
	var observedSCIM v1alpha1.IdentityProvider
	if err := kube.Get(ctx, client.ObjectKeyFromObject(scim), &observedSCIM); err != nil {
		t.Fatal(err)
	}
	if observedSCIM.Status.SCIMDirectory == nil || len(observedSCIM.Status.SCIMDirectory.Users) != int(identityProviderSCIMLimit) || len(observedSCIM.Status.SCIMDirectory.Groups) != int(identityProviderSCIMLimit) || !observedSCIM.Status.SCIMDirectory.UsersTruncated || !observedSCIM.Status.SCIMDirectory.GroupsTruncated {
		t.Fatalf("SCIM directory status = %#v", observedSCIM.Status.SCIMDirectory)
	}
	statusJSON, err := json.Marshal(observedSCIM.Status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(statusJSON), "one-time-scim-secret") {
		t.Fatalf("SCIM secret leaked into status: %s", statusJSON)
	}
	updates := api.updates
	for _, name := range []string{saml.Name, scim.Name} {
		if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "tenant", Name: name}}); err != nil {
			t.Fatalf("reconcile converged %s: %v", name, err)
		}
	}
	if api.updates != updates {
		t.Fatalf("converged providers updated: before=%d after=%d", updates, api.updates)
	}
}

func TestIdentityProviderReconcilerSCIMUpdateRejectsUnownedEmptySecret(t *testing.T) {
	for _, test := range []struct {
		name            string
		ownerReferences []metav1.OwnerReference
	}{
		{name: "ownerless"},
		{name: "foreign", ownerReferences: []metav1.OwnerReference{foreignIdentityProviderControllerReference("other")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			trueValue := true
			api := newParityIdentityProviderCloudflare()
			api.providers["idp"] = flarecloudflare.IdentityProvider{
				ID: "idp", Name: "scim", Type: v1alpha1.IdentityProviderTypeAzureAD, Config: v1alpha1.IdentityProviderConfig{ClientID: "client"},
			}
			provider := newSCIMCaptureIdentityProvider("scim")
			provider.Spec.SCIMConfig.Enabled = &trueValue
			provider.Status.IDPID = "idp"
			provider.Status.OwnershipVerified = true
			reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
			ctx := context.Background()
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "scim-secret",
					Namespace:       "tenant",
					OwnerReferences: test.ownerReferences,
					Labels:          map[string]string{"unrelated": "kept"},
					Annotations:     map[string]string{"unrelated": "kept"},
				},
				Type: corev1.SecretType("example.com/unrelated"),
				Data: map[string][]byte{"unrelated": []byte("kept")},
			}
			if err := kube.Create(ctx, secret); err != nil {
				t.Fatal(err)
			}
			var before corev1.Secret
			if err := kube.Get(ctx, client.ObjectKeyFromObject(secret), &before); err != nil {
				t.Fatal(err)
			}

			_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)})
			if err == nil {
				t.Fatal("reconcile accepted an unowned empty SCIM Secret")
			}
			if strings.Contains(err.Error(), "one-time-scim-secret") {
				t.Fatalf("reconcile error exposed the SCIM secret: %v", err)
			}
			if api.updates != 0 {
				t.Fatalf("remote update calls = %d, want 0", api.updates)
			}
			var after corev1.Secret
			if err := kube.Get(ctx, client.ObjectKeyFromObject(secret), &after); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(after.OwnerReferences, before.OwnerReferences) ||
				!reflect.DeepEqual(after.Labels, before.Labels) ||
				!reflect.DeepEqual(after.Annotations, before.Annotations) ||
				!reflect.DeepEqual(after.Data, before.Data) ||
				after.Type != before.Type {
				t.Fatalf("unowned SCIM Secret was mutated:\nbefore=%#v\nafter=%#v", before, after)
			}

			after.OwnerReferences = nil
			if err := controllerutil.SetControllerReference(provider, &after, reconciler.Scheme); err != nil {
				t.Fatal(err)
			}
			if err := kube.Update(ctx, &after); err != nil {
				t.Fatal(err)
			}
			if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}); err != nil {
				t.Fatalf("reconcile after repairing Secret ownership: %v", err)
			}
			if api.updates != 1 {
				t.Fatalf("remote update calls after repair = %d, want 1", api.updates)
			}
			var repaired corev1.Secret
			if err := kube.Get(ctx, client.ObjectKeyFromObject(secret), &repaired); err != nil {
				t.Fatal(err)
			}
			if repaired.Type != before.Type ||
				repaired.Labels["unrelated"] != "kept" ||
				repaired.Annotations["unrelated"] != "kept" ||
				repaired.Annotations[v1alpha1.IdentityProviderIDAnnotation] != "idp" ||
				string(repaired.Data["unrelated"]) != "kept" ||
				string(repaired.Data[v1alpha1.IdentityProviderSCIMSecretKey]) != "one-time-scim-secret" {
				t.Fatalf("repaired SCIM Secret = %#v", repaired)
			}
		})
	}
}

func TestIdentityProviderReconcilerSCIMCreateRejectsUnownedEmptySecret(t *testing.T) {
	for _, test := range []struct {
		name            string
		ownerReferences []metav1.OwnerReference
	}{
		{name: "ownerless"},
		{name: "foreign", ownerReferences: []metav1.OwnerReference{foreignIdentityProviderControllerReference("other")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			trueValue := true
			api := newParityIdentityProviderCloudflare()
			provider := newSCIMCaptureIdentityProvider("scim")
			provider.Spec.SCIMConfig.Enabled = &trueValue
			reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
			ctx := context.Background()
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "scim-secret",
					Namespace:       "tenant",
					OwnerReferences: test.ownerReferences,
					Labels:          map[string]string{"unrelated": "kept"},
					Annotations:     map[string]string{"unrelated": "kept"},
				},
				Type: corev1.SecretType("example.com/unrelated"),
				Data: map[string][]byte{"unrelated": []byte("kept")},
			}
			if err := kube.Create(ctx, secret); err != nil {
				t.Fatal(err)
			}

			_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)})
			if err == nil {
				t.Fatal("reconcile accepted an unowned SCIM Secret destination")
			}
			if api.creates != 0 {
				t.Fatalf("remote create calls = %d, want 0", api.creates)
			}
			var repaired corev1.Secret
			if err := kube.Get(ctx, client.ObjectKeyFromObject(secret), &repaired); err != nil {
				t.Fatal(err)
			}
			repaired.OwnerReferences = nil
			if err := controllerutil.SetControllerReference(provider, &repaired, reconciler.Scheme); err != nil {
				t.Fatal(err)
			}
			if err := kube.Update(ctx, &repaired); err != nil {
				t.Fatal(err)
			}
			if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}); err != nil {
				t.Fatalf("reconcile after repairing Secret ownership: %v", err)
			}
			if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}); err != nil {
				t.Fatalf("enable SCIM after identity checkpoint: %v", err)
			}
			if api.creates != 1 {
				t.Fatalf("remote create calls after repair = %d, want 1", api.creates)
			}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(secret), &repaired); err != nil {
				t.Fatal(err)
			}
			if repaired.Type != corev1.SecretType("example.com/unrelated") ||
				repaired.Labels["unrelated"] != "kept" ||
				repaired.Annotations["unrelated"] != "kept" ||
				repaired.Annotations[v1alpha1.IdentityProviderIDAnnotation] != "idp-1" ||
				string(repaired.Data["unrelated"]) != "kept" ||
				string(repaired.Data[v1alpha1.IdentityProviderSCIMSecretKey]) != "one-time-scim-secret" {
				t.Fatalf("repaired SCIM Secret = %#v", repaired)
			}
		})
	}
}

func TestIdentityProviderReconcilerSCIMCreateRejectsForeignReservationCollision(t *testing.T) {
	trueValue := true
	api := newParityIdentityProviderCloudflare()
	provider := newSCIMCaptureIdentityProvider("scim")
	provider.Spec.SCIMConfig.Enabled = &trueValue
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	collision := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            provider.Spec.SCIMConfig.SecretRef.Name,
			Namespace:       provider.Namespace,
			OwnerReferences: []metav1.OwnerReference{foreignIdentityProviderControllerReference("other")},
		},
	}
	racingClient := &identityProviderSCIMCreateCollisionClient{Client: kube, collision: collision}
	reconciler.Client = racingClient

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)})
	if err == nil {
		t.Fatal("reconcile accepted a foreign Secret that won the reservation race")
	}
	if !racingClient.collided {
		t.Fatal("reconcile did not exercise the reservation collision")
	}
	if api.creates != 0 {
		t.Fatalf("remote create calls = %d, want 0", api.creates)
	}
}

func TestIdentityProviderReconcilerSCIMCaptureFailureDisablesAndRetriesWithoutDuplicate(t *testing.T) {
	trueValue := true
	api := newParityIdentityProviderCloudflare()
	provider := newSCIMCaptureIdentityProvider("scim")
	provider.Spec.SCIMConfig.Enabled = &trueValue
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	ctx := context.Background()
	failingClient := &identityProviderSCIMCaptureFailureClient{
		Client: kube,
		key:    types.NamespacedName{Namespace: provider.Namespace, Name: provider.Spec.SCIMConfig.SecretRef.Name},
		fail:   true,
	}
	reconciler.Client = failingClient

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}); err != nil {
		t.Fatalf("create disabled provider and checkpoint identity: %v", err)
	}
	if identityProviderRemoteSCIMEnabled(api.providers["idp-1"].SCIMConfig) {
		t.Fatalf("new remote provider was created with SCIM enabled: %#v", api.providers["idp-1"].SCIMConfig)
	}
	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)})
	if err == nil {
		t.Fatal("reconcile unexpectedly captured the SCIM credential")
	}
	if strings.Contains(err.Error(), "one-time-scim-secret") {
		t.Fatalf("capture failure exposed the SCIM credential: %v", err)
	}
	if api.creates != 1 || api.updates != 2 || failingClient.failures == 0 {
		t.Fatalf("after compensation create=%d update=%d captureFailures=%d", api.creates, api.updates, failingClient.failures)
	}
	if identityProviderRemoteSCIMEnabled(api.providers["idp-1"].SCIMConfig) {
		t.Fatalf("failed capture left remote SCIM enabled: %#v", api.providers["idp-1"].SCIMConfig)
	}
	var checkpointed v1alpha1.IdentityProvider
	if err := kube.Get(ctx, client.ObjectKeyFromObject(provider), &checkpointed); err != nil {
		t.Fatal(err)
	}
	if checkpointed.Status.IDPID != "idp-1" || !checkpointed.Status.OwnershipVerified {
		t.Fatalf("remote identity was not checkpointed before SCIM enable: %#v", checkpointed.Status)
	}

	failingClient.fail = false
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	if api.creates != 1 || len(api.providers) != 1 {
		t.Fatalf("retry duplicated remote provider: creates=%d providers=%d", api.creates, len(api.providers))
	}
	var secret corev1.Secret
	if err := kube.Get(ctx, failingClient.key, &secret); err != nil {
		t.Fatal(err)
	}
	if secret.Annotations[v1alpha1.IdentityProviderIDAnnotation] != "idp-1" ||
		string(secret.Data[v1alpha1.IdentityProviderSCIMSecretKey]) != "one-time-scim-secret" {
		t.Fatalf("retry did not capture replacement credential: %#v", secret)
	}
	statusJSON, err := json.Marshal(checkpointed.Status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(statusJSON), "one-time-scim-secret") {
		t.Fatalf("SCIM credential leaked into checkpoint status: %s", statusJSON)
	}
}

func TestIdentityProviderReconcilerSCIMRecoversAmbiguousCreateByJournaledName(t *testing.T) {
	trueValue := true
	api := newParityIdentityProviderCloudflare()
	api.createErrAfterStore = fmt.Errorf("injected ambiguous create response")
	provider := newSCIMCaptureIdentityProvider("scim")
	provider.Spec.SCIMConfig.Enabled = &trueValue
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	ctx := context.Background()
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}

	if _, err := reconciler.Reconcile(ctx, request); err == nil {
		t.Fatal("reconcile unexpectedly received the created provider identity")
	}
	if api.creates != 1 || len(api.providers) != 1 {
		t.Fatalf("ambiguous create calls=%d providers=%d", api.creates, len(api.providers))
	}
	var journal corev1.Secret
	if err := kube.Get(ctx, types.NamespacedName{Namespace: provider.Namespace, Name: provider.Spec.SCIMConfig.SecretRef.Name}, &journal); err != nil {
		t.Fatal(err)
	}
	pendingName := journal.Annotations[identityProviderSCIMCreateIntentAnnotation]
	pending := api.providers["idp-1"]
	if !strings.HasPrefix(pendingName, identityProviderSCIMPendingRemoteNamePrefix) ||
		journal.Annotations[identityProviderSCIMCreateStateAnnotation] != identityProviderSCIMCreateIssued ||
		pending.Name != pendingName ||
		identityProviderRemoteSCIMEnabled(pending.SCIMConfig) {
		t.Fatalf("ambiguous remote provider = %#v, journal = %#v", pending, journal.Annotations)
	}
	var uncheckpointed v1alpha1.IdentityProvider
	if err := kube.Get(ctx, client.ObjectKeyFromObject(provider), &uncheckpointed); err != nil {
		t.Fatal(err)
	}
	if uncheckpointed.Status.IDPID != "" || uncheckpointed.Status.OwnershipVerified {
		t.Fatalf("ambiguous create unexpectedly checkpointed status: %#v", uncheckpointed.Status)
	}

	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("recover journaled create: %v", err)
	}
	if api.creates != 1 || len(api.providers) != 1 {
		t.Fatalf("journal recovery duplicated remote provider: creates=%d providers=%d", api.creates, len(api.providers))
	}
	var checkpointed v1alpha1.IdentityProvider
	if err := kube.Get(ctx, client.ObjectKeyFromObject(provider), &checkpointed); err != nil {
		t.Fatal(err)
	}
	if checkpointed.Status.IDPID != "idp-1" || !checkpointed.Status.OwnershipVerified {
		t.Fatalf("journal recovery checkpoint = %#v", checkpointed.Status)
	}

	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("enable recovered provider: %v", err)
	}
	if api.creates != 1 || len(api.providers) != 1 {
		t.Fatalf("enable after recovery duplicated remote provider: creates=%d providers=%d", api.creates, len(api.providers))
	}
	var secret corev1.Secret
	if err := kube.Get(ctx, types.NamespacedName{Namespace: provider.Namespace, Name: provider.Spec.SCIMConfig.SecretRef.Name}, &secret); err != nil {
		t.Fatal(err)
	}
	if secret.Annotations[identityProviderSCIMCreateIntentAnnotation] != "" ||
		secret.Annotations[identityProviderSCIMCreateStateAnnotation] != "" ||
		secret.Annotations[v1alpha1.IdentityProviderIDAnnotation] != "idp-1" ||
		string(secret.Data[v1alpha1.IdentityProviderSCIMSecretKey]) != "one-time-scim-secret" {
		t.Fatalf("recovered SCIM Secret = %#v", secret)
	}
}

func TestIdentityProviderReconcilerSCIMDisabledAfterAmbiguousCreateRecoversWithoutDuplicate(t *testing.T) {
	trueValue, falseValue := true, false
	api := newParityIdentityProviderCloudflare()
	api.createErrAfterStore = fmt.Errorf("injected ambiguous create response")
	provider := newSCIMCaptureIdentityProvider("scim")
	provider.Spec.SCIMConfig.Enabled = &trueValue
	provider.Spec.DeletionPolicy = v1alpha1.DeletionPolicyDelete
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	ctx := context.Background()
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}

	if _, err := reconciler.Reconcile(ctx, request); err == nil {
		t.Fatal("reconcile unexpectedly checkpointed ambiguous create")
	}
	var disabled v1alpha1.IdentityProvider
	if err := kube.Get(ctx, client.ObjectKeyFromObject(provider), &disabled); err != nil {
		t.Fatal(err)
	}
	disabled.Spec.SCIMConfig.Enabled = &falseValue
	if err := kube.Update(ctx, &disabled); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("recover disabled ambiguous create: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("converge disabled recovered provider: %v", err)
	}
	if api.creates != 1 || len(api.providers) != 1 {
		t.Fatalf("disabled recovery duplicated remote provider: creates=%d providers=%d", api.creates, len(api.providers))
	}
	var recovered v1alpha1.IdentityProvider
	if err := kube.Get(ctx, client.ObjectKeyFromObject(provider), &recovered); err != nil {
		t.Fatal(err)
	}
	if recovered.Status.IDPID != "idp-1" || !recovered.Status.OwnershipVerified {
		t.Fatalf("disabled recovery status = %#v", recovered.Status)
	}
	if identityProviderRemoteSCIMEnabled(api.providers["idp-1"].SCIMConfig) {
		t.Fatalf("disabled recovery enabled SCIM: %#v", api.providers["idp-1"].SCIMConfig)
	}
	if err := reconciler.reconcileDelete(ctx, &recovered); err != nil {
		t.Fatal(err)
	}
	if api.deletes != 1 || len(api.providers) != 0 {
		t.Fatalf("disabled recovered delete calls=%d providers=%d", api.deletes, len(api.providers))
	}
}

func TestIdentityProviderReconcilerSCIMPreparedJournalConflictStaysRejected(t *testing.T) {
	trueValue := true
	api := newParityIdentityProviderCloudflare()
	provider := newSCIMCaptureIdentityProvider("scim")
	provider.Spec.SCIMConfig.Enabled = &trueValue
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	pendingName := identityProviderSCIMPendingRemoteNamePrefix + "preexisting"
	secret := ownedSCIMSecret(t, reconciler, provider)
	secret.Annotations = map[string]string{
		identityProviderSCIMCreateIntentAnnotation: pendingName,
		identityProviderSCIMCreateStateAnnotation:  identityProviderSCIMCreatePrepared,
	}
	if err := kube.Create(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	input := flarecloudflare.IdentityProviderInput{
		Name:       pendingName,
		Type:       provider.Spec.Type,
		Config:     provider.Spec.Config,
		SCIMConfig: provider.Spec.SCIMConfig,
	}
	api.providers["foreign"] = parityIdentityProviderFromInput("foreign", identityProviderInputWithSCIMEnabled(input, false))
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}

	for attempt := range 2 {
		if _, err := reconciler.Reconcile(context.Background(), request); err == nil {
			t.Fatalf("reconcile attempt %d adopted pre-existing marker occupancy", attempt+1)
		}
	}
	if api.creates != 0 || api.updates != 0 || api.deletes != 0 {
		t.Fatalf("pre-existing marker provider was mutated: create=%d update=%d delete=%d", api.creates, api.updates, api.deletes)
	}
	var conflicted corev1.Secret
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(secret), &conflicted); err != nil {
		t.Fatal(err)
	}
	if conflicted.Annotations[identityProviderSCIMCreateStateAnnotation] != identityProviderSCIMCreateConflict {
		t.Fatalf("create journal state = %q, want conflict", conflicted.Annotations[identityProviderSCIMCreateStateAnnotation])
	}
}

func TestIdentityProviderReconcilerSCIMIssuedJournalRejectsMultipleRemotes(t *testing.T) {
	trueValue := true
	api := newParityIdentityProviderCloudflare()
	provider := newSCIMCaptureIdentityProvider("scim")
	provider.Spec.SCIMConfig.Enabled = &trueValue
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	pendingName := identityProviderSCIMPendingRemoteNamePrefix + "issued"
	secret := ownedSCIMSecret(t, reconciler, provider)
	secret.Annotations = map[string]string{
		identityProviderSCIMCreateIntentAnnotation: pendingName,
		identityProviderSCIMCreateStateAnnotation:  identityProviderSCIMCreateIssued,
	}
	if err := kube.Create(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	input := identityProviderInputWithSCIMEnabled(flarecloudflare.IdentityProviderInput{
		Name:       pendingName,
		Type:       provider.Spec.Type,
		Config:     provider.Spec.Config,
		SCIMConfig: provider.Spec.SCIMConfig,
	}, false)
	api.providers["first"] = parityIdentityProviderFromInput("first", input)
	api.providers["second"] = parityIdentityProviderFromInput("second", input)

	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}); err == nil {
		t.Fatal("reconcile accepted multiple remotes for one issued create journal")
	}
	if api.creates != 0 || api.updates != 0 || api.deletes != 0 {
		t.Fatalf("ambiguous issued remotes were mutated: create=%d update=%d delete=%d", api.creates, api.updates, api.deletes)
	}
}

func TestIdentityProviderReconcilerSCIMJournalSurvivesSecretRefRemovalOrChange(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*v1alpha1.IdentityProvider)
	}{
		{
			name: "remove",
			mutate: func(provider *v1alpha1.IdentityProvider) {
				provider.Spec.SCIMConfig = nil
			},
		},
		{
			name: "change",
			mutate: func(provider *v1alpha1.IdentityProvider) {
				falseValue := false
				provider.Spec.SCIMConfig.Enabled = &falseValue
				provider.Spec.SCIMConfig.SecretRef = &corev1.LocalObjectReference{Name: "replacement-scim-secret"}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			trueValue := true
			api := newParityIdentityProviderCloudflare()
			api.createErrAfterStore = fmt.Errorf("injected ambiguous create response")
			provider := newSCIMCaptureIdentityProvider("scim")
			provider.Spec.SCIMConfig.Enabled = &trueValue
			provider.Spec.DeletionPolicy = v1alpha1.DeletionPolicyDelete
			reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
			ctx := context.Background()
			request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}

			if _, err := reconciler.Reconcile(ctx, request); err == nil {
				t.Fatal("reconcile unexpectedly checkpointed ambiguous create")
			}
			var changed v1alpha1.IdentityProvider
			if err := kube.Get(ctx, client.ObjectKeyFromObject(provider), &changed); err != nil {
				t.Fatal(err)
			}
			test.mutate(&changed)
			if err := kube.Update(ctx, &changed); err != nil {
				t.Fatal(err)
			}
			if _, err := reconciler.Reconcile(ctx, request); err != nil {
				t.Fatalf("recover journal after spec mutation: %v", err)
			}
			if _, err := reconciler.Reconcile(ctx, request); err != nil {
				t.Fatalf("converge recovered provider: %v", err)
			}
			if api.creates != 1 || len(api.providers) != 1 {
				t.Fatalf("spec mutation duplicated remote provider: creates=%d providers=%d", api.creates, len(api.providers))
			}
			var deleting v1alpha1.IdentityProvider
			if err := kube.Get(ctx, client.ObjectKeyFromObject(provider), &deleting); err != nil {
				t.Fatal(err)
			}
			if deleting.Status.IDPID != "idp-1" || !deleting.Status.OwnershipVerified {
				t.Fatalf("recovered status = %#v", deleting.Status)
			}
			if err := reconciler.reconcileDelete(ctx, &deleting); err != nil {
				t.Fatal(err)
			}
			if api.deletes != 1 || len(api.providers) != 0 {
				t.Fatalf("spec mutation delete calls=%d providers=%d", api.deletes, len(api.providers))
			}
		})
	}
}

func TestIdentityProviderReconcileDeleteCleansStatusAndIssuedJournalRemotes(t *testing.T) {
	trueValue := true
	api := newParityIdentityProviderCloudflare()
	provider := newSCIMCaptureIdentityProvider("scim")
	provider.Spec.SCIMConfig.Enabled = &trueValue
	provider.Spec.DeletionPolicy = v1alpha1.DeletionPolicyDelete
	provider.Status.IDPID = "primary"
	provider.Status.OwnershipVerified = true
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	pendingName := identityProviderSCIMPendingRemoteNamePrefix + "orphan"
	secret := ownedSCIMSecret(t, reconciler, provider)
	secret.Annotations = map[string]string{
		identityProviderSCIMCreateIntentAnnotation: pendingName,
		identityProviderSCIMCreateStateAnnotation:  identityProviderSCIMCreateIssued,
	}
	if err := kube.Create(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	api.providers["primary"] = flarecloudflare.IdentityProvider{ID: "primary", Name: "primary", Type: provider.Spec.Type}
	pendingInput := identityProviderInputWithSCIMEnabled(flarecloudflare.IdentityProviderInput{
		Name:       pendingName,
		Type:       provider.Spec.Type,
		Config:     provider.Spec.Config,
		SCIMConfig: provider.Spec.SCIMConfig,
	}, false)
	api.providers["pending"] = parityIdentityProviderFromInput("pending", pendingInput)
	var deleting v1alpha1.IdentityProvider
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(provider), &deleting); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.reconcileDelete(context.Background(), &deleting); err != nil {
		t.Fatal(err)
	}
	if api.deletes != 2 || len(api.providers) != 0 {
		t.Fatalf("status and journal cleanup deletes=%d providers=%d", api.deletes, len(api.providers))
	}
}

func TestIdentityProviderReconcileDeleteCleansIssuedAmbiguousCreate(t *testing.T) {
	trueValue := true
	api := newParityIdentityProviderCloudflare()
	api.createErrAfterStore = fmt.Errorf("injected ambiguous create response")
	provider := newSCIMCaptureIdentityProvider("scim")
	provider.Spec.SCIMConfig.Enabled = &trueValue
	provider.Spec.DeletionPolicy = v1alpha1.DeletionPolicyDelete
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	ctx := context.Background()
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}); err == nil {
		t.Fatal("reconcile unexpectedly checkpointed ambiguous create")
	}
	var deleting v1alpha1.IdentityProvider
	if err := kube.Get(ctx, client.ObjectKeyFromObject(provider), &deleting); err != nil {
		t.Fatal(err)
	}
	if deleting.Status.IDPID != "" {
		t.Fatalf("ambiguous create status = %#v", deleting.Status)
	}
	if err := reconciler.reconcileDelete(ctx, &deleting); err != nil {
		t.Fatal(err)
	}
	if api.deletes != 1 || len(api.providers) != 0 {
		t.Fatalf("issued create cleanup deletes=%d providers=%d", api.deletes, len(api.providers))
	}
}

func TestIdentityProviderReconcilerSCIMCreateCheckpointFailureRecoversJournal(t *testing.T) {
	for _, commitThenFail := range []bool{false, true} {
		t.Run(fmt.Sprintf("commit=%t", commitThenFail), func(t *testing.T) {
			trueValue := true
			api := newParityIdentityProviderCloudflare()
			provider := newSCIMCaptureIdentityProvider("scim")
			provider.Spec.SCIMConfig.Enabled = &trueValue
			reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
			ctx := context.Background()
			failingClient := &identityProviderStatusPatchFailureClient{Client: kube, failAt: 1, commitThenFail: commitThenFail}
			reconciler.Client = failingClient
			request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}

			if _, err := reconciler.Reconcile(ctx, request); err == nil {
				t.Fatal("reconcile unexpectedly observed a successful checkpoint")
			}
			if api.creates != 1 || api.deletes != 0 || len(api.providers) != 1 {
				t.Fatalf("failed checkpoint handling creates=%d deletes=%d providers=%d", api.creates, api.deletes, len(api.providers))
			}
			var afterFailure v1alpha1.IdentityProvider
			if err := kube.Get(ctx, client.ObjectKeyFromObject(provider), &afterFailure); err != nil {
				t.Fatal(err)
			}
			if commitThenFail != (afterFailure.Status.IDPID == "idp-1" && afterFailure.Status.OwnershipVerified) {
				t.Fatalf("ambiguous checkpoint status = %#v", afterFailure.Status)
			}

			failingClient.failAt = 0
			for range 2 {
				if _, err := reconciler.Reconcile(ctx, request); err != nil {
					t.Fatalf("retry reconcile: %v", err)
				}
			}
			if api.creates != 1 || api.deletes != 0 || len(api.providers) != 1 {
				t.Fatalf("retry lifecycle creates=%d deletes=%d providers=%d", api.creates, api.deletes, len(api.providers))
			}
			var observed v1alpha1.IdentityProvider
			if err := kube.Get(ctx, client.ObjectKeyFromObject(provider), &observed); err != nil {
				t.Fatal(err)
			}
			if observed.Status.IDPID != "idp-1" || !observed.Status.OwnershipVerified {
				t.Fatalf("retry checkpoint = %#v", observed.Status)
			}
		})
	}
}

func TestIdentityProviderReconcilerSCIMReenableReplacesOwnedCredential(t *testing.T) {
	trueValue, falseValue := true, false
	api := newParityIdentityProviderCloudflare()
	provider := newSCIMCaptureIdentityProvider("scim")
	provider.Spec.SCIMConfig.Enabled = &trueValue
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	ctx := context.Background()
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatal(err)
	}
	var current v1alpha1.IdentityProvider
	if err := kube.Get(ctx, client.ObjectKeyFromObject(provider), &current); err != nil {
		t.Fatal(err)
	}
	current.Spec.SCIMConfig.Enabled = &falseValue
	if err := kube.Update(ctx, &current); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatal(err)
	}
	var retained corev1.Secret
	if err := kube.Get(ctx, types.NamespacedName{Namespace: provider.Namespace, Name: provider.Spec.SCIMConfig.SecretRef.Name}, &retained); err != nil {
		t.Fatal(err)
	}
	if len(retained.Data[v1alpha1.IdentityProviderSCIMSecretKey]) == 0 {
		t.Fatal("disabling SCIM unexpectedly removed the retained credential")
	}

	if err := kube.Get(ctx, client.ObjectKeyFromObject(provider), &current); err != nil {
		t.Fatal(err)
	}
	id := current.Status.IDPID
	current.Spec.SCIMConfig.Enabled = &trueValue
	if err := kube.Update(ctx, &current); err != nil {
		t.Fatal(err)
	}
	updatesBefore := api.updates
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("re-enable SCIM: %v", err)
	}
	if api.updates != updatesBefore+1 {
		t.Fatalf("re-enable update calls = %d, want %d", api.updates, updatesBefore+1)
	}
	var replaced corev1.Secret
	if err := kube.Get(ctx, client.ObjectKeyFromObject(&retained), &replaced); err != nil {
		t.Fatal(err)
	}
	if replaced.Annotations[v1alpha1.IdentityProviderIDAnnotation] != id ||
		string(replaced.Data[v1alpha1.IdentityProviderSCIMSecretKey]) != "one-time-scim-secret" {
		t.Fatalf("re-enabled SCIM Secret = %#v", replaced)
	}
}

func TestIdentityProviderReconcilerSCIMEnableRejectsImmutableEmptySecret(t *testing.T) {
	trueValue := true
	api := newParityIdentityProviderCloudflare()
	api.providers["idp"] = flarecloudflare.IdentityProvider{
		ID: "idp", Name: "scim", Type: v1alpha1.IdentityProviderTypeAzureAD, Config: v1alpha1.IdentityProviderConfig{ClientID: "client"},
	}
	provider := newSCIMCaptureIdentityProvider("scim")
	provider.Spec.SCIMConfig.Enabled = &trueValue
	provider.Status.IDPID = "idp"
	provider.Status.OwnershipVerified = true
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	secret := ownedSCIMSecret(t, reconciler, provider)
	secret.Immutable = &trueValue
	if err := kube.Create(context.Background(), secret); err != nil {
		t.Fatal(err)
	}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)})
	if err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("immutable SCIM Secret error = %v", err)
	}
	if api.updates != 0 {
		t.Fatalf("immutable destination consumed a remote enable token: update calls = %d", api.updates)
	}
}

func TestIdentityProviderReconcilerSCIMCaptureRetriesTransientWriteFailure(t *testing.T) {
	trueValue := true
	api := newParityIdentityProviderCloudflare()
	api.providers["idp"] = flarecloudflare.IdentityProvider{
		ID: "idp", Name: "scim", Type: v1alpha1.IdentityProviderTypeAzureAD, Config: v1alpha1.IdentityProviderConfig{ClientID: "client"},
	}
	provider := newSCIMCaptureIdentityProvider("scim")
	provider.Spec.SCIMConfig.Enabled = &trueValue
	provider.Status.IDPID = "idp"
	provider.Status.OwnershipVerified = true
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	secret := ownedSCIMSecret(t, reconciler, provider)
	if err := kube.Create(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	failingClient := &identityProviderSCIMCaptureFailureClient{
		Client:            kube,
		key:               client.ObjectKeyFromObject(secret),
		failuresRemaining: 1,
	}
	reconciler.Client = failingClient

	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}); err != nil {
		t.Fatal(err)
	}
	if failingClient.failures != 1 || api.updates != 1 || !identityProviderRemoteSCIMEnabled(api.providers["idp"].SCIMConfig) {
		t.Fatalf("transient capture retry failures=%d updates=%d remote=%#v", failingClient.failures, api.updates, api.providers["idp"].SCIMConfig)
	}
	var captured corev1.Secret
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(secret), &captured); err != nil {
		t.Fatal(err)
	}
	if captured.Annotations[v1alpha1.IdentityProviderIDAnnotation] != "idp" ||
		string(captured.Data[v1alpha1.IdentityProviderSCIMSecretKey]) != "one-time-scim-secret" {
		t.Fatalf("captured SCIM Secret = %#v", captured)
	}
}

func TestIdentityProviderReconcilerSCIMSecretRecoversDeletionAfterReadyStatusFailure(t *testing.T) {
	trueValue := true
	api := newParityIdentityProviderCloudflare()
	provider := newSCIMCaptureIdentityProvider("scim")
	provider.Spec.SCIMConfig.Enabled = &trueValue
	provider.Spec.DeletionPolicy = v1alpha1.DeletionPolicyDelete
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	ctx := context.Background()
	failingClient := &identityProviderStatusPatchFailureClient{Client: kube, failAt: 2}
	reconciler.Client = failingClient

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}); err != nil {
		t.Fatalf("create disabled provider and checkpoint identity: %v", err)
	}
	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)})
	if err == nil {
		t.Fatal("reconcile unexpectedly persisted Ready status")
	}
	if strings.Contains(err.Error(), "one-time-scim-secret") {
		t.Fatalf("status failure exposed the SCIM credential: %v", err)
	}
	if api.creates != 1 || failingClient.patches != 2 {
		t.Fatalf("create=%d status patches=%d", api.creates, failingClient.patches)
	}
	var secret corev1.Secret
	if err := kube.Get(ctx, types.NamespacedName{Namespace: provider.Namespace, Name: provider.Spec.SCIMConfig.SecretRef.Name}, &secret); err != nil {
		t.Fatal(err)
	}
	if secret.Annotations[v1alpha1.IdentityProviderIDAnnotation] != "idp-1" ||
		string(secret.Data[v1alpha1.IdentityProviderSCIMSecretKey]) != "one-time-scim-secret" {
		t.Fatalf("captured SCIM Secret = %#v", secret)
	}

	var deleting v1alpha1.IdentityProvider
	if err := kube.Get(ctx, client.ObjectKeyFromObject(provider), &deleting); err != nil {
		t.Fatal(err)
	}
	statusBase := deleting.DeepCopy()
	deleting.Status = v1alpha1.IdentityProviderStatus{}
	if err := kube.Status().Patch(ctx, &deleting, client.MergeFrom(statusBase)); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(ctx, client.ObjectKeyFromObject(provider), &deleting); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.reconcileDelete(ctx, &deleting); err != nil {
		t.Fatal(err)
	}
	if api.deletes != 1 {
		t.Fatalf("remote delete calls = %d, want 1", api.deletes)
	}
}

func TestIdentityProviderReconcileDeleteSkipsSCIMRecoveryWithoutRemoteDeletePolicy(t *testing.T) {
	for _, test := range []struct {
		name             string
		managementPolicy v1alpha1.ManagementPolicy
		deletionPolicy   v1alpha1.DeletionPolicy
	}{
		{name: "orphan", managementPolicy: v1alpha1.ManagementPolicyManaged, deletionPolicy: v1alpha1.DeletionPolicyOrphan},
		{name: "observe-only", managementPolicy: v1alpha1.ManagementPolicyObserveOnly, deletionPolicy: v1alpha1.DeletionPolicyDelete},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := newParityIdentityProviderCloudflare()
			provider := newSCIMCaptureIdentityProvider("scim")
			provider.Spec.ManagementPolicy = test.managementPolicy
			provider.Spec.DeletionPolicy = test.deletionPolicy
			reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
			foreign := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            provider.Spec.SCIMConfig.SecretRef.Name,
					Namespace:       provider.Namespace,
					OwnerReferences: []metav1.OwnerReference{foreignIdentityProviderControllerReference("other")},
				},
			}
			if err := kube.Create(context.Background(), foreign); err != nil {
				t.Fatal(err)
			}
			var deleting v1alpha1.IdentityProvider
			if err := kube.Get(context.Background(), client.ObjectKeyFromObject(provider), &deleting); err != nil {
				t.Fatal(err)
			}
			if err := reconciler.reconcileDelete(context.Background(), &deleting); err != nil {
				t.Fatal(err)
			}
			if api.deletes != 0 {
				t.Fatalf("remote delete calls = %d, want 0", api.deletes)
			}
		})
	}
}

func TestIdentityProviderReconcilerSCIMProviderIDBindingRequiredForReady(t *testing.T) {
	trueValue := true
	api := newParityIdentityProviderCloudflare()
	provider := newSCIMCaptureIdentityProvider("scim")
	provider.Spec.SCIMConfig.Enabled = &trueValue
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	ctx := context.Background()
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}); err != nil {
		t.Fatal(err)
	}
	var secret corev1.Secret
	if err := kube.Get(ctx, types.NamespacedName{Namespace: provider.Namespace, Name: provider.Spec.SCIMConfig.SecretRef.Name}, &secret); err != nil {
		t.Fatal(err)
	}
	secret.Annotations[v1alpha1.IdentityProviderIDAnnotation] = "different-idp"
	if err := kube.Update(ctx, &secret); err != nil {
		t.Fatal(err)
	}
	updatesBefore := api.updates

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}); err != nil {
		t.Fatal(err)
	}
	if api.updates != updatesBefore {
		t.Fatalf("converged provider was updated: before=%d after=%d", updatesBefore, api.updates)
	}
	var observed v1alpha1.IdentityProvider
	if err := kube.Get(ctx, client.ObjectKeyFromObject(provider), &observed); err != nil {
		t.Fatal(err)
	}
	var ready *metav1.Condition
	for index := range observed.Status.Conditions {
		if observed.Status.Conditions[index].Type == "Ready" {
			ready = &observed.Status.Conditions[index]
			break
		}
	}
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != "SecretMissing" {
		t.Fatalf("Ready condition = %#v", ready)
	}
	requireErr := reconciler.requireSCIMSecret(ctx, &observed, observed.Status.IDPID)
	if requireErr == nil {
		t.Fatal("mismatched provider annotation satisfied SCIM Secret readiness")
	}
	if strings.Contains(requireErr.Error(), "one-time-scim-secret") {
		t.Fatalf("SCIM readiness error exposed the credential: %v", requireErr)
	}
	statusJSON, err := json.Marshal(observed.Status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(statusJSON), "one-time-scim-secret") {
		t.Fatalf("SCIM credential leaked into status: %s", statusJSON)
	}
}

func TestCaptureSCIMSecretRejectsProviderIDMismatch(t *testing.T) {
	api := newParityIdentityProviderCloudflare()
	provider := newSCIMCaptureIdentityProvider("scim")
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	secret := ownedSCIMSecret(t, reconciler, provider)
	secret.Annotations = map[string]string{
		v1alpha1.IdentityProviderIDAnnotation: "other-idp",
		"unrelated":                           "kept",
	}
	secret.Data = map[string][]byte{
		v1alpha1.IdentityProviderSCIMSecretKey: []byte("original-secret"),
		"unrelated":                            []byte("kept"),
	}
	ctx := context.Background()
	if err := kube.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}
	var before corev1.Secret
	if err := kube.Get(ctx, client.ObjectKeyFromObject(secret), &before); err != nil {
		t.Fatal(err)
	}

	err := reconciler.captureSCIMSecret(ctx, provider, "idp", "replacement-secret")
	if err == nil {
		t.Fatal("capture accepted a SCIM Secret bound to another remote provider")
	}
	if strings.Contains(err.Error(), "replacement-secret") {
		t.Fatalf("capture error exposed the SCIM secret: %v", err)
	}
	var after corev1.Secret
	if err := kube.Get(ctx, client.ObjectKeyFromObject(secret), &after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("mismatched SCIM Secret was mutated:\nbefore=%#v\nafter=%#v", before, after)
	}
}

func TestCaptureSCIMSecretWritesOwnedEmptySecret(t *testing.T) {
	api := newParityIdentityProviderCloudflare()
	provider := newSCIMCaptureIdentityProvider("scim")
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	secret := ownedSCIMSecret(t, reconciler, provider)
	secret.Labels = map[string]string{"unrelated": "kept"}
	secret.Annotations = map[string]string{"unrelated": "kept"}
	secret.Type = corev1.SecretType("example.com/unrelated")
	secret.Data = map[string][]byte{"unrelated": []byte("kept")}
	ctx := context.Background()
	if err := kube.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}

	if err := reconciler.captureSCIMSecret(ctx, provider, "idp", "one-time-scim-secret"); err != nil {
		t.Fatal(err)
	}
	var observed corev1.Secret
	if err := kube.Get(ctx, client.ObjectKeyFromObject(secret), &observed); err != nil {
		t.Fatal(err)
	}
	if !metav1.IsControlledBy(&observed, provider) ||
		observed.Type != corev1.SecretType("example.com/unrelated") ||
		observed.Labels["unrelated"] != "kept" ||
		observed.Annotations["unrelated"] != "kept" ||
		observed.Annotations[v1alpha1.IdentityProviderIDAnnotation] != "idp" ||
		string(observed.Data["unrelated"]) != "kept" ||
		string(observed.Data[v1alpha1.IdentityProviderSCIMSecretKey]) != "one-time-scim-secret" {
		t.Fatalf("owned SCIM Secret = %#v", observed)
	}
}

func TestCaptureSCIMSecretKeepsOwnedExistingSecret(t *testing.T) {
	api := newParityIdentityProviderCloudflare()
	provider := newSCIMCaptureIdentityProvider("scim")
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	secret := ownedSCIMSecret(t, reconciler, provider)
	secret.Labels = map[string]string{"unrelated": "kept"}
	secret.Annotations = map[string]string{
		v1alpha1.IdentityProviderIDAnnotation: "idp",
		"unrelated":                           "kept",
	}
	secret.Type = corev1.SecretType("example.com/unrelated")
	secret.Data = map[string][]byte{
		v1alpha1.IdentityProviderSCIMSecretKey: []byte("original-secret"),
		"unrelated":                            []byte("kept"),
	}
	ctx := context.Background()
	if err := kube.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}
	var before corev1.Secret
	if err := kube.Get(ctx, client.ObjectKeyFromObject(secret), &before); err != nil {
		t.Fatal(err)
	}

	if err := reconciler.captureSCIMSecret(ctx, provider, "idp", "replacement-secret"); err != nil {
		t.Fatal(err)
	}
	var after corev1.Secret
	if err := kube.Get(ctx, client.ObjectKeyFromObject(secret), &after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("existing SCIM Secret was not idempotent:\nbefore=%#v\nafter=%#v", before, after)
	}
}

func TestCaptureSCIMSecretRejectsForeignCreateCollision(t *testing.T) {
	api := newParityIdentityProviderCloudflare()
	provider := newSCIMCaptureIdentityProvider("scim")
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	collision := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "scim-secret",
			Namespace:       "tenant",
			OwnerReferences: []metav1.OwnerReference{foreignIdentityProviderControllerReference("other")},
			Labels:          map[string]string{"unrelated": "kept"},
		},
		Type: corev1.SecretType("example.com/unrelated"),
		Data: map[string][]byte{"unrelated": []byte("kept")},
	}
	racingClient := &identityProviderSCIMCreateCollisionClient{Client: kube, collision: collision}
	reconciler.Client = racingClient

	err := reconciler.captureSCIMSecret(context.Background(), provider, "idp", "one-time-scim-secret")
	if err == nil {
		t.Fatal("capture adopted a foreign Secret that won the create race")
	}
	if !racingClient.collided {
		t.Fatal("capture did not exercise the create collision")
	}
	var observed corev1.Secret
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(collision), &observed); err != nil {
		t.Fatal(err)
	}
	if metav1.IsControlledBy(&observed, provider) ||
		len(observed.Data[v1alpha1.IdentityProviderSCIMSecretKey]) != 0 ||
		observed.Labels["unrelated"] != "kept" ||
		observed.Type != corev1.SecretType("example.com/unrelated") {
		t.Fatalf("foreign collision Secret was adopted or overwritten: %#v", observed)
	}
}

func TestCaptureSCIMSecretRejectsConcurrentOwnerChange(t *testing.T) {
	api := newParityIdentityProviderCloudflare()
	provider := newSCIMCaptureIdentityProvider("scim")
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	secret := ownedSCIMSecret(t, reconciler, provider)
	secret.Labels = map[string]string{"unrelated": "kept"}
	ctx := context.Background()
	if err := kube.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}
	racingClient := &identityProviderSCIMOwnerChangeClient{
		Client:                   kube,
		key:                      client.ObjectKeyFromObject(secret),
		fetchedResourceVersion:   "resource-version-before-write",
		concurrentOwnerReference: foreignIdentityProviderControllerReference("other"),
	}
	reconciler.Client = racingClient

	err := reconciler.captureSCIMSecret(ctx, provider, "idp", "one-time-scim-secret")
	if err == nil || !strings.Contains(err.Error(), "not owned by this IdentityProvider") {
		t.Fatalf("capture error = %v, want ownership rejection", err)
	}
	if racingClient.attemptedResourceVersion != racingClient.fetchedResourceVersion {
		t.Fatalf("update resourceVersion = %q, want fetched %q", racingClient.attemptedResourceVersion, racingClient.fetchedResourceVersion)
	}
	var observed corev1.Secret
	if err := kube.Get(ctx, client.ObjectKeyFromObject(secret), &observed); err != nil {
		t.Fatal(err)
	}
	if metav1.IsControlledBy(&observed, provider) ||
		len(observed.Data[v1alpha1.IdentityProviderSCIMSecretKey]) != 0 ||
		observed.Labels["unrelated"] != "kept" {
		t.Fatalf("concurrently changed Secret was overwritten: %#v", observed)
	}
}

func TestCaptureSCIMSecretRetriesConflictAndPreservesUnrelatedData(t *testing.T) {
	api := newParityIdentityProviderCloudflare()
	provider := newSCIMCaptureIdentityProvider("scim")
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	secret := ownedSCIMSecret(t, reconciler, provider)
	secret.Labels = map[string]string{"initial": "kept"}
	secret.Annotations = map[string]string{"initial": "kept"}
	secret.Data = map[string][]byte{"initial": []byte("kept")}
	ctx := context.Background()
	if err := kube.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}
	racingClient := &identityProviderSCIMDataConflictClient{
		Client: kube,
		key:    client.ObjectKeyFromObject(secret),
	}
	reconciler.Client = racingClient

	if err := reconciler.captureSCIMSecret(ctx, provider, "idp", "one-time-scim-secret"); err != nil {
		t.Fatal(err)
	}
	if !racingClient.conflicted {
		t.Fatal("capture did not retry an update conflict")
	}
	var observed corev1.Secret
	if err := kube.Get(ctx, client.ObjectKeyFromObject(secret), &observed); err != nil {
		t.Fatal(err)
	}
	if observed.Labels["initial"] != "kept" ||
		observed.Labels["concurrent"] != "kept" ||
		observed.Annotations["initial"] != "kept" ||
		observed.Annotations["concurrent"] != "kept" ||
		observed.Annotations[v1alpha1.IdentityProviderIDAnnotation] != "idp" ||
		string(observed.Data["initial"]) != "kept" ||
		string(observed.Data["concurrent"]) != "kept" ||
		string(observed.Data[v1alpha1.IdentityProviderSCIMSecretKey]) != "one-time-scim-secret" {
		t.Fatalf("captured SCIM Secret lost unrelated data: %#v", observed)
	}
}

func TestIdentityProviderReconcilerRedirectURLStatus(t *testing.T) {
	const redirectURL = "https://example.cloudflareaccess.com/cdn-cgi/access/login"
	api := newParityIdentityProviderCloudflare()
	api.providers["cloudflare"] = flarecloudflare.IdentityProvider{
		ID: "cloudflare", Name: "cloudflare", Type: v1alpha1.IdentityProviderTypeCloudflare, RedirectURL: redirectURL, ReadOnly: true,
	}
	api.providers["oidc"] = flarecloudflare.IdentityProvider{
		ID: "oidc", Name: "oidc", Type: v1alpha1.IdentityProviderTypeOIDC, RedirectURL: "https://must-not-be-projected.example",
	}
	otp := &v1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "otp", Namespace: "tenant", UID: types.UID("otp-uid"), Finalizers: []string{v1alpha1.IdentityProviderFinalizer}},
		Spec: v1alpha1.IdentityProviderSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"}, Name: "otp", Type: v1alpha1.IdentityProviderTypeOneTimePIN, ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
	}
	cloudflare := &v1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "cloudflare", Namespace: "tenant", UID: types.UID("cloudflare-uid"), Finalizers: []string{v1alpha1.IdentityProviderFinalizer}},
		Spec: v1alpha1.IdentityProviderSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"}, Name: "cloudflare", Type: v1alpha1.IdentityProviderTypeCloudflare, ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly, ExternalRef: &v1alpha1.IdentityProviderExternalReference{IDPID: "cloudflare"},
		},
	}
	oidc := &v1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc", Namespace: "tenant", UID: types.UID("oidc-uid"), Finalizers: []string{v1alpha1.IdentityProviderFinalizer}},
		Spec: v1alpha1.IdentityProviderSpec{
			AccountRef: corev1.LocalObjectReference{Name: "account"}, Name: "oidc", Type: v1alpha1.IdentityProviderTypeOIDC, ManagementPolicy: v1alpha1.ManagementPolicyObserveOnly, ExternalRef: &v1alpha1.IdentityProviderExternalReference{IDPID: "oidc"},
		},
	}
	reconciler, kube := newIdentityProviderParityReconciler(t, api, otp, cloudflare, oidc)
	ctx := context.Background()
	for _, provider := range []*v1alpha1.IdentityProvider{otp, cloudflare, oidc} {
		if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}); err != nil {
			t.Fatalf("reconcile %s: %v", provider.Name, err)
		}
	}

	for _, test := range []struct {
		provider *v1alpha1.IdentityProvider
		wantURL  string
	}{
		{provider: otp, wantURL: redirectURL},
		{provider: cloudflare, wantURL: redirectURL},
		{provider: oidc},
	} {
		var observed v1alpha1.IdentityProvider
		if err := kube.Get(ctx, client.ObjectKeyFromObject(test.provider), &observed); err != nil {
			t.Fatalf("get %s: %v", test.provider.Name, err)
		}
		if observed.Status.RedirectURL != test.wantURL {
			t.Fatalf("%s status redirect URL = %q, want %q", test.provider.Name, observed.Status.RedirectURL, test.wantURL)
		}
		statusJSON, err := json.Marshal(observed.Status)
		if err != nil {
			t.Fatalf("marshal %s status: %v", test.provider.Name, err)
		}
		if strings.Contains(string(statusJSON), `"redirectUrl"`) != (test.wantURL != "") {
			t.Fatalf("%s status redirectUrl presence = %s", test.provider.Name, statusJSON)
		}
	}

	var listed v1alpha1.IdentityProviderList
	if err := kube.List(ctx, &listed, client.InNamespace("tenant")); err != nil {
		t.Fatalf("list identity providers: %v", err)
	}
	listedURLs := make(map[string]string, len(listed.Items))
	for _, provider := range listed.Items {
		listedURLs[provider.Name] = provider.Status.RedirectURL
	}
	if listedURLs["otp"] != redirectURL || listedURLs["cloudflare"] != redirectURL || listedURLs["oidc"] != "" {
		t.Fatalf("listed status redirect URLs = %#v", listedURLs)
	}
}

func TestIdentityProviderReconcilerProtectsReadOnlyProviders(t *testing.T) {
	api := newParityIdentityProviderCloudflare()
	api.providers["read-only"] = flarecloudflare.IdentityProvider{ID: "read-only", Name: "built-in", Type: v1alpha1.IdentityProviderTypeCloudflare, ReadOnly: true}
	provider := &v1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "read-only", Namespace: "tenant", UID: types.UID("read-only-uid"), Finalizers: []string{v1alpha1.IdentityProviderFinalizer}},
		Spec:       v1alpha1.IdentityProviderSpec{AccountRef: corev1.LocalObjectReference{Name: "account"}, Name: "managed", Type: v1alpha1.IdentityProviderTypeCloudflare, ManagementPolicy: v1alpha1.ManagementPolicyManaged, Adoption: v1alpha1.AdoptionSpec{Mode: v1alpha1.AdoptionModeAdoptByID}, ExternalRef: &v1alpha1.IdentityProviderExternalReference{IDPID: "read-only"}, DeletionPolicy: v1alpha1.DeletionPolicyDelete},
	}
	reconciler, kube := newIdentityProviderParityReconciler(t, api, provider)
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(provider)}); err != nil {
		t.Fatal(err)
	}
	if api.updates != 0 || api.deletes != 0 || api.certificates != 0 {
		t.Fatalf("read-only provider was mutated: update=%d delete=%d certificate=%d", api.updates, api.deletes, api.certificates)
	}
	var observed v1alpha1.IdentityProvider
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(provider), &observed); err != nil {
		t.Fatal(err)
	}
	if !observed.Status.ReadOnly {
		t.Fatalf("read-only status = %#v", observed.Status)
	}
	observed.Status.IDPID = "read-only"
	observed.Status.OwnershipVerified = true
	if err := reconciler.reconcileDelete(context.Background(), &observed); err != nil {
		t.Fatal(err)
	}
	if api.deletes != 0 {
		t.Fatalf("read-only provider delete calls = %d", api.deletes)
	}
}

func newSCIMCaptureIdentityProvider(name string) *v1alpha1.IdentityProvider {
	return &v1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  "tenant",
			UID:        types.UID(name + "-uid"),
			Finalizers: []string{v1alpha1.IdentityProviderFinalizer},
		},
		Spec: v1alpha1.IdentityProviderSpec{
			AccountRef:       corev1.LocalObjectReference{Name: "account"},
			Name:             name,
			Type:             v1alpha1.IdentityProviderTypeAzureAD,
			Config:           v1alpha1.IdentityProviderConfig{ClientID: "client"},
			SCIMConfig:       &v1alpha1.IdentityProviderSCIMConfig{SecretRef: &corev1.LocalObjectReference{Name: "scim-secret"}},
			ManagementPolicy: v1alpha1.ManagementPolicyManaged,
		},
	}
}

func ownedSCIMSecret(t *testing.T, reconciler *IdentityProviderReconciler, provider *v1alpha1.IdentityProvider) *corev1.Secret {
	t.Helper()
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "scim-secret", Namespace: provider.Namespace}}
	if err := controllerutil.SetControllerReference(provider, secret, reconciler.Scheme); err != nil {
		t.Fatal(err)
	}
	return secret
}

func foreignIdentityProviderControllerReference(name string) metav1.OwnerReference {
	controller, blockOwnerDeletion := true, true
	return metav1.OwnerReference{
		APIVersion:         v1alpha1.GroupVersion.String(),
		Kind:               "IdentityProvider",
		Name:               name,
		UID:                types.UID(name + "-uid"),
		Controller:         &controller,
		BlockOwnerDeletion: &blockOwnerDeletion,
	}
}

type identityProviderSCIMCreateCollisionClient struct {
	client.Client
	collision *corev1.Secret
	collided  bool
}

func (c *identityProviderSCIMCreateCollisionClient) Create(ctx context.Context, object client.Object, options ...client.CreateOption) error {
	secret, ok := object.(*corev1.Secret)
	if !ok || c.collided || client.ObjectKeyFromObject(secret) != client.ObjectKeyFromObject(c.collision) {
		return c.Client.Create(ctx, object, options...)
	}
	c.collided = true
	if err := c.Client.Create(ctx, c.collision.DeepCopy(), options...); err != nil {
		return err
	}
	return apierrors.NewAlreadyExists(corev1.Resource("secrets"), secret.Name)
}

type identityProviderSCIMCaptureFailureClient struct {
	client.Client
	key               types.NamespacedName
	fail              bool
	failuresRemaining int
	failures          int
}

func (c *identityProviderSCIMCaptureFailureClient) Update(ctx context.Context, object client.Object, options ...client.UpdateOption) error {
	secret, ok := object.(*corev1.Secret)
	if ok && (c.fail || c.failuresRemaining > 0) && client.ObjectKeyFromObject(secret) == c.key && len(secret.Data[v1alpha1.IdentityProviderSCIMSecretKey]) > 0 {
		c.failures++
		if c.failuresRemaining > 0 {
			c.failuresRemaining--
		}
		return fmt.Errorf("injected SCIM Secret capture failure")
	}
	return c.Client.Update(ctx, object, options...)
}

type identityProviderStatusPatchFailureClient struct {
	client.Client
	patches        int
	failAt         int
	commitThenFail bool
}

func (c *identityProviderStatusPatchFailureClient) Status() client.SubResourceWriter {
	return &identityProviderStatusPatchFailureWriter{SubResourceWriter: c.Client.Status(), client: c}
}

type identityProviderStatusPatchFailureWriter struct {
	client.SubResourceWriter
	client *identityProviderStatusPatchFailureClient
}

func (w *identityProviderStatusPatchFailureWriter) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.SubResourcePatchOption) error {
	if _, ok := object.(*v1alpha1.IdentityProvider); ok {
		w.client.patches++
		if w.client.patches == w.client.failAt {
			if w.client.commitThenFail {
				if err := w.SubResourceWriter.Patch(ctx, object, patch, options...); err != nil {
					return err
				}
			}
			return fmt.Errorf("injected IdentityProvider status failure")
		}
	}
	return w.SubResourceWriter.Patch(ctx, object, patch, options...)
}

type identityProviderSCIMDataConflictClient struct {
	client.Client
	key        types.NamespacedName
	conflicted bool
}

func (c *identityProviderSCIMDataConflictClient) Update(ctx context.Context, object client.Object, options ...client.UpdateOption) error {
	secret, ok := object.(*corev1.Secret)
	if !ok || c.conflicted || client.ObjectKeyFromObject(secret) != c.key || len(secret.Data[v1alpha1.IdentityProviderSCIMSecretKey]) == 0 {
		return c.Client.Update(ctx, object, options...)
	}
	var current corev1.Secret
	if err := c.Get(ctx, c.key, &current); err != nil {
		return err
	}
	if current.Labels == nil {
		current.Labels = map[string]string{}
	}
	if current.Annotations == nil {
		current.Annotations = map[string]string{}
	}
	if current.Data == nil {
		current.Data = map[string][]byte{}
	}
	current.Labels["concurrent"] = "kept"
	current.Annotations["concurrent"] = "kept"
	current.Data["concurrent"] = []byte("kept")
	if err := c.Client.Update(ctx, &current, options...); err != nil {
		return err
	}
	c.conflicted = true
	return apierrors.NewConflict(corev1.Resource("secrets"), secret.Name, fmt.Errorf("concurrent unrelated Secret update"))
}

type identityProviderSCIMOwnerChangeClient struct {
	client.Client
	key                      types.NamespacedName
	fetchedResourceVersion   string
	attemptedResourceVersion string
	concurrentOwnerReference metav1.OwnerReference
}

func (c *identityProviderSCIMOwnerChangeClient) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	if err := c.Client.Get(ctx, key, object, options...); err != nil {
		return err
	}
	if secret, ok := object.(*corev1.Secret); ok && key == c.key {
		secret.ResourceVersion = c.fetchedResourceVersion
	}
	return nil
}

func (c *identityProviderSCIMOwnerChangeClient) Update(ctx context.Context, object client.Object, options ...client.UpdateOption) error {
	secret, ok := object.(*corev1.Secret)
	if !ok || client.ObjectKeyFromObject(secret) != c.key {
		return c.Client.Update(ctx, object, options...)
	}
	c.attemptedResourceVersion = secret.ResourceVersion
	var current corev1.Secret
	if err := c.Client.Get(ctx, c.key, &current); err != nil {
		return err
	}
	current.OwnerReferences = []metav1.OwnerReference{c.concurrentOwnerReference}
	if err := c.Client.Update(ctx, &current); err != nil {
		return err
	}
	return apierrors.NewConflict(corev1.Resource("secrets"), secret.Name, fmt.Errorf("concurrent owner change"))
}

func newIdentityProviderParityReconciler(t *testing.T, api *parityIdentityProviderCloudflare, providers ...*v1alpha1.IdentityProvider) (*IdentityProviderReconciler, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, time.September, 14, 12, 0, 0, 0, time.UTC)
	account := &v1alpha1.CloudflareAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "account"},
		Spec: v1alpha1.CloudflareAccountSpec{
			AccountID:   "0123456789abcdef0123456789abcdef",
			Credentials: v1alpha1.CloudflareAccountCredentials{APITokenSecretRef: v1alpha1.NamespacedSecretKeyReference{Namespace: "tenant", Name: "api-token", Key: "token"}},
			Grants:      []v1alpha1.CloudflareAccountGrant{{NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "true"}}, PlatformObjects: v1alpha1.GrantPermissionAllowed}},
		},
		Status: v1alpha1.CloudflareAccountStatus{Conditions: []metav1.Condition{
			{Type: v1alpha1.CloudflareAccountConditionAccepted, Status: metav1.ConditionTrue, Reason: "Accepted", LastTransitionTime: metav1.NewTime(clock)},
			{Type: v1alpha1.CloudflareAccountConditionCredentialsValid, Status: metav1.ConditionTrue, Reason: "Valid", LastTransitionTime: metav1.NewTime(clock)},
		}},
	}
	objects := []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Labels: map[string]string{"tenant": "true"}}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster")}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "api-token", Namespace: "tenant"}, Data: map[string][]byte{"token": []byte("api-token")}},
		account,
	}
	for _, provider := range providers {
		objects = append(objects, provider)
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1alpha1.IdentityProvider{}).WithObjects(objects...).Build()
	reconciler := &IdentityProviderReconciler{
		Client: kube,
		Scheme: scheme,
		Now:    func() time.Time { return clock },
		NewCloudflareClient: func(string, string) (flarecloudflare.AccessAPI, error) {
			return api, nil
		},
	}
	return reconciler, kube
}
