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
	"fmt"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
)

// GatewayAPI is the complete M5 Gateway rules and lists surface.
type GatewayAPI interface {
	GatewayRuleAPI
	GatewayListAPI
}

// GatewayRuleAPI manages Cloudflare Zero Trust Gateway rules.
type GatewayRuleAPI interface {
	CreateGatewayRule(context.Context, GatewayRuleInput) (GatewayRule, error)
	UpdateGatewayRule(context.Context, string, GatewayRuleInput) (GatewayRule, error)
	GetGatewayRule(context.Context, string) (GatewayRule, error)
	ListGatewayRules(context.Context) ([]GatewayRule, error)
	DeleteGatewayRule(context.Context, string) error
}

// GatewayListAPI manages Cloudflare Zero Trust Gateway lists and whole-list items.
type GatewayListAPI interface {
	CreateGatewayList(context.Context, GatewayListInput) (GatewayList, error)
	UpdateGatewayList(context.Context, string, string) (GatewayList, error)
	GetGatewayList(context.Context, string) (GatewayList, error)
	ListGatewayLists(context.Context) ([]GatewayList, error)
	DeleteGatewayList(context.Context, string) error
	ReplaceGatewayListItems(context.Context, string, string, []GatewayListItem) (GatewayList, error)
}

// GatewayRuleFilter selects the rule evaluation layer.
type GatewayRuleFilter string

const (
	// GatewayRuleFilterL4 is part of the Flareway API.
	GatewayRuleFilterL4 GatewayRuleFilter = "l4"
	// GatewayRuleFilterDNS is part of the Flareway API.
	GatewayRuleFilterDNS GatewayRuleFilter = "dns"
)

// GatewayRuleCheckSession configures session freshness.
type GatewayRuleCheckSession struct {
	Enforce  *bool
	Duration *string
}

// GatewayRuleAuditSSH configures SSH command logging.
type GatewayRuleAuditSSH struct {
	CommandLogging *bool
}

// GatewayRuleL4Override redirects traffic to an IP address and port.
type GatewayRuleL4Override struct {
	IP   string
	Port int32
}

// GatewayRuleNotification configures a client notification for a block rule.
type GatewayRuleNotification struct {
	Enabled        *bool
	IncludeContext *bool
	Message        *string
	SupportURL     *string
}

// GatewayRuleSettings is the typed l4/dns settings subset exposed by Flareway.
type GatewayRuleSettings struct {
	AuditSSH                        *GatewayRuleAuditSSH
	BlockPageEnabled                *bool
	BlockReason                     *string
	CheckSession                    *GatewayRuleCheckSession
	IgnoreCNAMECategoryMatches      *bool
	InsecureDisableDNSSECValidation *bool
	IPCategories                    *bool
	IPIndicatorFeeds                *bool
	L4Override                      *GatewayRuleL4Override
	Notification                    *GatewayRuleNotification
	OverrideHost                    *string
	OverrideIPs                     *[]string
}

// GatewayRuleInput preserves optional API fields while requiring rule identity and selectors.
type GatewayRuleInput struct {
	Name          string
	Description   *string
	Enabled       *bool
	Precedence    *int64
	Filters       []GatewayRuleFilter
	Action        string
	Traffic       string
	Identity      *string
	DevicePosture *string
	RuleSettings  *GatewayRuleSettings
}

// GatewayRule is the non-secret normalized rule returned by Cloudflare.
type GatewayRule struct {
	ID            string
	Name          string
	Description   string
	Enabled       bool
	Precedence    int64
	Filters       []GatewayRuleFilter
	Action        string
	Traffic       string
	Identity      string
	DevicePosture string
	RuleSettings  GatewayRuleSettings
	ReadOnly      bool
	Version       int64
}

// GatewayListType selects the Cloudflare list item parser.
type GatewayListType string

const (
	// GatewayListTypeSerial is part of the Flareway API.
	GatewayListTypeSerial GatewayListType = "SERIAL"
	// GatewayListTypeURL is part of the Flareway API.
	GatewayListTypeURL GatewayListType = "URL"
	// GatewayListTypeDomain is part of the Flareway API.
	GatewayListTypeDomain GatewayListType = "DOMAIN"
	// GatewayListTypeEmail is part of the Flareway API.
	GatewayListTypeEmail GatewayListType = "EMAIL"
	// GatewayListTypeIP is part of the Flareway API.
	GatewayListTypeIP GatewayListType = "IP"
)

// GatewayListItem is one value in a whole-list replacement.
type GatewayListItem struct {
	Value       string
	Description string
}

// GatewayListInput defines a new Gateway list.
type GatewayListInput struct {
	Name  string
	Type  GatewayListType
	Items []GatewayListItem
}

// GatewayList is the non-secret remote list state.
type GatewayList struct {
	ID    string
	Name  string
	Type  GatewayListType
	Items []GatewayListItem
	Count int64
}

// CreateGatewayRule is part of the Cloudflare adapter API.
func (client *Client) CreateGatewayRule(ctx context.Context, input GatewayRuleInput) (GatewayRule, error) {
	params, err := gatewayRuleNewParams(client.accountID, input)
	if err != nil {
		return GatewayRule{}, err
	}
	remote, err := client.sdk.ZeroTrust.Gateway.Rules.New(ctx, params)
	if err != nil {
		return GatewayRule{}, fmt.Errorf("create Cloudflare Gateway rule: %w", err)
	}
	return gatewayRuleFromSDK(remote), nil
}

// UpdateGatewayRule is part of the Cloudflare adapter API.
func (client *Client) UpdateGatewayRule(ctx context.Context, ruleID string, input GatewayRuleInput) (GatewayRule, error) {
	params, err := gatewayRuleUpdateParams(client.accountID, input)
	if err != nil {
		return GatewayRule{}, err
	}
	remote, err := client.sdk.ZeroTrust.Gateway.Rules.Update(ctx, ruleID, params)
	if err != nil {
		return GatewayRule{}, fmt.Errorf("update Cloudflare Gateway rule: %w", err)
	}
	return gatewayRuleFromSDK(remote), nil
}

// GetGatewayRule is part of the Cloudflare adapter API.
func (client *Client) GetGatewayRule(ctx context.Context, ruleID string) (GatewayRule, error) {
	remote, err := client.sdk.ZeroTrust.Gateway.Rules.Get(ctx, ruleID, zero_trust.GatewayRuleGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return GatewayRule{}, fmt.Errorf("get Cloudflare Gateway rule: %w", err)
	}
	return gatewayRuleFromSDK(remote), nil
}

// ListGatewayRules is part of the Cloudflare adapter API.
func (client *Client) ListGatewayRules(ctx context.Context) ([]GatewayRule, error) {
	pager := client.sdk.ZeroTrust.Gateway.Rules.ListAutoPaging(ctx, zero_trust.GatewayRuleListParams{AccountID: cloudflaresdk.F(client.accountID)})
	result := make([]GatewayRule, 0)
	for pager.Next() {
		remote := pager.Current()
		result = append(result, gatewayRuleFromSDK(&remote))
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Cloudflare Gateway rules: %w", err)
	}
	return result, nil
}

// DeleteGatewayRule is part of the Cloudflare adapter API.
func (client *Client) DeleteGatewayRule(ctx context.Context, ruleID string) error {
	_, err := client.sdk.ZeroTrust.Gateway.Rules.Delete(ctx, ruleID, zero_trust.GatewayRuleDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return fmt.Errorf("delete Cloudflare Gateway rule: %w", err)
	}
	return nil
}

// CreateGatewayList is part of the Cloudflare adapter API.
func (client *Client) CreateGatewayList(ctx context.Context, input GatewayListInput) (GatewayList, error) {
	if err := validateGatewayListInput(input); err != nil {
		return GatewayList{}, err
	}
	if err := client.waitGatewayList(ctx); err != nil {
		return GatewayList{}, err
	}
	remote, err := client.sdk.ZeroTrust.Gateway.Lists.New(ctx, zero_trust.GatewayListNewParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Name:      cloudflaresdk.F(input.Name),
		Type:      cloudflaresdk.F(zero_trust.GatewayListNewParamsType(input.Type)),
		Items:     cloudflaresdk.F(gatewayListNewItems(input.Items)),
	})
	if err != nil {
		return GatewayList{}, fmt.Errorf("create Cloudflare Gateway list: %w", err)
	}
	return gatewayListFromNewSDK(remote), nil
}

// UpdateGatewayList is part of the Cloudflare adapter API.
func (client *Client) UpdateGatewayList(ctx context.Context, listID, name string) (GatewayList, error) {
	if name == "" {
		return GatewayList{}, fmt.Errorf("update Cloudflare Gateway list: name is required")
	}
	if err := client.waitGatewayList(ctx); err != nil {
		return GatewayList{}, err
	}
	remote, err := client.sdk.ZeroTrust.Gateway.Lists.Update(ctx, listID, zero_trust.GatewayListUpdateParams{AccountID: cloudflaresdk.F(client.accountID), Name: cloudflaresdk.F(name)})
	if err != nil {
		return GatewayList{}, fmt.Errorf("update Cloudflare Gateway list: %w", err)
	}
	return gatewayListFromSDK(remote), nil
}

// GetGatewayList is part of the Cloudflare adapter API.
func (client *Client) GetGatewayList(ctx context.Context, listID string) (GatewayList, error) {
	if err := client.waitGatewayList(ctx); err != nil {
		return GatewayList{}, err
	}
	remote, err := client.sdk.ZeroTrust.Gateway.Lists.Get(ctx, listID, zero_trust.GatewayListGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return GatewayList{}, fmt.Errorf("get Cloudflare Gateway list: %w", err)
	}
	result := gatewayListFromSDK(remote)
	items, err := client.listGatewayListItems(ctx, listID)
	if err != nil {
		return GatewayList{}, err
	}
	result.Items = items
	result.Count = int64(len(items))
	return result, nil
}

// ListGatewayLists is part of the Cloudflare adapter API.
func (client *Client) ListGatewayLists(ctx context.Context) ([]GatewayList, error) {
	if err := client.waitGatewayList(ctx); err != nil {
		return nil, err
	}
	pager := client.sdk.ZeroTrust.Gateway.Lists.ListAutoPaging(ctx, zero_trust.GatewayListListParams{AccountID: cloudflaresdk.F(client.accountID)})
	result := make([]GatewayList, 0)
	for pager.Next() {
		remote := pager.Current()
		result = append(result, gatewayListFromSDK(&remote))
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Cloudflare Gateway lists: %w", err)
	}
	return result, nil
}

// DeleteGatewayList is part of the Cloudflare adapter API.
func (client *Client) DeleteGatewayList(ctx context.Context, listID string) error {
	if err := client.waitGatewayList(ctx); err != nil {
		return err
	}
	_, err := client.sdk.ZeroTrust.Gateway.Lists.Delete(ctx, listID, zero_trust.GatewayListDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return fmt.Errorf("delete Cloudflare Gateway list: %w", err)
	}
	return nil
}

// ReplaceGatewayListItems is part of the Cloudflare adapter API.
func (client *Client) ReplaceGatewayListItems(ctx context.Context, listID, name string, items []GatewayListItem) (GatewayList, error) {
	if name == "" {
		return GatewayList{}, fmt.Errorf("replace Cloudflare Gateway list items: name is required")
	}
	if len(items) == 0 {
		current, err := client.listGatewayListItems(ctx, listID)
		if err != nil {
			return GatewayList{}, err
		}
		if len(current) == 0 {
			if err := client.waitGatewayList(ctx); err != nil {
				return GatewayList{}, err
			}
			remote, err := client.sdk.ZeroTrust.Gateway.Lists.Get(ctx, listID, zero_trust.GatewayListGetParams{AccountID: cloudflaresdk.F(client.accountID)})
			if err != nil {
				return GatewayList{}, fmt.Errorf("get empty Cloudflare Gateway list: %w", err)
			}
			result := gatewayListFromSDK(remote)
			result.Items = []GatewayListItem{}
			result.Count = 0
			return result, nil
		}
		values := make([]string, len(current))
		for i := range current {
			values[i] = current[i].Value
		}
		if err := client.waitGatewayList(ctx); err != nil {
			return GatewayList{}, err
		}
		remote, err := client.sdk.ZeroTrust.Gateway.Lists.Edit(ctx, listID, zero_trust.GatewayListEditParams{
			AccountID: cloudflaresdk.F(client.accountID),
			Remove:    cloudflaresdk.F(values),
		})
		if err != nil {
			return GatewayList{}, fmt.Errorf("clear Cloudflare Gateway list items: %w", err)
		}
		return gatewayListFromSDK(remote), nil
	}
	if err := client.waitGatewayList(ctx); err != nil {
		return GatewayList{}, err
	}
	remote, err := client.sdk.ZeroTrust.Gateway.Lists.Update(ctx, listID, zero_trust.GatewayListUpdateParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Name:      cloudflaresdk.F(name),
		Items:     cloudflaresdk.F(gatewayListUpdateItems(items)),
	})
	if err != nil {
		return GatewayList{}, fmt.Errorf("replace Cloudflare Gateway list items: %w", err)
	}
	return gatewayListFromSDK(remote), nil
}

func (client *Client) listGatewayListItems(ctx context.Context, listID string) ([]GatewayListItem, error) {
	if err := client.waitGatewayList(ctx); err != nil {
		return nil, err
	}
	pager := client.sdk.ZeroTrust.Gateway.Lists.Items.ListAutoPaging(ctx, listID, zero_trust.GatewayListItemListParams{AccountID: cloudflaresdk.F(client.accountID)})
	result := make([]GatewayListItem, 0)
	for pager.Next() {
		item := pager.Current()
		result = append(result, GatewayListItem{Value: item.Value, Description: item.Description})
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Cloudflare Gateway list items: %w", err)
	}
	return result, nil
}

func (client *Client) waitGatewayList(ctx context.Context) error {
	if client.listLimiter == nil {
		return nil
	}
	if err := client.listLimiter.Wait(ctx); err != nil {
		return fmt.Errorf("wait for Cloudflare Gateway list rate limit: %w", err)
	}
	return nil
}

func gatewayRuleNewParams(accountID string, input GatewayRuleInput) (zero_trust.GatewayRuleNewParams, error) {
	if err := validateGatewayRuleInput(input); err != nil {
		return zero_trust.GatewayRuleNewParams{}, err
	}
	params := zero_trust.GatewayRuleNewParams{
		AccountID: cloudflaresdk.F(accountID),
		Name:      cloudflaresdk.F(input.Name),
		Action:    cloudflaresdk.F(zero_trust.GatewayRuleNewParamsAction(input.Action)),
		Filters:   cloudflaresdk.F(gatewayFiltersToSDK(input.Filters)),
		Traffic:   cloudflaresdk.F(input.Traffic),
	}
	setGatewayRuleNewOptional(&params, input)
	return params, nil
}

func gatewayRuleUpdateParams(accountID string, input GatewayRuleInput) (zero_trust.GatewayRuleUpdateParams, error) {
	if err := validateGatewayRuleInput(input); err != nil {
		return zero_trust.GatewayRuleUpdateParams{}, err
	}
	params := zero_trust.GatewayRuleUpdateParams{
		AccountID: cloudflaresdk.F(accountID),
		Name:      cloudflaresdk.F(input.Name),
		Action:    cloudflaresdk.F(zero_trust.GatewayRuleUpdateParamsAction(input.Action)),
		Filters:   cloudflaresdk.F(gatewayFiltersToSDK(input.Filters)),
		Traffic:   cloudflaresdk.F(input.Traffic),
	}
	setGatewayRuleUpdateOptional(&params, input)
	return params, nil
}

func validateGatewayRuleInput(input GatewayRuleInput) error {
	if input.Name == "" || input.Action == "" || input.Traffic == "" {
		return fmt.Errorf("cloudflare Gateway rule name, action, and traffic are required")
	}
	if len(input.Filters) != 1 || (input.Filters[0] != GatewayRuleFilterL4 && input.Filters[0] != GatewayRuleFilterDNS) {
		return fmt.Errorf("cloudflare Gateway rule requires exactly one l4 or dns filter")
	}
	return nil
}

func setGatewayRuleNewOptional(params *zero_trust.GatewayRuleNewParams, input GatewayRuleInput) {
	if input.Description != nil {
		params.Description = cloudflaresdk.F(*input.Description)
	}
	if input.Enabled != nil {
		params.Enabled = cloudflaresdk.F(*input.Enabled)
	}
	if input.Precedence != nil {
		params.Precedence = cloudflaresdk.F(*input.Precedence)
	}
	if input.Identity != nil {
		params.Identity = cloudflaresdk.F(*input.Identity)
	}
	if input.DevicePosture != nil {
		params.DevicePosture = cloudflaresdk.F(*input.DevicePosture)
	}
	if input.RuleSettings != nil {
		params.RuleSettings = cloudflaresdk.F(gatewayRuleSettingsToSDK(input.RuleSettings))
	}
}

func setGatewayRuleUpdateOptional(params *zero_trust.GatewayRuleUpdateParams, input GatewayRuleInput) {
	if input.Description != nil {
		params.Description = cloudflaresdk.F(*input.Description)
	}
	if input.Enabled != nil {
		params.Enabled = cloudflaresdk.F(*input.Enabled)
	}
	if input.Precedence != nil {
		params.Precedence = cloudflaresdk.F(*input.Precedence)
	}
	if input.Identity != nil {
		params.Identity = cloudflaresdk.F(*input.Identity)
	}
	if input.DevicePosture != nil {
		params.DevicePosture = cloudflaresdk.F(*input.DevicePosture)
	}
	if input.RuleSettings != nil {
		params.RuleSettings = cloudflaresdk.F(gatewayRuleSettingsToSDK(input.RuleSettings))
	}
}

func gatewayRuleSettingsToSDK(input *GatewayRuleSettings) zero_trust.RuleSettingParam {
	result := zero_trust.RuleSettingParam{}
	if input.AuditSSH != nil {
		value := zero_trust.RuleSettingAuditSSHParam{}
		if input.AuditSSH.CommandLogging != nil {
			value.CommandLogging = cloudflaresdk.F(*input.AuditSSH.CommandLogging)
		}
		result.AuditSSH = cloudflaresdk.F(value)
	}
	if input.BlockPageEnabled != nil {
		result.BlockPageEnabled = cloudflaresdk.F(*input.BlockPageEnabled)
	}
	if input.BlockReason != nil {
		result.BlockReason = cloudflaresdk.F(*input.BlockReason)
	}
	if input.CheckSession != nil {
		value := zero_trust.RuleSettingCheckSessionParam{}
		if input.CheckSession.Enforce != nil {
			value.Enforce = cloudflaresdk.F(*input.CheckSession.Enforce)
		}
		if input.CheckSession.Duration != nil {
			value.Duration = cloudflaresdk.F(*input.CheckSession.Duration)
		}
		result.CheckSession = cloudflaresdk.F(value)
	}
	if input.IgnoreCNAMECategoryMatches != nil {
		result.IgnoreCNAMECategoryMatches = cloudflaresdk.F(*input.IgnoreCNAMECategoryMatches)
	}
	if input.InsecureDisableDNSSECValidation != nil {
		result.InsecureDisableDNSSECValidation = cloudflaresdk.F(*input.InsecureDisableDNSSECValidation)
	}
	if input.IPCategories != nil {
		result.IPCategories = cloudflaresdk.F(*input.IPCategories)
	}
	if input.IPIndicatorFeeds != nil {
		result.IPIndicatorFeeds = cloudflaresdk.F(*input.IPIndicatorFeeds)
	}
	if input.L4Override != nil {
		result.L4override = cloudflaresdk.F(zero_trust.RuleSettingL4overrideParam{IP: cloudflaresdk.F(input.L4Override.IP), Port: cloudflaresdk.F(int64(input.L4Override.Port))})
	}
	if input.Notification != nil {
		value := zero_trust.RuleSettingNotificationSettingsParam{}
		if input.Notification.Enabled != nil {
			value.Enabled = cloudflaresdk.F(*input.Notification.Enabled)
		}
		if input.Notification.IncludeContext != nil {
			value.IncludeContext = cloudflaresdk.F(*input.Notification.IncludeContext)
		}
		if input.Notification.Message != nil {
			value.Msg = cloudflaresdk.F(*input.Notification.Message)
		}
		if input.Notification.SupportURL != nil {
			value.SupportURL = cloudflaresdk.F(*input.Notification.SupportURL)
		}
		result.NotificationSettings = cloudflaresdk.F(value)
	}
	if input.OverrideHost != nil {
		result.OverrideHost = cloudflaresdk.F(*input.OverrideHost)
	}
	if input.OverrideIPs != nil {
		result.OverrideIPs = cloudflaresdk.F(append([]string(nil), (*input.OverrideIPs)...))
	}
	return result
}

func gatewayFiltersToSDK(filters []GatewayRuleFilter) []zero_trust.GatewayFilter {
	result := make([]zero_trust.GatewayFilter, len(filters))
	for i := range filters {
		result[i] = zero_trust.GatewayFilter(filters[i])
	}
	return result
}

func gatewayRuleFromSDK(remote *zero_trust.GatewayRule) GatewayRule {
	result := GatewayRule{ID: remote.ID, Name: remote.Name, Description: remote.Description, Enabled: remote.Enabled, Precedence: remote.Precedence, Action: string(remote.Action), Traffic: remote.Traffic, Identity: remote.Identity, DevicePosture: remote.DevicePosture, ReadOnly: remote.ReadOnly, Version: remote.Version}
	for _, filter := range remote.Filters {
		result.Filters = append(result.Filters, GatewayRuleFilter(filter))
	}
	settings := remote.RuleSettings
	result.RuleSettings = GatewayRuleSettings{BlockPageEnabled: boolPointer(settings.BlockPageEnabled), BlockReason: stringPointer(settings.BlockReason), IgnoreCNAMECategoryMatches: boolPointer(settings.IgnoreCNAMECategoryMatches), InsecureDisableDNSSECValidation: boolPointer(settings.InsecureDisableDNSSECValidation), IPCategories: boolPointer(settings.IPCategories), IPIndicatorFeeds: boolPointer(settings.IPIndicatorFeeds), OverrideHost: stringPointer(settings.OverrideHost)}
	if settings.OverrideIPs != nil {
		values := append([]string(nil), settings.OverrideIPs...)
		result.RuleSettings.OverrideIPs = &values
	}
	if settings.AuditSSH.CommandLogging {
		result.RuleSettings.AuditSSH = &GatewayRuleAuditSSH{CommandLogging: boolPointer(true)}
	}
	if settings.CheckSession.Duration != "" || settings.CheckSession.Enforce {
		result.RuleSettings.CheckSession = &GatewayRuleCheckSession{Enforce: boolPointer(settings.CheckSession.Enforce), Duration: stringPointer(settings.CheckSession.Duration)}
	}
	if settings.L4override.IP != "" || settings.L4override.Port != 0 {
		result.RuleSettings.L4Override = &GatewayRuleL4Override{IP: settings.L4override.IP, Port: int32(settings.L4override.Port)}
	}
	if settings.NotificationSettings.Enabled || settings.NotificationSettings.Msg != "" || settings.NotificationSettings.SupportURL != "" {
		result.RuleSettings.Notification = &GatewayRuleNotification{Enabled: boolPointer(settings.NotificationSettings.Enabled), IncludeContext: boolPointer(settings.NotificationSettings.IncludeContext), Message: stringPointer(settings.NotificationSettings.Msg), SupportURL: stringPointer(settings.NotificationSettings.SupportURL)}
	}
	return result
}

func validateGatewayListInput(input GatewayListInput) error {
	if input.Name == "" {
		return fmt.Errorf("create Cloudflare Gateway list: name is required")
	}
	switch input.Type {
	case GatewayListTypeSerial, GatewayListTypeURL, GatewayListTypeDomain, GatewayListTypeEmail, GatewayListTypeIP:
	default:
		return fmt.Errorf("create Cloudflare Gateway list: unsupported type %q", input.Type)
	}
	for i, item := range input.Items {
		if item.Value == "" {
			return fmt.Errorf("create Cloudflare Gateway list: item %d value is required", i)
		}
	}
	return nil
}

func gatewayListNewItems(items []GatewayListItem) []zero_trust.GatewayListNewParamsItem {
	result := make([]zero_trust.GatewayListNewParamsItem, len(items))
	for i := range items {
		result[i] = zero_trust.GatewayListNewParamsItem{Value: cloudflaresdk.F(items[i].Value), Description: cloudflaresdk.F(items[i].Description)}
	}
	return result
}
func gatewayListUpdateItems(items []GatewayListItem) []zero_trust.GatewayListUpdateParamsItem {
	result := make([]zero_trust.GatewayListUpdateParamsItem, len(items))
	for i := range items {
		result[i] = zero_trust.GatewayListUpdateParamsItem{Value: cloudflaresdk.F(items[i].Value), Description: cloudflaresdk.F(items[i].Description)}
	}
	return result
}
func gatewayListFromSDK(remote *zero_trust.GatewayList) GatewayList {
	result := GatewayList{ID: remote.ID, Name: remote.Name, Type: GatewayListType(remote.Type), Count: int64(remote.Count)}
	for _, item := range remote.Items {
		result.Items = append(result.Items, GatewayListItem{Value: item.Value, Description: item.Description})
	}
	return result
}
func gatewayListFromNewSDK(remote *zero_trust.GatewayListNewResponse) GatewayList {
	result := GatewayList{ID: remote.ID, Name: remote.Name, Type: GatewayListType(remote.Type), Count: int64(len(remote.Items))}
	for _, item := range remote.Items {
		result.Items = append(result.Items, GatewayListItem{Value: item.Value, Description: item.Description})
	}
	return result
}
func boolPointer(value bool) *bool       { result := value; return &result }
func stringPointer(value string) *string { result := value; return &result }
