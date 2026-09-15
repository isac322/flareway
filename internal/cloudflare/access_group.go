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
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
)

// AccessGroupAPI is part of the Flareway API.
type AccessGroupAPI interface {
	CreateAccessGroup(context.Context, AccessScope, AccessGroupInput) (AccessGroup, error)
	UpdateAccessGroup(context.Context, AccessScope, string, AccessGroupInput) (AccessGroup, error)
	GetAccessGroup(context.Context, AccessScope, string) (AccessGroup, error)
	ListAccessGroups(context.Context, AccessGroupListOptions) ([]AccessGroup, error)
	DeleteAccessGroup(context.Context, AccessScope, string) error
}

// AccessGroupListOptions selects the endpoint and optional server-side filters.
type AccessGroupListOptions struct {
	Scope  AccessScope
	Name   string
	Search string
}

// AccessGroupInput is part of the Flareway API.
type AccessGroupInput struct {
	Name      string
	Include   []ResolvedAccessRule
	Require   []ResolvedAccessRule
	Exclude   []ResolvedAccessRule
	IsDefault bool
}

// AccessGroup is part of the Flareway API.
type AccessGroup struct {
	ID        string
	Name      string
	Include   []ResolvedAccessRule
	Require   []ResolvedAccessRule
	Exclude   []ResolvedAccessRule
	IsDefault *bool
	// Default preserves the rule-array form returned by Cloudflare's asymmetric
	// is_default response field.
	Default []ResolvedAccessRule
}

// CreateAccessGroup is part of the Flareway API.
func (client *Client) CreateAccessGroup(ctx context.Context, scope AccessScope, input AccessGroupInput) (AccessGroup, error) {
	params, err := accessGroupNewParams(client.accountID, scope, input)
	if err != nil {
		return AccessGroup{}, err
	}
	result, err := client.sdk.ZeroTrust.Access.Groups.New(ctx, params)
	if err != nil {
		return AccessGroup{}, fmt.Errorf("create Access group: %w", err)
	}
	group, err := accessGroupFromSDK(result.ID, result.Name, result.Include, result.Require, result.Exclude, result.IsDefault, result.JSON.RawJSON())
	if err != nil {
		return AccessGroup{ID: result.ID, Name: result.Name}, fmt.Errorf("decode created Access group: %w", err)
	}
	return group, nil
}

// UpdateAccessGroup is part of the Flareway API.
func (client *Client) UpdateAccessGroup(ctx context.Context, scope AccessScope, id string, input AccessGroupInput) (AccessGroup, error) {
	params, err := accessGroupUpdateParams(client.accountID, scope, input)
	if err != nil {
		return AccessGroup{}, err
	}
	result, err := client.sdk.ZeroTrust.Access.Groups.Update(ctx, id, params)
	if err != nil {
		return AccessGroup{}, fmt.Errorf("update Access group: %w", err)
	}
	resultID := result.ID
	if resultID == "" {
		resultID = id
	}
	group, err := accessGroupFromSDK(resultID, result.Name, result.Include, result.Require, result.Exclude, result.IsDefault, result.JSON.RawJSON())
	if err != nil {
		return AccessGroup{ID: resultID, Name: result.Name}, fmt.Errorf("decode updated Access group: %w", err)
	}
	return group, nil
}

// GetAccessGroup is part of the Flareway API.
func (client *Client) GetAccessGroup(ctx context.Context, scope AccessScope, id string) (AccessGroup, error) {
	params := zero_trust.AccessGroupGetParams{}
	applyAccessScope(client.accountID, scope,
		func(id string) { params.AccountID = cloudflaresdk.F(id) },
		func(id string) { params.ZoneID = cloudflaresdk.F(id) },
	)
	result, err := client.sdk.ZeroTrust.Access.Groups.Get(ctx, id, params)
	if err != nil {
		return AccessGroup{}, fmt.Errorf("get Access group: %w", err)
	}
	group, err := accessGroupFromSDK(result.ID, result.Name, result.Include, result.Require, result.Exclude, result.IsDefault, result.JSON.RawJSON())
	if err != nil {
		return AccessGroup{}, fmt.Errorf("decode Access group: %w", err)
	}
	return group, nil
}

// ListAccessGroups is part of the Flareway API.
func (client *Client) ListAccessGroups(ctx context.Context, options AccessGroupListOptions) ([]AccessGroup, error) {
	params := zero_trust.AccessGroupListParams{}
	applyAccessScope(client.accountID, options.Scope,
		func(id string) { params.AccountID = cloudflaresdk.F(id) },
		func(id string) { params.ZoneID = cloudflaresdk.F(id) },
	)
	if options.Name != "" {
		params.Name = cloudflaresdk.F(options.Name)
	}
	if options.Search != "" {
		params.Search = cloudflaresdk.F(options.Search)
	}
	pager := client.sdk.ZeroTrust.Access.Groups.ListAutoPaging(ctx, params)
	var out []AccessGroup
	for pager.Next() {
		result := pager.Current()
		group, err := accessGroupFromSDK(result.ID, result.Name, result.Include, result.Require, result.Exclude, result.IsDefault, result.JSON.RawJSON())
		if err != nil {
			return nil, fmt.Errorf("decode listed Access group %q: %w", result.ID, err)
		}
		out = append(out, group)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Access groups: %w", err)
	}
	return out, nil
}

// DeleteAccessGroup is part of the Flareway API.
func (client *Client) DeleteAccessGroup(ctx context.Context, scope AccessScope, id string) error {
	params := zero_trust.AccessGroupDeleteParams{}
	applyAccessScope(client.accountID, scope,
		func(id string) { params.AccountID = cloudflaresdk.F(id) },
		func(id string) { params.ZoneID = cloudflaresdk.F(id) },
	)
	if _, err := client.sdk.ZeroTrust.Access.Groups.Delete(ctx, id, params); err != nil {
		return fmt.Errorf("delete Access group: %w", err)
	}
	return nil
}
func accessGroupNewParams(accountID string, scope AccessScope, input AccessGroupInput) (zero_trust.AccessGroupNewParams, error) {
	include, require, exclude, err := accessGroupRulesToSDK(input)
	if err != nil {
		return zero_trust.AccessGroupNewParams{}, err
	}
	params := zero_trust.AccessGroupNewParams{
		Name:      cloudflaresdk.F(input.Name),
		Include:   cloudflaresdk.F(include),
		Require:   cloudflaresdk.F(require),
		Exclude:   cloudflaresdk.F(exclude),
		IsDefault: cloudflaresdk.F(input.IsDefault),
	}
	applyAccessScope(accountID, scope,
		func(id string) { params.AccountID = cloudflaresdk.F(id) },
		func(id string) { params.ZoneID = cloudflaresdk.F(id) },
	)
	return params, nil
}
func accessGroupUpdateParams(accountID string, scope AccessScope, input AccessGroupInput) (zero_trust.AccessGroupUpdateParams, error) {
	include, require, exclude, err := accessGroupRulesToSDK(input)
	if err != nil {
		return zero_trust.AccessGroupUpdateParams{}, err
	}
	params := zero_trust.AccessGroupUpdateParams{
		Name:      cloudflaresdk.F(input.Name),
		Include:   cloudflaresdk.F(include),
		Require:   cloudflaresdk.F(require),
		Exclude:   cloudflaresdk.F(exclude),
		IsDefault: cloudflaresdk.F(input.IsDefault),
	}
	applyAccessScope(accountID, scope,
		func(id string) { params.AccountID = cloudflaresdk.F(id) },
		func(id string) { params.ZoneID = cloudflaresdk.F(id) },
	)
	return params, nil
}
func accessGroupRulesToSDK(input AccessGroupInput) ([]zero_trust.AccessRuleUnionParam, []zero_trust.AccessRuleUnionParam, []zero_trust.AccessRuleUnionParam, error) {
	include, err := AccessRulesForSDK(input.Include)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode include rules: %w", err)
	}
	require, err := AccessRulesForSDK(input.Require)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode require rules: %w", err)
	}
	exclude, err := AccessRulesForSDK(input.Exclude)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode exclude rules: %w", err)
	}
	return include, require, exclude, nil
}

func accessGroupFromSDK(id, name string, include, require, exclude, defaultValue []zero_trust.AccessRule, raw string) (AccessGroup, error) {
	parsedInclude, err := AccessRulesFromSDK(include)
	if err != nil {
		return AccessGroup{}, fmt.Errorf("include rules: %w", err)
	}
	parsedRequire, err := AccessRulesFromSDK(require)
	if err != nil {
		return AccessGroup{}, fmt.Errorf("require rules: %w", err)
	}
	parsedExclude, err := AccessRulesFromSDK(exclude)
	if err != nil {
		return AccessGroup{}, fmt.Errorf("exclude rules: %w", err)
	}
	parsedDefault, err := AccessRulesFromSDK(defaultValue)
	if err != nil {
		return AccessGroup{}, fmt.Errorf("default rules: %w", err)
	}
	isDefault, err := accessGroupDefaultBoolean(raw)
	if err != nil {
		return AccessGroup{}, err
	}
	return AccessGroup{
		ID:        id,
		Name:      name,
		Include:   parsedInclude,
		Require:   parsedRequire,
		Exclude:   parsedExclude,
		IsDefault: isDefault,
		Default:   parsedDefault,
	}, nil
}

func accessGroupDefaultBoolean(raw string) (*bool, error) {
	if raw == "" {
		return nil, nil
	}
	var fields struct {
		IsDefault json.RawMessage `json:"is_default"`
	}
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return nil, fmt.Errorf("decode Access group raw response: %w", err)
	}
	value := bytes.TrimSpace(fields.IsDefault)
	if len(value) == 0 || bytes.Equal(value, []byte("null")) || value[0] == '[' {
		return nil, nil
	}
	if value[0] != 't' && value[0] != 'f' {
		return nil, fmt.Errorf("decode Access group is_default: unexpected JSON value %s", value)
	}
	var result bool
	if err := json.Unmarshal(value, &result); err != nil {
		return nil, fmt.Errorf("decode Access group is_default: %w", err)
	}
	return &result, nil
}
