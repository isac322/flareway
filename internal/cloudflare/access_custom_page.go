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

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
)

// One million results is far above realistic account totals while bounding malformed pagination.
const (
	accessCustomPageListPerPage  = int64(1000)
	accessCustomPageListMaxPages = int64(1000)
)

// AccessCustomPageAPI is the account-level Cloudflare Access custom-page surface.
type AccessCustomPageAPI interface {
	CreateAccessCustomPage(context.Context, AccessCustomPageInput) (AccessCustomPage, error)
	UpdateAccessCustomPage(context.Context, string, AccessCustomPageInput) (AccessCustomPage, error)
	GetAccessCustomPage(context.Context, string) (AccessCustomPage, error)
	ListAccessCustomPages(context.Context) ([]AccessCustomPageSummary, error)
	DeleteAccessCustomPage(context.Context, string) (string, error)
}

// AccessCustomPageInput is the desired mutable state of an Access custom page.
type AccessCustomPageInput struct {
	Name            string
	Type            v1alpha1.AccessCustomPageType
	HTML            string
	ContractVersion *int64
}

// AccessCustomPage is a full custom-page observation, including its HTML.
type AccessCustomPage struct {
	AccessCustomPageSummary
	HTML string
}

// AccessCustomPageSummary is the HTML-free response returned by list, create, and update.
type AccessCustomPageSummary struct {
	ID              string
	Name            string
	Type            v1alpha1.AccessCustomPageType
	ContractVersion int64
	Warnings        []AccessCustomPageWarning
}

// AccessCustomPageWarning is an advisory HTML or Liquid validation finding.
type AccessCustomPageWarning struct {
	Message string
	Tier    string
	Ref     string
}

// CreateAccessCustomPage is part of the Flareway API.
func (client *Client) CreateAccessCustomPage(ctx context.Context, input AccessCustomPageInput) (AccessCustomPage, error) {
	body, err := accessCustomPageParam(input)
	if err != nil {
		return AccessCustomPage{}, err
	}
	result, err := client.sdk.ZeroTrust.Access.CustomPages.New(ctx, zero_trust.AccessCustomPageNewParams{
		AccountID:  cloudflaresdk.F(client.accountID),
		CustomPage: body,
	})
	if err != nil {
		return AccessCustomPage{}, fmt.Errorf("create Access custom page: %w", err)
	}
	summary, err := accessCustomPageSummaryFromSDK(result)
	if err != nil {
		return AccessCustomPage{}, err
	}
	return AccessCustomPage{AccessCustomPageSummary: summary, HTML: input.HTML}, nil
}

// UpdateAccessCustomPage is part of the Flareway API.
func (client *Client) UpdateAccessCustomPage(ctx context.Context, id string, input AccessCustomPageInput) (AccessCustomPage, error) {
	if id == "" {
		return AccessCustomPage{}, fmt.Errorf("access custom page ID is required")
	}
	body, err := accessCustomPageParam(input)
	if err != nil {
		return AccessCustomPage{}, err
	}
	result, err := client.sdk.ZeroTrust.Access.CustomPages.Update(ctx, id, zero_trust.AccessCustomPageUpdateParams{
		AccountID:  cloudflaresdk.F(client.accountID),
		CustomPage: body,
	})
	if err != nil {
		return AccessCustomPage{}, fmt.Errorf("update Access custom page: %w", err)
	}
	summary, err := accessCustomPageSummaryFromSDK(result)
	if err != nil {
		return AccessCustomPage{}, err
	}
	return AccessCustomPage{AccessCustomPageSummary: summary, HTML: input.HTML}, nil
}

// GetAccessCustomPage is part of the Flareway API.
func (client *Client) GetAccessCustomPage(ctx context.Context, id string) (AccessCustomPage, error) {
	if id == "" {
		return AccessCustomPage{}, fmt.Errorf("access custom page ID is required")
	}
	result, err := client.sdk.ZeroTrust.Access.CustomPages.Get(ctx, id, zero_trust.AccessCustomPageGetParams{
		AccountID: cloudflaresdk.F(client.accountID),
	})
	if err != nil {
		return AccessCustomPage{}, fmt.Errorf("get Access custom page: %w", err)
	}
	pageType, err := accessCustomPageTypeFromSDK(string(result.Type))
	if err != nil {
		return AccessCustomPage{}, err
	}
	return AccessCustomPage{
		AccessCustomPageSummary: AccessCustomPageSummary{
			ID: result.UID, Name: result.Name, Type: pageType, ContractVersion: result.ContractVersion,
		},
		HTML: result.CustomHTML,
	}, nil
}

// ListAccessCustomPages is part of the Flareway API.
func (client *Client) ListAccessCustomPages(ctx context.Context) ([]AccessCustomPageSummary, error) {
	type paginationIdentity struct {
		id, name, pageType string
	}
	identityFor := func(page *zero_trust.CustomPageWithoutHTML) paginationIdentity {
		return paginationIdentity{id: page.UID, name: page.Name, pageType: string(page.Type)}
	}
	result := make([]AccessCustomPageSummary, 0)
	var previousPage []paginationIdentity
	complete := false
	for pageNumber := int64(1); pageNumber <= accessCustomPageListMaxPages; pageNumber++ {
		page, err := client.sdk.ZeroTrust.Access.CustomPages.List(ctx, zero_trust.AccessCustomPageListParams{
			AccountID: cloudflaresdk.F(client.accountID),
			Page:      cloudflaresdk.F(pageNumber),
			PerPage:   cloudflaresdk.F(accessCustomPageListPerPage),
		})
		if err != nil {
			return nil, fmt.Errorf("list Access custom pages: %w", err)
		}
		if len(page.Result) == 0 {
			complete = true
			break
		}
		nonAdvancing := len(previousPage) == len(page.Result)
		for index := range page.Result {
			if nonAdvancing && previousPage[index] != identityFor(&page.Result[index]) {
				nonAdvancing = false
			}
		}
		if pageNumber > 1 && nonAdvancing {
			return nil, fmt.Errorf("list Access custom pages: pagination did not advance at page %d", pageNumber)
		}
		for index := range page.Result {
			summary, err := accessCustomPageSummaryFromSDK(&page.Result[index])
			if err != nil {
				return nil, err
			}
			result = append(result, summary)
		}
		if int64(len(page.Result)) < accessCustomPageListPerPage {
			complete = true
			break
		}
		previousPage = previousPage[:0]
		for index := range page.Result {
			previousPage = append(previousPage, identityFor(&page.Result[index]))
		}
	}
	if !complete {
		return nil, fmt.Errorf("list Access custom pages: exceeded pagination limit of %d pages", accessCustomPageListMaxPages)
	}
	return result, nil
}

// DeleteAccessCustomPage is part of the Flareway API.
func (client *Client) DeleteAccessCustomPage(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("access custom page ID is required")
	}
	result, err := client.sdk.ZeroTrust.Access.CustomPages.Delete(ctx, id, zero_trust.AccessCustomPageDeleteParams{
		AccountID: cloudflaresdk.F(client.accountID),
	})
	if err != nil {
		return "", fmt.Errorf("delete Access custom page: %w", err)
	}
	return result.ID, nil
}

func accessCustomPageParam(input AccessCustomPageInput) (zero_trust.CustomPageParam, error) {
	if input.Name == "" {
		return zero_trust.CustomPageParam{}, fmt.Errorf("access custom page name is required")
	}
	if input.HTML == "" {
		return zero_trust.CustomPageParam{}, fmt.Errorf("access custom page HTML is required")
	}
	pageType, err := accessCustomPageTypeToSDK(input.Type)
	if err != nil {
		return zero_trust.CustomPageParam{}, err
	}
	result := zero_trust.CustomPageParam{
		CustomHTML: cloudflaresdk.F(input.HTML),
		Name:       cloudflaresdk.F(input.Name),
		Type:       cloudflaresdk.F(pageType),
	}
	if input.ContractVersion != nil {
		if *input.ContractVersion < 1 {
			return zero_trust.CustomPageParam{}, fmt.Errorf("access custom page contract version must be at least 1")
		}
		result.ContractVersion = cloudflaresdk.F(*input.ContractVersion)
	}
	return result, nil
}

func accessCustomPageSummaryFromSDK(value *zero_trust.CustomPageWithoutHTML) (AccessCustomPageSummary, error) {
	pageType, err := accessCustomPageTypeFromSDK(string(value.Type))
	if err != nil {
		return AccessCustomPageSummary{}, err
	}
	warnings := make([]AccessCustomPageWarning, len(value.Warnings))
	for index := range value.Warnings {
		warnings[index] = AccessCustomPageWarning{
			Message: value.Warnings[index].Message,
			Tier:    value.Warnings[index].Tier,
			Ref:     value.Warnings[index].Ref,
		}
	}
	return AccessCustomPageSummary{
		ID: value.UID, Name: value.Name, Type: pageType, ContractVersion: value.ContractVersion, Warnings: warnings,
	}, nil
}

func accessCustomPageTypeToSDK(value v1alpha1.AccessCustomPageType) (zero_trust.CustomPageType, error) {
	switch value {
	case v1alpha1.AccessCustomPageTypeIdentityDenied:
		return zero_trust.CustomPageTypeIdentityDenied, nil
	case v1alpha1.AccessCustomPageTypeForbidden:
		return zero_trust.CustomPageTypeForbidden, nil
	case v1alpha1.AccessCustomPageTypeLogin:
		return zero_trust.CustomPageTypeLogin, nil
	case v1alpha1.AccessCustomPageTypeInterstitial:
		return zero_trust.CustomPageTypeInterstitial, nil
	default:
		return "", fmt.Errorf("unsupported Access custom page type %q", value)
	}
}

func accessCustomPageTypeFromSDK(value string) (v1alpha1.AccessCustomPageType, error) {
	switch value {
	case string(zero_trust.CustomPageTypeIdentityDenied):
		return v1alpha1.AccessCustomPageTypeIdentityDenied, nil
	case string(zero_trust.CustomPageTypeForbidden):
		return v1alpha1.AccessCustomPageTypeForbidden, nil
	case string(zero_trust.CustomPageTypeLogin):
		return v1alpha1.AccessCustomPageTypeLogin, nil
	case string(zero_trust.CustomPageTypeInterstitial):
		return v1alpha1.AccessCustomPageTypeInterstitial, nil
	default:
		return "", fmt.Errorf("unsupported Cloudflare Access custom page type %q", value)
	}
}
