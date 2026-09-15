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
	"errors"
	"fmt"
	"slices"

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
)

const (
	// AccessTagNameMaxLength is Cloudflare's maximum Access tag name length.
	AccessTagNameMaxLength = 35
	// AccessApplicationTagLimit is Cloudflare's maximum number of tags on one Access application.
	AccessApplicationTagLimit = 25
)

// One million results is far above realistic account totals while bounding malformed pagination.
const (
	accessTagListPerPage  = int64(1000)
	accessTagListMaxPages = int64(1000)
)

// AccessTagAPI is part of the Flareway API.
type AccessTagAPI interface {
	GetAccessTag(context.Context, string) (AccessTag, error)
	ListAccessTags(context.Context) ([]AccessTag, error)
	CreateAccessTag(context.Context, string) (AccessTag, error)
	UpdateAccessTag(context.Context, string, string) (AccessTag, error)
	DeleteAccessTag(context.Context, string) error
}

// AccessTag is the secret-free Access application tag representation.
type AccessTag struct {
	Name string
}

// GetAccessTag is part of the Flareway API.
func (client *Client) GetAccessTag(ctx context.Context, name string) (AccessTag, error) {
	if err := validateAccessTagName(name); err != nil {
		return AccessTag{}, err
	}
	result, err := client.sdk.ZeroTrust.Access.Tags.Get(ctx, name, zero_trust.AccessTagGetParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return AccessTag{}, fmt.Errorf("get Access tag: %w", err)
	}
	return AccessTag{Name: result.Name}, nil
}

// ListAccessTags is part of the Flareway API.
func (client *Client) ListAccessTags(ctx context.Context) ([]AccessTag, error) {
	result := make([]AccessTag, 0)
	var previousPage []string
	complete := false
	for pageNumber := int64(1); pageNumber <= accessTagListMaxPages; pageNumber++ {
		page, err := client.sdk.ZeroTrust.Access.Tags.List(ctx, zero_trust.AccessTagListParams{
			AccountID: cloudflaresdk.F(client.accountID),
			Page:      cloudflaresdk.F(pageNumber),
			PerPage:   cloudflaresdk.F(accessTagListPerPage),
		})
		if err != nil {
			return nil, fmt.Errorf("list Access tags: %w", err)
		}
		if len(page.Result) == 0 {
			complete = true
			break
		}
		nonAdvancing := len(previousPage) == len(page.Result)
		for index, tag := range page.Result {
			if nonAdvancing && previousPage[index] != tag.Name {
				nonAdvancing = false
			}
			result = append(result, AccessTag{Name: tag.Name})
		}
		if pageNumber > 1 && nonAdvancing {
			return nil, fmt.Errorf("list Access tags: pagination did not advance at page %d", pageNumber)
		}
		if int64(len(page.Result)) < accessTagListPerPage {
			complete = true
			break
		}
		previousPage = previousPage[:0]
		for _, tag := range page.Result {
			previousPage = append(previousPage, tag.Name)
		}
	}
	if !complete {
		return nil, fmt.Errorf("list Access tags: exceeded pagination limit of %d pages", accessTagListMaxPages)
	}
	slices.SortFunc(result, func(left, right AccessTag) int {
		return compareString(left.Name, right.Name)
	})
	return result, nil
}

// CreateAccessTag is part of the Flareway API.
func (client *Client) CreateAccessTag(ctx context.Context, name string) (AccessTag, error) {
	if err := validateAccessTagName(name); err != nil {
		return AccessTag{}, err
	}
	result, err := client.sdk.ZeroTrust.Access.Tags.New(ctx, zero_trust.AccessTagNewParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Name:      cloudflaresdk.F(name),
	})
	if err != nil {
		return AccessTag{}, fmt.Errorf("create Access tag: %w", err)
	}
	return AccessTag{Name: result.Name}, nil
}

// UpdateAccessTag is part of the Flareway API.
func (client *Client) UpdateAccessTag(ctx context.Context, oldName, newName string) (AccessTag, error) {
	if err := validateAccessTagName(oldName); err != nil {
		return AccessTag{}, fmt.Errorf("old Access tag name: %w", err)
	}
	if err := validateAccessTagName(newName); err != nil {
		return AccessTag{}, fmt.Errorf("new Access tag name: %w", err)
	}
	result, err := client.sdk.ZeroTrust.Access.Tags.Update(ctx, oldName, zero_trust.AccessTagUpdateParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Name:      cloudflaresdk.F(newName),
	})
	if err != nil {
		return AccessTag{}, fmt.Errorf("update Access tag: %w", err)
	}
	return AccessTag{Name: result.Name}, nil
}

// DeleteAccessTag is part of the Flareway API.
func (client *Client) DeleteAccessTag(ctx context.Context, name string) error {
	if err := validateAccessTagName(name); err != nil {
		return err
	}
	_, err := client.sdk.ZeroTrust.Access.Tags.Delete(ctx, name, zero_trust.AccessTagDeleteParams{AccountID: cloudflaresdk.F(client.accountID)})
	if err != nil {
		return fmt.Errorf("delete Access tag: %w", err)
	}
	return nil
}

func validateAccessTagName(name string) error {
	if name == "" {
		return errors.New("access tag name is required")
	}
	if len(name) > AccessTagNameMaxLength {
		return fmt.Errorf("access tag name must not exceed %d characters", AccessTagNameMaxLength)
	}
	for index := range len(name) {
		value := name[index]
		if (value >= 'a' && value <= 'z') ||
			(value >= 'A' && value <= 'Z') ||
			(value >= '0' && value <= '9') ||
			value == '_' || value == '-' {
			continue
		}
		return fmt.Errorf("access tag name %q contains unsupported character %q", name, value)
	}
	return nil
}

func compareString(left, right string) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}
