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

	cloudflaresdk "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
)

// AccessInfrastructureTargetAPI is the Cloudflare Access infrastructure-target surface.
type AccessInfrastructureTargetAPI interface {
	CreateAccessInfrastructureTarget(context.Context, AccessInfrastructureTargetInput) (AccessInfrastructureTarget, error)
	UpdateAccessInfrastructureTarget(context.Context, string, AccessInfrastructureTargetInput) (AccessInfrastructureTarget, error)
	GetAccessInfrastructureTarget(context.Context, string) (AccessInfrastructureTarget, error)
	ListAccessInfrastructureTargets(context.Context) ([]AccessInfrastructureTarget, error)
	DeleteAccessInfrastructureTarget(context.Context, string) error
	BulkDeleteAccessInfrastructureTargets(context.Context, []string) error
}

// AccessInfrastructureTargetAddress identifies one address and its optional virtual network.
type AccessInfrastructureTargetAddress struct {
	IPAddr           string
	VirtualNetworkID string
}

// AccessInfrastructureTargetInput is the mutable infrastructure-target state.
type AccessInfrastructureTargetInput struct {
	Hostname string
	IPV4     *AccessInfrastructureTargetAddress
	IPV6     *AccessInfrastructureTargetAddress
}

// AccessInfrastructureTarget is the observed infrastructure-target state.
type AccessInfrastructureTarget struct {
	ID       string
	Hostname string
	IPV4     *AccessInfrastructureTargetAddress
	IPV6     *AccessInfrastructureTargetAddress
}

// CreateAccessInfrastructureTarget creates an account-scoped infrastructure target.
func (client *Client) CreateAccessInfrastructureTarget(ctx context.Context, input AccessInfrastructureTargetInput) (AccessInfrastructureTarget, error) {
	params := zero_trust.AccessInfrastructureTargetNewParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Hostname:  cloudflaresdk.F(input.Hostname),
		IP:        cloudflaresdk.F(newInfrastructureTargetIP(input)),
	}
	response, err := client.sdk.ZeroTrust.Access.Infrastructure.Targets.New(ctx, params)
	if err != nil {
		return AccessInfrastructureTarget{}, err
	}
	if response == nil {
		return AccessInfrastructureTarget{}, errors.New("cloudflare Access infrastructure target create response is empty")
	}
	return validateInfrastructureTargetResponse(infrastructureTargetFromNew(*response))
}

// UpdateAccessInfrastructureTarget updates an account-scoped infrastructure target.
func (client *Client) UpdateAccessInfrastructureTarget(ctx context.Context, id string, input AccessInfrastructureTargetInput) (AccessInfrastructureTarget, error) {
	params := zero_trust.AccessInfrastructureTargetUpdateParams{
		AccountID: cloudflaresdk.F(client.accountID),
		Hostname:  cloudflaresdk.F(input.Hostname),
		IP:        cloudflaresdk.F(updateInfrastructureTargetIP(input)),
	}
	response, err := client.sdk.ZeroTrust.Access.Infrastructure.Targets.Update(ctx, id, params)
	if err != nil {
		return AccessInfrastructureTarget{}, err
	}
	if response == nil {
		return AccessInfrastructureTarget{}, errors.New("cloudflare Access infrastructure target update response is empty")
	}
	return validateInfrastructureTargetResponse(infrastructureTargetFromUpdate(*response))
}

// GetAccessInfrastructureTarget returns one account-scoped infrastructure target.
func (client *Client) GetAccessInfrastructureTarget(ctx context.Context, id string) (AccessInfrastructureTarget, error) {
	response, err := client.sdk.ZeroTrust.Access.Infrastructure.Targets.Get(ctx, id, zero_trust.AccessInfrastructureTargetGetParams{
		AccountID: cloudflaresdk.F(client.accountID),
	})
	if err != nil {
		return AccessInfrastructureTarget{}, err
	}
	if response == nil {
		return AccessInfrastructureTarget{}, errors.New("cloudflare Access infrastructure target get response is empty")
	}
	return validateInfrastructureTargetResponse(infrastructureTargetFromGet(*response))
}

// ListAccessInfrastructureTargets returns every account-scoped infrastructure target.
func (client *Client) ListAccessInfrastructureTargets(ctx context.Context) ([]AccessInfrastructureTarget, error) {
	pager := client.sdk.ZeroTrust.Access.Infrastructure.Targets.ListAutoPaging(ctx, zero_trust.AccessInfrastructureTargetListParams{
		AccountID: cloudflaresdk.F(client.accountID),
		PerPage:   cloudflaresdk.F(int64(accessListPerPage)),
	})
	result := make([]AccessInfrastructureTarget, 0)
	for pager.Next() {
		result = append(result, infrastructureTargetFromList(pager.Current()))
	}
	if err := pager.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// DeleteAccessInfrastructureTarget deletes one account-scoped infrastructure target.
func (client *Client) DeleteAccessInfrastructureTarget(ctx context.Context, id string) error {
	return client.sdk.ZeroTrust.Access.Infrastructure.Targets.Delete(ctx, id, zero_trust.AccessInfrastructureTargetDeleteParams{
		AccountID: cloudflaresdk.F(client.accountID),
	})
}

// BulkDeleteAccessInfrastructureTargets deletes exactly the supplied target IDs.
func (client *Client) BulkDeleteAccessInfrastructureTargets(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	for _, id := range ids {
		if id == "" {
			return errors.New("bulk delete Access infrastructure target ID is empty")
		}
	}
	return client.sdk.ZeroTrust.Access.Infrastructure.Targets.BulkDeleteV2(ctx, zero_trust.AccessInfrastructureTargetBulkDeleteV2Params{
		AccountID: cloudflaresdk.F(client.accountID),
		TargetIDs: cloudflaresdk.F(append([]string(nil), ids...)),
	})
}

func validateInfrastructureTargetResponse(target AccessInfrastructureTarget) (AccessInfrastructureTarget, error) {
	if target.ID == "" {
		return AccessInfrastructureTarget{}, errors.New("cloudflare Access infrastructure target response has an empty ID")
	}
	return target, nil
}

func newInfrastructureTargetIP(input AccessInfrastructureTargetInput) zero_trust.AccessInfrastructureTargetNewParamsIP {
	var result zero_trust.AccessInfrastructureTargetNewParamsIP
	if input.IPV4 != nil {
		value := zero_trust.AccessInfrastructureTargetNewParamsIPIPV4{IPAddr: cloudflaresdk.F(input.IPV4.IPAddr)}
		if input.IPV4.VirtualNetworkID != "" {
			value.VirtualNetworkID = cloudflaresdk.F(input.IPV4.VirtualNetworkID)
		}
		result.IPV4 = cloudflaresdk.F(value)
	}
	if input.IPV6 != nil {
		value := zero_trust.AccessInfrastructureTargetNewParamsIPIPV6{IPAddr: cloudflaresdk.F(input.IPV6.IPAddr)}
		if input.IPV6.VirtualNetworkID != "" {
			value.VirtualNetworkID = cloudflaresdk.F(input.IPV6.VirtualNetworkID)
		}
		result.IPV6 = cloudflaresdk.F(value)
	}
	return result
}

func updateInfrastructureTargetIP(input AccessInfrastructureTargetInput) zero_trust.AccessInfrastructureTargetUpdateParamsIP {
	var result zero_trust.AccessInfrastructureTargetUpdateParamsIP
	if input.IPV4 != nil {
		value := zero_trust.AccessInfrastructureTargetUpdateParamsIPIPV4{IPAddr: cloudflaresdk.F(input.IPV4.IPAddr)}
		if input.IPV4.VirtualNetworkID != "" {
			value.VirtualNetworkID = cloudflaresdk.F(input.IPV4.VirtualNetworkID)
		}
		result.IPV4 = cloudflaresdk.F(value)
	}
	if input.IPV6 != nil {
		value := zero_trust.AccessInfrastructureTargetUpdateParamsIPIPV6{IPAddr: cloudflaresdk.F(input.IPV6.IPAddr)}
		if input.IPV6.VirtualNetworkID != "" {
			value.VirtualNetworkID = cloudflaresdk.F(input.IPV6.VirtualNetworkID)
		}
		result.IPV6 = cloudflaresdk.F(value)
	}
	return result
}

func infrastructureTargetFromNew(value zero_trust.AccessInfrastructureTargetNewResponse) AccessInfrastructureTarget {
	return AccessInfrastructureTarget{
		ID:       value.ID,
		Hostname: value.Hostname,
		IPV4:     infrastructureTargetAddress(value.IP.IPV4.IPAddr, value.IP.IPV4.VirtualNetworkID),
		IPV6:     infrastructureTargetAddress(value.IP.IPV6.IPAddr, value.IP.IPV6.VirtualNetworkID),
	}
}

func infrastructureTargetFromUpdate(value zero_trust.AccessInfrastructureTargetUpdateResponse) AccessInfrastructureTarget {
	return AccessInfrastructureTarget{
		ID:       value.ID,
		Hostname: value.Hostname,
		IPV4:     infrastructureTargetAddress(value.IP.IPV4.IPAddr, value.IP.IPV4.VirtualNetworkID),
		IPV6:     infrastructureTargetAddress(value.IP.IPV6.IPAddr, value.IP.IPV6.VirtualNetworkID),
	}
}

func infrastructureTargetFromGet(value zero_trust.AccessInfrastructureTargetGetResponse) AccessInfrastructureTarget {
	return AccessInfrastructureTarget{
		ID:       value.ID,
		Hostname: value.Hostname,
		IPV4:     infrastructureTargetAddress(value.IP.IPV4.IPAddr, value.IP.IPV4.VirtualNetworkID),
		IPV6:     infrastructureTargetAddress(value.IP.IPV6.IPAddr, value.IP.IPV6.VirtualNetworkID),
	}
}

func infrastructureTargetFromList(value zero_trust.AccessInfrastructureTargetListResponse) AccessInfrastructureTarget {
	return AccessInfrastructureTarget{
		ID:       value.ID,
		Hostname: value.Hostname,
		IPV4:     infrastructureTargetAddress(value.IP.IPV4.IPAddr, value.IP.IPV4.VirtualNetworkID),
		IPV6:     infrastructureTargetAddress(value.IP.IPV6.IPAddr, value.IP.IPV6.VirtualNetworkID),
	}
}

func infrastructureTargetAddress(ipAddress, virtualNetworkID string) *AccessInfrastructureTargetAddress {
	if ipAddress == "" && virtualNetworkID == "" {
		return nil
	}
	return &AccessInfrastructureTargetAddress{IPAddr: ipAddress, VirtualNetworkID: virtualNetworkID}
}
