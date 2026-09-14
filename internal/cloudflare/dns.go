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
	"github.com/cloudflare/cloudflare-go/v7/dns"
)

// DNSAPI is the public DNS record surface used by the tunnel controller.
type DNSAPI interface {
	ListDNSRecords(ctx context.Context, zoneID, name string) ([]DNSRecord, error)
	CreateCNAME(ctx context.Context, zoneID string, input DNSRecordInput) (DNSRecord, error)
	UpdateCNAME(ctx context.Context, zoneID, recordID string, input DNSRecordInput) (DNSRecord, error)
	DeleteDNSRecord(ctx context.Context, zoneID, recordID string) error
}

// DNSRecordInput is the desired state for a proxied CNAME record. Empty tags are omitted.
type DNSRecordInput struct {
	Name    string
	Content string
	Comment string
	Tags    []string
	Proxied bool
}

// DNSRecord is the remote record state used for ownership and conflict checks.
type DNSRecord struct {
	ID      string
	Name    string
	Type    string
	Content string
	Comment string
	Tags    []string
	Proxied bool
}

// ListDNSRecords returns records of any type exactly matching name so callers
// can detect collisions before attempting to create a CNAME.
func (client *Client) ListDNSRecords(ctx context.Context, zoneID, name string) ([]DNSRecord, error) {
	pager := client.sdk.DNS.Records.ListAutoPaging(ctx, dns.RecordListParams{
		ZoneID: cloudflaresdk.F(zoneID),
		Name: cloudflaresdk.F(dns.RecordListParamsName{
			Exact: cloudflaresdk.F(name),
		}),
		PerPage: cloudflaresdk.F(100.0),
	})

	result := make([]DNSRecord, 0)
	for pager.Next() {
		record := pager.Current()
		result = append(result, dnsRecordFromSDK(record))
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("list Cloudflare DNS records: %w", err)
	}
	return result, nil
}

// CreateCNAME creates a complete CNAME record using cloudflare-go's typed union payload.
func (client *Client) CreateCNAME(ctx context.Context, zoneID string, input DNSRecordInput) (DNSRecord, error) {
	result, err := client.sdk.DNS.Records.New(ctx, dns.RecordNewParams{
		ZoneID: cloudflaresdk.F(zoneID),
		Body:   cnameParams(input),
	})
	if err != nil {
		return DNSRecord{}, fmt.Errorf("create Cloudflare DNS record: %w", err)
	}
	return dnsRecordFromSDK(*result), nil
}

// UpdateCNAME updates the desired CNAME fields.
func (client *Client) UpdateCNAME(ctx context.Context, zoneID, recordID string, input DNSRecordInput) (DNSRecord, error) {
	result, err := client.sdk.DNS.Records.Update(ctx, recordID, dns.RecordUpdateParams{
		ZoneID: cloudflaresdk.F(zoneID),
		Body:   cnameParams(input),
	})
	if err != nil {
		return DNSRecord{}, fmt.Errorf("update Cloudflare DNS record: %w", err)
	}
	return dnsRecordFromSDK(*result), nil
}

// DeleteDNSRecord deletes a record by zone and record ID.
func (client *Client) DeleteDNSRecord(ctx context.Context, zoneID, recordID string) error {
	_, err := client.sdk.DNS.Records.Delete(ctx, recordID, dns.RecordDeleteParams{
		ZoneID: cloudflaresdk.F(zoneID),
	})
	if err != nil {
		return fmt.Errorf("delete Cloudflare DNS record: %w", err)
	}
	return nil
}

func cnameParams(input DNSRecordInput) dns.CNAMERecordParam {
	body := dns.CNAMERecordParam{
		Name:    cloudflaresdk.F(input.Name),
		TTL:     cloudflaresdk.F(dns.TTL1),
		Type:    cloudflaresdk.F(dns.CNAMERecordTypeCNAME),
		Comment: cloudflaresdk.F(input.Comment),
		Content: cloudflaresdk.F(input.Content),
		Proxied: cloudflaresdk.F(input.Proxied),
	}
	if len(input.Tags) > 0 {
		tags := make([]dns.RecordTagsParam, len(input.Tags))
		copy(tags, input.Tags)
		body.Tags = cloudflaresdk.F(tags)
	}
	return body
}

func dnsRecordFromSDK(record dns.RecordResponse) DNSRecord {
	return DNSRecord{
		ID:      record.ID,
		Name:    record.Name,
		Type:    string(record.Type),
		Content: record.Content,
		Comment: record.Comment,
		Tags:    dnsRecordTags(record.Tags),
		Proxied: record.Proxied,
	}
}

func dnsRecordTags(value any) []string {
	switch tags := value.(type) {
	case []string:
		return append([]string(nil), tags...)
	case []any:
		result := make([]string, 0, len(tags))
		for _, tag := range tags {
			if text, ok := tag.(string); ok {
				result = append(result, text)
			}
		}
		return result
	default:
		return nil
	}
}
