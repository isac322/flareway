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
	"strings"
	"time"

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

// DNSRecordSettings contains optional CNAME response-filtering settings.
type DNSRecordSettings struct {
	IPv4Only *bool
	IPv6Only *bool
}

// DNSRecordInput is the desired state for a CNAME record. Nil optional fields
// are omitted from Cloudflare requests.
type DNSRecordInput struct {
	Name     string
	Content  string
	Comment  string
	TTL      *int64
	Proxied  *bool
	Settings *DNSRecordSettings
}

// DNSRecord is the bounded remote record state used for ownership, drift, and
// status observations.
type DNSRecord struct {
	ID                string
	Name              string
	Type              string
	Content           string
	Comment           string
	TTL               int64
	Proxied           bool
	Proxiable         bool
	Settings          *DNSRecordSettings
	CreatedOn         time.Time
	ModifiedOn        time.Time
	CommentModifiedOn time.Time
}

// ListDNSRecords returns records of any type exactly matching name so callers
// can detect collisions before attempting to create a CNAME.
func (client *Client) ListDNSRecords(ctx context.Context, zoneID, name string) ([]DNSRecord, error) {
	normalizedName, err := NormalizeDNSHostname(name)
	if err != nil {
		return nil, err
	}
	pager := client.sdk.DNS.Records.ListAutoPaging(ctx, dns.RecordListParams{
		ZoneID: cloudflaresdk.F(zoneID),
		Name: cloudflaresdk.F(dns.RecordListParamsName{
			Exact: cloudflaresdk.F(normalizedName),
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
	body, err := cnameParams(input)
	if err != nil {
		return DNSRecord{}, err
	}
	result, err := client.sdk.DNS.Records.New(ctx, dns.RecordNewParams{
		ZoneID: cloudflaresdk.F(zoneID),
		Body:   body,
	})
	if err != nil {
		return DNSRecord{}, fmt.Errorf("create Cloudflare DNS record: %w", err)
	}
	return dnsRecordFromSDK(*result), nil
}

// UpdateCNAME updates the desired CNAME fields.
func (client *Client) UpdateCNAME(ctx context.Context, zoneID, recordID string, input DNSRecordInput) (DNSRecord, error) {
	body, err := cnameParams(input)
	if err != nil {
		return DNSRecord{}, err
	}
	result, err := client.sdk.DNS.Records.Update(ctx, recordID, dns.RecordUpdateParams{
		ZoneID: cloudflaresdk.F(zoneID),
		Body:   body,
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

func cnameParams(input DNSRecordInput) (dns.CNAMERecordParam, error) {
	name, err := NormalizeDNSHostname(input.Name)
	if err != nil {
		return dns.CNAMERecordParam{}, err
	}
	content, err := NormalizeDNSHostname(input.Content)
	if err != nil {
		return dns.CNAMERecordParam{}, fmt.Errorf("normalize CNAME content: %w", err)
	}
	if err := validateCNAMEInput(input); err != nil {
		return dns.CNAMERecordParam{}, err
	}

	body := dns.CNAMERecordParam{
		Name:    cloudflaresdk.F(name),
		Type:    cloudflaresdk.F(dns.CNAMERecordTypeCNAME),
		Content: cloudflaresdk.F(content),
	}
	if input.Comment != "" {
		body.Comment = cloudflaresdk.F(input.Comment)
	}
	if input.TTL != nil {
		body.TTL = cloudflaresdk.F(dns.TTL(*input.TTL))
	}
	if input.Proxied != nil {
		body.Proxied = cloudflaresdk.F(*input.Proxied)
	}
	if settings, present := cnameSettingsParams(input.Settings); present {
		body.Settings = cloudflaresdk.F(settings)
	}
	return body, nil
}

func validateCNAMEInput(input DNSRecordInput) error {
	if input.TTL != nil && *input.TTL != 1 && (*input.TTL < 60 || *input.TTL > 86400) {
		return fmt.Errorf("cloudflare DNS TTL must be 1 or between 60 and 86400 seconds")
	}
	if input.Proxied != nil && *input.Proxied && input.TTL != nil && *input.TTL != 1 {
		return fmt.Errorf("proxied Cloudflare DNS records require automatic TTL 1")
	}
	if input.Settings == nil {
		return nil
	}
	ipv4Only := input.Settings.IPv4Only != nil && *input.Settings.IPv4Only
	ipv6Only := input.Settings.IPv6Only != nil && *input.Settings.IPv6Only
	if ipv4Only && ipv6Only {
		return fmt.Errorf("cloudflare DNS ipv4Only and ipv6Only settings are mutually exclusive")
	}
	if (ipv4Only || ipv6Only) && (input.Proxied == nil || !*input.Proxied) {
		return fmt.Errorf("cloudflare DNS ipv4Only and ipv6Only settings require proxied=true")
	}
	return nil
}

func cnameSettingsParams(settings *DNSRecordSettings) (dns.CNAMERecordSettingsParam, bool) {
	if settings == nil || (settings.IPv4Only == nil && settings.IPv6Only == nil) {
		return dns.CNAMERecordSettingsParam{}, false
	}
	result := dns.CNAMERecordSettingsParam{}
	if settings.IPv4Only != nil {
		result.IPV4Only = cloudflaresdk.F(*settings.IPv4Only)
	}
	if settings.IPv6Only != nil {
		result.IPV6Only = cloudflaresdk.F(*settings.IPv6Only)
	}
	return result, true
}

func dnsRecordFromSDK(record dns.RecordResponse) DNSRecord {
	name := record.Name
	if normalized, err := NormalizeDNSHostname(name); err == nil {
		name = normalized
	}
	content := record.Content
	if strings.EqualFold(string(record.Type), "CNAME") {
		if normalized, err := NormalizeDNSHostname(content); err == nil {
			content = normalized
		}
	}
	return DNSRecord{
		ID:                record.ID,
		Name:              name,
		Type:              string(record.Type),
		Content:           content,
		Comment:           record.Comment,
		TTL:               int64(record.TTL),
		Proxied:           record.Proxied,
		Proxiable:         record.Proxiable,
		Settings:          dnsRecordSettings(record),
		CreatedOn:         record.CreatedOn,
		ModifiedOn:        record.ModifiedOn,
		CommentModifiedOn: record.CommentModifiedOn,
	}
}

func dnsRecordSettings(record dns.RecordResponse) *DNSRecordSettings {
	var wire struct {
		Settings *struct {
			IPv4Only *bool `json:"ipv4_only"`
			IPv6Only *bool `json:"ipv6_only"`
		} `json:"settings"`
	}
	if err := json.Unmarshal([]byte(record.JSON.RawJSON()), &wire); err != nil || wire.Settings == nil {
		return nil
	}
	return &DNSRecordSettings{
		IPv4Only: wire.Settings.IPv4Only,
		IPv6Only: wire.Settings.IPv6Only,
	}
}
