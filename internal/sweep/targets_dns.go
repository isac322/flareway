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

package sweep

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/types"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	flarecloudflare "github.com/isac322/flareway/internal/cloudflare"
)

// dnsCommentFilter is the substring passed to ListDNSRecordsByComment. Both
// marker families start with "flareway" ("flareway <clusterID>/..." and
// "flareway hmac:<hex>"), so one filtered listing per zone covers every
// record this controller could own.
const dnsCommentFilter = "flareway"

// tunnelCNAMETarget is the CNAME content a managed DNS record must point
// at, mirroring the controller's tunnelCNAMETarget.
func tunnelCNAMETarget(tunnelID string) string {
	return tunnelID + ".cfargotunnel.com"
}

// dnsTunnelInfo is one CloudflareTunnel's DNS ownership context.
type dnsTunnelInfo struct {
	key      types.NamespacedName
	tunnelID string
	// markers are every ownership comment a reader must accept for this
	// tunnel: signed and legacy, for the Gateway owner name (Gateway mode)
	// and the tunnel's own name (Direct mode).
	markers []string
	// checkpoints indexes status.dnsRecords by record ID.
	checkpoints map[string]v1alpha1.CloudflareTunnelDNSRecordStatus
}

// sweepDNSRecords judges managed DNS records against the zone-scoped
// comment-filtered listing (D6). Local truth is the CloudflareTunnel
// status.dnsRecords checkpoint, not a DNSRecord CR (none exists).
//
// Ownership is asymmetric per D12/C14#3: ExpectedTarget is always
// populated from the checkpoint's tunnel target; when the tunnel ID is
// unknown the record is treated as not owned — never as owned-by-default —
// and it is not even an orphan candidate.
func sweepDNSRecords(ctx context.Context, as *AccountSweeper) ([]DriftItem, error) {
	api, wait := as.remote()
	zones, err := as.zones(ctx)
	if err != nil {
		return nil, err
	}
	clusterID, err := as.clusterID(ctx)
	if err != nil {
		return nil, err
	}
	key := as.ownershipKey(ctx)

	// Collect the complete filtered listing across zones. Any zone that
	// fails makes the whole listing incomplete (fail-closed).
	remoteByID := make(map[string]flarecloudflare.DNSRecord)
	listedZones := make(map[string]bool, len(zones))
	for _, zone := range zones {
		if err := wait(ctx); err != nil {
			return nil, err
		}
		records, err := api.ListDNSRecordsByComment(ctx, zone.ID, dnsCommentFilter)
		if err != nil {
			return nil, listFailure(err)
		}
		listedZones[zone.ID] = true
		for _, record := range records {
			remoteByID[record.ID] = record
		}
	}

	var list v1alpha1.CloudflareTunnelList
	if err := as.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list CloudflareTunnels: %w", err)
	}
	var tunnels []dnsTunnelInfo
	claimed := make(map[string]bool)
	for i := range list.Items {
		tunnel := &list.Items[i]
		if tunnel.Spec.AccountRef.Name != as.accountName || deleting(tunnel) || observeOnly(tunnel.Spec.ManagementPolicy) {
			continue
		}
		info := dnsTunnelInfo{
			key:         types.NamespacedName{Namespace: tunnel.Namespace, Name: tunnel.Name},
			tunnelID:    tunnel.Status.TunnelID,
			checkpoints: make(map[string]v1alpha1.CloudflareTunnelDNSRecordStatus, len(tunnel.Status.DNSRecords)),
		}
		ownerNames := []string{tunnel.Name}
		if tunnel.Status.GatewayRef != nil && tunnel.Status.GatewayRef.Name != "" {
			ownerNames = append(ownerNames, tunnel.Status.GatewayRef.Name)
		}
		for _, ownerName := range ownerNames {
			info.markers = append(info.markers, dnsOwnershipMarkers(tunnel, key, clusterID, ownerName)...)
		}
		for _, checkpoint := range tunnel.Status.DNSRecords {
			if checkpoint.RecordID == "" {
				continue
			}
			info.checkpoints[checkpoint.RecordID] = checkpoint
			claimed[checkpoint.RecordID] = true
		}
		tunnels = append(tunnels, info)
	}

	items := make([]DriftItem, 0)
	for _, tunnel := range tunnels {
		for recordID, checkpoint := range tunnel.checkpoints {
			if !listedZones[checkpoint.ZoneID] {
				// The checkpoint's zone was not listed: no judgement, so a
				// zone that left the account can never produce a false
				// missing verdict.
				continue
			}
			remote, found := remoteByID[recordID]
			if !found {
				items = append(items, DriftItem{
					Kind: "DNSRecord", TargetKind: "CloudflareTunnel",
					NamespacedName: tunnel.key, RemoteID: recordID,
					Case:   DriftCaseMissing,
					Reason: fmt.Sprintf("checkpointed DNS record %s (%s) is absent from the zone listing", recordID, checkpoint.Hostname),
				})
				continue
			}
			if reason := dnsMismatchReason(tunnel, checkpoint, remote); reason != "" {
				items = append(items, DriftItem{
					Kind: "DNSRecord", TargetKind: "CloudflareTunnel",
					NamespacedName: tunnel.key, RemoteID: recordID,
					Case: DriftCaseMismatch, Reason: reason,
				})
			}
		}
	}

	// Orphan candidates: records carrying one of our markers that no
	// checkpoint claims. ExpectedTarget is always populated; a record whose
	// owning tunnel cannot be identified is not owned and not a candidate.
	for _, remote := range remoteByID {
		if claimed[remote.ID] {
			continue
		}
		if item, ok := dnsOrphanCandidate(remote, tunnels); ok {
			items = append(items, item)
		}
	}
	return items, nil
}

// dnsOwnershipMarkers returns every marker a reader must accept for one
// tunnel/owner-name pair, mirroring the controller's dnsOwnershipMarkers:
// the signed marker first, then the legacy plaintext marker. The marker is
// comment-prefix only — IsOwnedDNSRecord accepts an optional " | text"
// suffix, so the checkpointed human comment never has to be recomputed.
func dnsOwnershipMarkers(tunnel *v1alpha1.CloudflareTunnel, key []byte, clusterID, ownerName string) []string {
	signed := flarecloudflare.SignDNSRecordComment(key, clusterID, tunnel.Namespace, ownerName)
	legacy := flarecloudflare.DNSRecordComment(clusterID, tunnel.Namespace, ownerName)
	if signed == legacy {
		return []string{signed}
	}
	return []string{signed, legacy}
}

// dnsRecordOwned reports whether the remote record carries the checkpointed
// comment or any recomputed marker for this tunnel.
func dnsRecordOwned(record flarecloudflare.DNSRecord, checkpointComment string, markers []string) bool {
	if checkpointComment != "" && flarecloudflare.IsOwnedDNSRecord(record, checkpointComment) {
		return true
	}
	for _, marker := range markers {
		if flarecloudflare.IsOwnedDNSRecord(record, marker) {
			return true
		}
	}
	return false
}

// dnsMismatchReason reports why a checkpointed record disagrees with the
// remote, or "" when it agrees. The strict ownership check always carries
// ExpectedTarget when the tunnel ID is known (C14#3); without it the
// content check is impossible, so only the checkpointed scalar fields are
// compared.
func dnsMismatchReason(tunnel dnsTunnelInfo, checkpoint v1alpha1.CloudflareTunnelDNSRecordStatus, remote flarecloudflare.DNSRecord) string {
	if !dnsRecordOwned(remote, checkpoint.OwnershipComment, tunnel.markers) {
		return fmt.Sprintf("remote record comment %q no longer carries the checkpointed ownership marker", remote.Comment)
	}
	if tunnel.tunnelID != "" {
		owned := false
		for _, marker := range tunnel.markers {
			if flarecloudflare.IsOwnedDNSRecordStrict(flarecloudflare.OwnedDNSRecordCheck{
				Record: remote, ExpectedComment: marker,
				ExpectedTarget: tunnelCNAMETarget(tunnel.tunnelID),
			}) {
				owned = true
				break
			}
		}
		if !owned {
			return fmt.Sprintf("remote record is not a CNAME to %s (type %s, content %q)",
				tunnelCNAMETarget(tunnel.tunnelID), remote.Type, remote.Content)
		}
	}
	if !flarecloudflare.DNSHostnamesEqual(remote.Name, checkpoint.Hostname) {
		return fmt.Sprintf("remote record name %q no longer matches checkpointed hostname %q", remote.Name, checkpoint.Hostname)
	}
	// The checkpoint stores the exact comment written (marker + text), and
	// the controller's dnsRecordMatches compares it verbatim; a changed
	// suffix is drift even though the marker still matches.
	if checkpoint.OwnershipComment != "" && remote.Comment != checkpoint.OwnershipComment {
		return fmt.Sprintf("remote record comment %q no longer matches checkpointed comment %q", remote.Comment, checkpoint.OwnershipComment)
	}
	if checkpoint.TTL != 0 && remote.TTL != checkpoint.TTL {
		return fmt.Sprintf("remote record TTL %d does not match checkpointed TTL %d", remote.TTL, checkpoint.TTL)
	}
	if checkpoint.Proxied != nil && remote.Proxied != *checkpoint.Proxied {
		return fmt.Sprintf("remote record proxied %t does not match checkpointed proxied %t", remote.Proxied, *checkpoint.Proxied)
	}
	if reason := dnsSettingsDrift(checkpoint.Settings, remote.Settings); reason != "" {
		return reason
	}
	return ""
}

// dnsSettingsDrift compares the checkpointed DNS settings against the
// remote, mirroring the controller's dnsSettingsEqual: a nil desired flag
// accepts any remote value.
func dnsSettingsDrift(checkpoint *v1alpha1.DNSRecordSettings, remote *flarecloudflare.DNSRecordSettings) string {
	if checkpoint == nil {
		return ""
	}
	var remoteV4, remoteV6 *bool
	if remote != nil {
		remoteV4, remoteV6 = remote.IPv4Only, remote.IPv6Only
	}
	if !optionalBoolEqual(remoteV4, checkpoint.IPv4Only) {
		return fmt.Sprintf("remote ipv4Only %v does not match checkpointed %v", remoteV4, checkpoint.IPv4Only)
	}
	if !optionalBoolEqual(remoteV6, checkpoint.IPv6Only) {
		return fmt.Sprintf("remote ipv6Only %v does not match checkpointed %v", remoteV6, checkpoint.IPv6Only)
	}
	return ""
}

// optionalBoolEqual mirrors optionalDesiredBoolEqual: a nil desired value
// accepts anything.
func optionalBoolEqual(observed, desired *bool) bool {
	return desired == nil || observed != nil && *observed == *desired
}

// dnsOrphanCandidate judges one unclaimed remote record. A candidate must
// carry a marker of a live tunnel in this account AND point at that
// tunnel's CNAME target (ExpectedTarget is always populated). When the
// tunnel ID is unknown the record is not owned and not a candidate.
func dnsOrphanCandidate(remote flarecloudflare.DNSRecord, tunnels []dnsTunnelInfo) (DriftItem, bool) {
	for _, tunnel := range tunnels {
		if tunnel.tunnelID == "" {
			continue
		}
		owned := false
		for _, marker := range tunnel.markers {
			if flarecloudflare.IsOwnedDNSRecordStrict(flarecloudflare.OwnedDNSRecordCheck{
				Record: remote, ExpectedComment: marker,
				ExpectedTarget: tunnelCNAMETarget(tunnel.tunnelID),
			}) {
				owned = true
				break
			}
		}
		if !owned {
			continue
		}
		return DriftItem{
			Kind: "DNSRecord", TargetKind: "CloudflareTunnel",
			NamespacedName: tunnel.key, RemoteID: remote.ID,
			Case:   DriftCaseOrphan,
			Reason: fmt.Sprintf("remote record %s (%s) carries this tunnel's ownership marker but is not checkpointed", remote.ID, remote.Name),
		}, true
	}
	return DriftItem{}, false
}

// parseTunnelTarget extracts the tunnel ID from a "<id>.cfargotunnel.com"
// CNAME target. Used by tests and future orphan-cleanup verification.
func parseTunnelTarget(content string) (string, bool) {
	id, found := strings.CutSuffix(strings.ToLower(strings.TrimSuffix(content, ".")), ".cfargotunnel.com")
	if !found || id == "" {
		return "", false
	}
	return id, true
}
