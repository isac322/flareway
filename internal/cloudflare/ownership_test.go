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
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestIsOwnedDNSRecordStrict(t *testing.T) {
	const (
		comment = "flareway cluster-uid/apps/gateway"
		target  = "tunnel-uuid.cfargotunnel.com"
	)
	owned := DNSRecord{Type: "CNAME", Name: "app.example.com", Content: target, Comment: comment}

	tests := []struct {
		name  string
		check OwnedDNSRecordCheck
		want  bool
	}{
		{"marker and target match", OwnedDNSRecordCheck{Record: owned, ExpectedComment: comment, ExpectedTarget: target}, true},
		{"marker only when target empty", OwnedDNSRecordCheck{Record: owned, ExpectedComment: comment}, true},
		{"empty expected comment", OwnedDNSRecordCheck{Record: owned, ExpectedComment: "", ExpectedTarget: target}, false},
		{"marker mismatch", OwnedDNSRecordCheck{Record: owned, ExpectedComment: "flareway other", ExpectedTarget: target}, false},
		{"forged marker on A record", OwnedDNSRecordCheck{
			Record:          DNSRecord{Type: "A", Name: "app.example.com", Content: "203.0.113.9", Comment: comment},
			ExpectedComment: comment, ExpectedTarget: target,
		}, false},
		{"forged marker on foreign CNAME", OwnedDNSRecordCheck{
			Record:          DNSRecord{Type: "CNAME", Name: "app.example.com", Content: "evil.attacker.com", Comment: comment},
			ExpectedComment: comment, ExpectedTarget: target,
		}, false},
		{"target case and trailing dot normalized", OwnedDNSRecordCheck{
			Record:          DNSRecord{Type: "cname", Content: "Tunnel-UUID.CFARGOTUNNEL.COM.", Comment: comment},
			ExpectedComment: comment, ExpectedTarget: target,
		}, true},
		{"marker with user text still owned", OwnedDNSRecordCheck{
			Record:          DNSRecord{Type: "CNAME", Content: target, Comment: comment + " operator note"},
			ExpectedComment: comment, ExpectedTarget: target,
		}, true},
	}
	for _, test := range tests {
		if got := IsOwnedDNSRecordStrict(test.check); got != test.want {
			t.Errorf("%s: IsOwnedDNSRecordStrict() = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestSignedAccessTagsRespectLimitAndKey(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	otherKey := []byte("fedcba9876543210fedcba9876543210")

	signed := SignAccessOwnerTag(key, "cluster-uid", "apps", "gateway", "object-uid")
	if len(signed) != AccessTagNameMaxLength || !strings.HasPrefix(signed, AccessOwnerTagPrefix) {
		t.Fatalf("SignAccessOwnerTag() = %q", signed)
	}
	if signed == SignAccessOwnerTag(otherKey, "cluster-uid", "apps", "gateway", "object-uid") {
		t.Fatal("distinct keys produced the same owner tag")
	}
	if signed == SignAccessOwnerTag(key, "cluster-uid", "apps", "other", "object-uid") {
		t.Fatal("distinct identities produced the same owner tag")
	}

	bypass := SignAccessBypassTag(key, signed, "child")
	if len(bypass) != AccessTagNameMaxLength || !strings.HasPrefix(bypass, AccessBypassTagPrefix) {
		t.Fatalf("SignAccessBypassTag() = %q", bypass)
	}

	// Without a key the markers are the legacy plaintext digests.
	legacy := SignAccessOwnerTag(nil, "cluster-uid", "apps", "gateway", "object-uid")
	sum := sha256Digest(OwnerTag("cluster-uid", "apps", "gateway", "object-uid"))
	if legacy != AccessOwnerTagPrefix+sum[:AccessTagNameMaxLength-len(AccessOwnerTagPrefix)] {
		t.Fatalf("keyless SignAccessOwnerTag() = %q, want legacy digest", legacy)
	}
}

func TestVerifyAccessOwnerTagDualRead(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signed := SignAccessOwnerTag(key, "cluster-uid", "apps", "gateway", "object-uid")
	legacy := SignAccessOwnerTag(nil, "cluster-uid", "apps", "gateway", "object-uid")

	if matched, isLegacy := VerifyAccessOwnerTag(signed, key, "cluster-uid", "apps", "gateway", "object-uid"); !matched || isLegacy {
		t.Fatalf("signed tag rejected: matched=%v isLegacy=%v", matched, isLegacy)
	}
	if matched, isLegacy := VerifyAccessOwnerTag(legacy, key, "cluster-uid", "apps", "gateway", "object-uid"); !matched || !isLegacy {
		t.Fatalf("legacy tag rejected: matched=%v isLegacy=%v", matched, isLegacy)
	}
	if matched, _ := VerifyAccessOwnerTag(legacy, nil, "cluster-uid", "apps", "gateway", "object-uid"); !matched {
		t.Fatal("keyless verify rejected the legacy tag")
	}
	if matched, _ := VerifyAccessOwnerTag(signed, []byte("other-key"), "cluster-uid", "apps", "gateway", "object-uid"); matched {
		t.Fatal("tag signed by another key was accepted")
	}
	if matched, _ := VerifyAccessOwnerTag("flareway-owner-foreign", key, "cluster-uid", "apps", "gateway", "object-uid"); matched {
		t.Fatal("foreign tag was accepted")
	}
}

func TestSignDNSRecordComment(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	comment := SignDNSRecordComment(key, "cluster-uid", "apps", "gateway")
	if !strings.HasPrefix(comment, "flareway hmac:") || !strings.HasSuffix(comment, " apps/gateway") {
		t.Fatalf("SignDNSRecordComment() = %q", comment)
	}
	if utf8.RuneCountInString(comment) > dnsRecordCommentLimit {
		t.Fatalf("signed comment exceeds the limit: %d", utf8.RuneCountInString(comment))
	}
	if comment == SignDNSRecordComment(key, "cluster-uid", "apps", "other") {
		t.Fatal("distinct identities produced the same signed comment")
	}
	if comment == SignDNSRecordComment([]byte("other"), "cluster-uid", "apps", "gateway") {
		t.Fatal("distinct keys produced the same signed comment")
	}
	if got := SignDNSRecordComment(nil, "cluster-uid", "apps", "gateway"); got != DNSRecordComment("cluster-uid", "apps", "gateway") {
		t.Fatalf("keyless SignDNSRecordComment() = %q, want legacy marker", got)
	}

	longNamespace := strings.Repeat("네임스페이스", 20)
	longGateway := strings.Repeat("게이트웨이", 20)
	long := SignDNSRecordComment(key, "cluster-uid", longNamespace, longGateway)
	if utf8.RuneCountInString(long) > dnsRecordCommentLimit {
		t.Fatalf("long signed comment exceeds the limit: %d", utf8.RuneCountInString(long))
	}
	if !strings.HasPrefix(long, "flareway hmac:") {
		t.Fatalf("long signed comment lost the marker: %q", long)
	}

	withText := SignDNSRecordCommentWithText(key, "cluster-uid", "apps", "gateway", "operator note")
	if !IsOwnedDNSRecord(DNSRecord{Comment: withText}, comment) {
		t.Fatalf("signed comment with text was not recognized: %q", withText)
	}
}

func TestDNSRecordOwnershipMarkers(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	markers := DNSRecordOwnershipMarkers(key, "cluster-uid", "apps", "gateway")
	if len(markers) != 2 || markers[0] != SignDNSRecordComment(key, "cluster-uid", "apps", "gateway") || markers[1] != DNSRecordComment("cluster-uid", "apps", "gateway") {
		t.Fatalf("DNSRecordOwnershipMarkers() = %v", markers)
	}
	if markers := DNSRecordOwnershipMarkers(nil, "cluster-uid", "apps", "gateway"); len(markers) != 1 {
		t.Fatalf("keyless DNSRecordOwnershipMarkers() = %v", markers)
	}
}

func TestSignedPrivateResourceComment(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signed := SignPrivateResourceComment(key, "cluster-uid", "apps", "resource")
	if !strings.HasPrefix(signed, "flareway hmac:") {
		t.Fatalf("SignPrivateResourceComment() = %q", signed)
	}
	if !IsOwnedPrivateResourceSigned(signed, key, "cluster-uid", "apps", "resource") {
		t.Fatal("signed private resource comment was rejected")
	}
	if !IsOwnedPrivateResourceSigned(signed+" | note", key, "cluster-uid", "apps", "resource") {
		t.Fatal("signed private resource comment with text was rejected")
	}
	legacy := PrivateResourceComment("cluster-uid", "apps", "resource", "note")
	if !IsOwnedPrivateResourceSigned(legacy, key, "cluster-uid", "apps", "resource") {
		t.Fatal("legacy private resource comment was rejected")
	}
	if IsOwnedPrivateResourceSigned(legacy, key, "cluster-uid", "apps", "other") {
		t.Fatal("foreign private resource comment was accepted")
	}
	if got := SignPrivateResourceComment(nil, "cluster-uid", "apps", "resource"); got != PrivateResourceComment("cluster-uid", "apps", "resource", "") {
		t.Fatalf("keyless SignPrivateResourceComment() = %q", got)
	}
}

func TestTunnelDNSOwnershipMarkers(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	const (
		clusterID = "cluster-uid"
		namespace = "apps"
	)

	// Plaintext checkpoint with operator text + HMAC checkpoint with operator text,
	// plus verified overflow hash forms derived from supplied ownerNames.
	oldPlainComment := DNSRecordCommentWithText(clusterID, namespace, "old-plain-gw", "managed by team")
	oldHMACComment := SignDNSRecordCommentWithText(key, clusterID, namespace, "old-hmac-gw", "managed by team")
	longGateway := strings.Repeat("gw-", 30)
	overflowHMAC := SignDNSRecordComment(key, clusterID, namespace, longGateway)
	overflowPlain := DNSRecordComment(clusterID, namespace, longGateway)
	unverifiedOverflowHMAC := SignDNSRecordComment(key, "other-cluster", "other-ns", longGateway)
	unverifiedSHA256 := DNSRecordComment("other-cluster", "other-ns", longGateway)

	checkpoints := []string{
		oldPlainComment,
		oldHMACComment,
		// Negative cases that must all be ignored:
		unverifiedOverflowHMAC,
		unverifiedOverflowHMAC + " team/platform",
		unverifiedSHA256,
		"flareway hmac:00112233445566778899aabbccddeeff",
		"flareway hmac:00112233445566778899aabbccddeeff note",
		DNSRecordCommentWithText("other-cluster", namespace, "foreign-cluster-gw", "note"),
		DNSRecordCommentWithText(clusterID, "other-ns", "foreign-ns-gw", "note"),
		SignDNSRecordComment([]byte("wrong-key-0123456789abcdef012345"), clusterID, namespace, "forged-hmac-gw"),
		"flareway hmac:00112233445566778899aabbccddeeff " + namespace + "/tampered-gw",
		"flareway sha256:not-64-hex",
		"external-dns:heritage=external-dns",
	}

	markers := TunnelDNSOwnershipMarkers(key, clusterID, namespace, []string{"tunnel-name", "gateway-ref", longGateway}, checkpoints)
	for _, want := range []string{
		SignDNSRecordComment(key, clusterID, namespace, "tunnel-name"),
		DNSRecordComment(clusterID, namespace, "tunnel-name"),
		SignDNSRecordComment(key, clusterID, namespace, "gateway-ref"),
		DNSRecordComment(clusterID, namespace, "gateway-ref"),
		DNSRecordComment(clusterID, namespace, "old-plain-gw"),
		SignDNSRecordComment(key, clusterID, namespace, "old-plain-gw"),
		SignDNSRecordComment(key, clusterID, namespace, "old-hmac-gw"),
		DNSRecordComment(clusterID, namespace, "old-hmac-gw"),
		overflowHMAC,
		overflowPlain,
	} {
		if !slicesContains(markers, want) {
			t.Fatalf("TunnelDNSOwnershipMarkers() missing %q; got %v", want, markers)
		}
	}

	for _, reject := range []string{
		unverifiedOverflowHMAC,
		unverifiedSHA256,
		DNSRecordComment("other-cluster", namespace, "foreign-cluster-gw"),
		DNSRecordComment(clusterID, "other-ns", "foreign-ns-gw"),
		SignDNSRecordComment([]byte("wrong-key-0123456789abcdef012345"), clusterID, namespace, "forged-hmac-gw"),
		"flareway hmac:00112233445566778899aabbccddeeff",
		"external-dns:heritage=external-dns",
	} {
		if slicesContains(markers, reject) {
			t.Fatalf("TunnelDNSOwnershipMarkers() unexpectedly accepted %q", reject)
		}
	}

	// Without a key, HMAC checkpoint comments cannot be verified and must be rejected.
	keyless := TunnelDNSOwnershipMarkers(nil, clusterID, namespace, []string{"tunnel-name"}, []string{oldHMACComment, overflowHMAC})
	if slicesContains(keyless, overflowHMAC) || slicesContains(keyless, SignDNSRecordComment(key, clusterID, namespace, "old-hmac-gw")) {
		t.Fatalf("keyless TunnelDNSOwnershipMarkers() accepted unverified HMAC markers: %v", keyless)
	}
}

func slicesContains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func sha256Digest(identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return fmt.Sprintf("%x", sum)
}
