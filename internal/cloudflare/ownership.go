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
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strings"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/types"
)

// HMAC ownership markers (D8). The plaintext markers in ledger.go are
// publicly derivable from the cluster UID, namespace, and object name, so a
// caller that knows those values can forge ownership. The functions below
// sign the same identities with a cluster-local HMAC-SHA256 key.
//
// Key lifecycle is intentionally out of scope for this package: callers pass
// the key bytes they resolved (a controller-owned Secret is planned for a
// later wave). An empty key preserves the pre-HMAC behavior exactly — signing
// falls back to the legacy plaintext marker — so a missing key never disables
// the feature; it only skips the hardening.
//
// Migration contract: writes always use the Sign* functions (HMAC when a key
// is present, plaintext otherwise) and reads accept either marker through the
// Verify*/dual-read helpers.

const (
	// AccessOwnerTagPrefix prefixes the signed Access application owner tag.
	AccessOwnerTagPrefix = "flareway-owner-"
	// AccessBypassTagPrefix prefixes the signed Access bypass application tag.
	AccessBypassTagPrefix = "flareway-bypass-"
)

const (
	// hmacMarkerPrefix prefixes HMAC-signed comment markers.
	hmacMarkerPrefix = "flareway hmac:"
	// hmacMarkerHexLength is the hex length of the truncated HMAC-SHA256
	// carried by comment markers (first 16 bytes).
	hmacMarkerHexLength = 32
	// privateResourceCommentLimit mirrors the 100-code-point budget callers
	// apply to private resource comments.
	privateResourceCommentLimit = 100
)

// SignAccessOwnerTag returns the Access application owner tag for one
// Kubernetes object. With a key it is an HMAC-SHA256 marker; without a key it
// falls back to the legacy plaintext digest. The result never exceeds
// AccessTagNameMaxLength.
func SignAccessOwnerTag(key []byte, clusterID, namespace, name string, uid types.UID) string {
	return signAccessDigestTag(key, AccessOwnerTagPrefix, OwnerTag(clusterID, namespace, name, uid))
}

// SignAccessBypassTag returns the Access bypass application tag derived from
// the parent owner tag and the child name. The key fallback matches
// SignAccessOwnerTag.
func SignAccessBypassTag(key []byte, ownerTag, childName string) string {
	return signAccessDigestTag(key, AccessBypassTagPrefix, ownerTag+"\x00"+childName)
}

// VerifyAccessOwnerTag reports whether tag is the owner marker for the given
// identity. It accepts the HMAC marker and, for migration, the legacy
// plaintext digest. The second return value reports whether the match used
// the legacy marker.
func VerifyAccessOwnerTag(tag string, key []byte, clusterID, namespace, name string, uid types.UID) (matched, isLegacy bool) {
	identity := OwnerTag(clusterID, namespace, name, uid)
	return verifyAccessDigestTag(tag, key, AccessOwnerTagPrefix, identity)
}

// VerifyAccessBypassTag reports whether tag is the bypass marker derived from
// the parent owner tag and child name, accepting both the HMAC marker and the
// legacy plaintext digest. The second return value reports whether the match
// used the legacy marker.
func VerifyAccessBypassTag(tag string, key []byte, ownerTag, childName string) (matched, isLegacy bool) {
	return verifyAccessDigestTag(tag, key, AccessBypassTagPrefix, ownerTag+"\x00"+childName)
}

// signAccessDigestTag formats a bounded Access tag: prefix plus a truncated
// hex digest of identity. With a key the digest is HMAC-SHA256; without one it
// is the legacy plain SHA-256.
func signAccessDigestTag(key []byte, prefix, identity string) string {
	var hexDigest string
	if len(key) == 0 {
		sum := sha256.Sum256([]byte(identity))
		hexDigest = fmt.Sprintf("%x", sum)
	} else {
		hexDigest = fmt.Sprintf("%x", hmacSHA256(key, identity))
	}
	return prefix + hexDigest[:AccessTagNameMaxLength-len(prefix)]
}

// verifyAccessDigestTag matches tag against the signed marker first and the
// legacy plaintext digest second.
func verifyAccessDigestTag(tag string, key []byte, prefix, identity string) (matched, isLegacy bool) {
	if len(key) > 0 && tag == signAccessDigestTag(key, prefix, identity) {
		return true, false
	}
	if tag == signAccessDigestTag(nil, prefix, identity) {
		return true, true
	}
	return false, false
}

// SignDNSRecordComment returns the HMAC-signed DNS ownership marker for one
// Gateway, no longer than Cloudflare's 100-code-point comment limit. The
// marker is "flareway hmac:<32hex> <namespace>/<gatewayName>" when the
// identity fits and "flareway hmac:<32hex>" otherwise. Without a key it falls
// back to DNSRecordComment.
func SignDNSRecordComment(key []byte, clusterID, namespace, gatewayName string) string {
	if len(key) == 0 {
		return DNSRecordComment(clusterID, namespace, gatewayName)
	}
	identity := fmt.Sprintf("%s/%s/%s", clusterID, namespace, gatewayName)
	marker := fmt.Sprintf("%s%x", hmacMarkerPrefix, hmacSHA256(key, identity)[:hmacMarkerHexLength/2])
	suffix := namespace + "/" + gatewayName
	if utf8.RuneCountInString(marker)+utf8.RuneCountInString(dnsRecordCommentSeparator)+utf8.RuneCountInString(suffix) <= dnsRecordCommentLimit {
		return marker + dnsRecordCommentSeparator + suffix
	}
	return marker
}

// SignDNSRecordCommentWithText appends a human comment to the signed DNS
// ownership marker without exceeding the Cloudflare DNS comment limit. The
// marker is never truncated.
func SignDNSRecordCommentWithText(key []byte, clusterID, namespace, gatewayName, text string) string {
	return dnsRecordCommentWithText(SignDNSRecordComment(key, clusterID, namespace, gatewayName), text)
}

// DNSRecordOwnershipMarkers returns every comment marker a reader must accept
// for one Gateway: the signed marker first and the legacy plaintext marker
// second. Without a key the signed marker is the legacy one, so a single
// marker is returned.
func DNSRecordOwnershipMarkers(key []byte, clusterID, namespace, gatewayName string) []string {
	signed := SignDNSRecordComment(key, clusterID, namespace, gatewayName)
	legacy := DNSRecordComment(clusterID, namespace, gatewayName)
	if signed == legacy {
		return []string{legacy}
	}
	return []string{signed, legacy}
}

// SignPrivateResourceComment returns the HMAC-signed ownership prefix for
// Cloudflare network resources, whose APIs do not support tags. Without a key
// it falls back to PrivateResourceComment.
func SignPrivateResourceComment(key []byte, clusterID, namespace, name string) string {
	if len(key) == 0 {
		return PrivateResourceComment(clusterID, namespace, name, "")
	}
	identity := fmt.Sprintf("%s/%s/%s", clusterID, namespace, name)
	return fmt.Sprintf("%s%x", hmacMarkerPrefix, hmacSHA256(key, identity)[:hmacMarkerHexLength/2])
}

// IsOwnedPrivateResourceSigned reports whether a network resource comment
// carries an ownership marker for one Kubernetes object, accepting the signed
// marker and, for migration, the legacy plaintext prefix (including the
// truncated sha256 form used for long identities).
func IsOwnedPrivateResourceSigned(comment string, key []byte, clusterID, namespace, name string) bool {
	if len(key) > 0 {
		signed := SignPrivateResourceComment(key, clusterID, namespace, name)
		if comment == signed || strings.HasPrefix(comment, signed+" | ") {
			return true
		}
	}
	if IsOwnedPrivateResource(comment, clusterID, namespace, name) {
		return true
	}
	owner := PrivateResourceComment(clusterID, namespace, name, "")
	if utf8.RuneCountInString(owner) > privateResourceCommentLimit {
		sum := sha256.Sum256([]byte(owner))
		truncated := fmt.Sprintf("flareway sha256:%x", sum[:16])
		return comment == truncated || strings.HasPrefix(comment, truncated+" | ")
	}
	return false
}

// hmacSHA256 computes HMAC-SHA256 of identity under key.
func hmacSHA256(key []byte, identity string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(identity))
	return mac.Sum(nil)
}
