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

// Shared per-page sizes for Cloudflare list endpoints. The SDK types differ
// per endpoint (float64 for DNS records and zones, int64 for Access), so the
// constants stay untyped and each call site converts explicitly.
const (
	// dnsListPerPage folds zone-scoped DNS record listings into a single page
	// for realistic zone sizes.
	dnsListPerPage = 1000
	// accessListPerPage is the Access list endpoints' per-page maximum.
	accessListPerPage = 1000
	// zoneListPerPage is the zones list API maximum.
	zoneListPerPage = 50
)
