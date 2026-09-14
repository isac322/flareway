//go:build e2e

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

package e2e

import (
	"net/netip"
	"testing"
)

func TestSyntheticPrivateAddressRanges(t *testing.T) {
	for _, test := range []struct {
		address string
		want    bool
	}{
		{address: "100.80.0.1", want: true},
		{address: "100.80.255.254", want: true},
		{address: "172.64.128.1", want: true},
		{address: "172.64.143.254", want: true},
		{address: "2606:4700:0cf1:4000::1", want: true},
		{address: "100.81.0.1", want: false},
		{address: "172.64.144.1", want: false},
		{address: "2606:4700:0cf1:5000::1", want: false},
	} {
		t.Run(test.address, func(t *testing.T) {
			if got := isSyntheticPrivateAddress(netip.MustParseAddr(test.address)); got != test.want {
				t.Fatalf("isSyntheticPrivateAddress(%s) = %t, want %t", test.address, got, test.want)
			}
		})
	}
}
