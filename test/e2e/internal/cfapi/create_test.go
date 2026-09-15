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

package cfapi

import (
	"context"
	"testing"

	"github.com/isac322/flareway/test/cfstub"
)

func TestCreateTunnel(t *testing.T) {
	server := cfstub.New(t)
	client := New("test-token", "account-1", server.URL)
	tunnel, err := client.CreateTunnel(context.Background(), "flareway-e2e-deadbeef-adopted")
	if err != nil {
		t.Fatalf("CreateTunnel returned error: %v", err)
	}
	if tunnel.ID == "" || tunnel.Name != "flareway-e2e-deadbeef-adopted" || tunnel.Status != "inactive" {
		t.Fatalf("unexpected tunnel: %#v", tunnel)
	}
}
