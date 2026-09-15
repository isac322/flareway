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

package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWritePrivateWARP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "private-warp.json")
	result := PrivateWARPResult{
		Result:                  PrivateWARPPass,
		DNSAddresses:            []string{"2606:4700:cf1:4000::1", "100.80.0.2"},
		UnregisteredPathChecked: true,
	}
	if err := WritePrivateWARP(path, result); err != nil {
		t.Fatalf("WritePrivateWARP: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	var got PrivateWARPResult
	if err := json.Unmarshal(content, &got); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if got.Result != PrivateWARPPass || got.RecordedAt == "" {
		t.Fatalf("result = %#v", got)
	}
	wantAddresses := []string{"100.80.0.2", "2606:4700:cf1:4000::1"}
	if !reflect.DeepEqual(got.DNSAddresses, wantAddresses) {
		t.Fatalf("DNS addresses = %v, want %v", got.DNSAddresses, wantAddresses)
	}
}

func TestWritePrivateWARPRejectsUnknownClassification(t *testing.T) {
	err := WritePrivateWARP(filepath.Join(t.TempDir(), "result.json"), PrivateWARPResult{Result: "skipped"})
	if err == nil {
		t.Fatal("WritePrivateWARP accepted an unclassified result")
	}
}
