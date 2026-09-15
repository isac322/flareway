// Copyright 2026 Byeonghoon Yoo.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestValidateLedgerRejectsUnownedActionableRow(t *testing.T) {
	value := validTestLedger()
	value.Rows[0].Disposition = "actionable"
	value.Rows[0].Owner = ""

	var problems problemList
	validateLedger(value, &problems)

	assertProblemContains(t, problems, "actionable ledger key")
}

func TestValidateLedgerRejectsDuplicateAndMissingKeys(t *testing.T) {
	value := validTestLedger()
	value.Rows[1] = value.Rows[0]
	value.Rows[2].OfficialPath = ""

	var problems problemList
	validateLedger(value, &problems)

	assertProblemContains(t, problems, "incomplete audit+direction+officialPath key")
	assertProblemContains(t, problems, "duplicate ledger key")
	assertProblemContains(t, problems, "ledger key set does not match")
}

func TestValidateLedgerRejectsPlaceholderMapping(t *testing.T) {
	for _, mapping := range []string{
		"Not mapped.",
		"unmapped in CRD",
		"none",
		"<none>. Evidence: example.go:Example.Field.",
		"(none). Evidence: example.go:Example.Field.",
		"(unimplemented). Evidence: example.go:Example.Field.",
		"placeholder",
	} {
		t.Run(mapping, func(t *testing.T) {
			value := validTestLedger()
			value.Rows[0].CurrentMapping = mapping

			var problems problemList
			validateLedger(value, &problems)

			assertProblemContains(t, problems, "placeholder currentMapping")
		})
	}
}

func TestValidateLedgerRejectsActionableRowInCompleteLedger(t *testing.T) {
	value := validTestLedger()
	value.Rows[0].Disposition = "actionable"

	var problems problemList
	validateLedger(value, &problems)

	assertProblemContains(t, problems, "claimed-complete ledger contains actionable key")
}

func TestValidateEvidenceMappingsRejectsMissingSymbol(t *testing.T) {
	root := t.TempDir()
	content := "package example\n\ntype Example struct { Field string }\n"
	if err := os.WriteFile(filepath.Join(root, "example.go"), []byte(content), 0o600); err != nil {
		t.Fatalf("write example.go: %v", err)
	}
	value := validTestLedger()
	value.Rows[0].CurrentMapping = "Evidence: example.go:Example.Missing."

	var problems problemList
	validateEvidenceMappings(root, value, &problems)

	assertProblemContains(t, problems, "references a missing symbol")
}

func TestValidateSDKVersionRejectsVersionChange(t *testing.T) {
	root := t.TempDir()
	content := "module example.com/parity\n\nrequire github.com/cloudflare/cloudflare-go/v7 v7.11.0\n"
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(content), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	value := validTestLedger()

	var problems problemList
	validateSDKVersion(root, value, &problems)

	assertProblemContains(t, problems, "Cloudflare SDK version is v7.11.0")
}

func TestValidateSDKFileRejectsNewOfficialField(t *testing.T) {
	const relative = "zero_trust/example.go"
	base := []byte("Example struct { Existing string }")
	digest := sha256.Sum256(base)
	expected := map[string]sdkStruct{
		relative + "::Example": {
			File:   relative,
			Name:   "Example",
			SHA256: hex.EncodeToString(digest[:]),
		},
	}
	seen := make(map[string]struct{})
	content := []byte("package sdk\ntype Example struct { Existing string; Added string }\n")

	var problems problemList
	validateSDKFile(relative, relative, content, nil, expected, seen, &problems)

	assertProblemContains(t, problems, "official SDK struct changed without a ledger update")
}

func TestIgnoredSDKType(t *testing.T) {
	rules := []ignoredTypeRule{
		{Contains: "ResponseEnvelope", Rationale: "transport"},
		{Suffix: "Service", Rationale: "transport"},
	}
	for _, name := range []string{"AccessApplicationResponseEnvelopeErrors", "AccessApplicationService"} {
		if !ignoredSDKType(name, rules) {
			t.Fatalf("ignoredSDKType(%q) = false, want true", name)
		}
	}
	if ignoredSDKType("AccessApplicationNewParams", rules) {
		t.Fatal("ignoredSDKType(AccessApplicationNewParams) = true, want false")
	}
}

func validTestLedger() ledger {
	rows := make([]row, expectedLedgerRows)
	for index := range rows {
		path := "field-" + strconv.Itoa(index)
		rows[index] = row{
			Audit:          "Audit",
			Direction:      "request",
			OfficialPath:   path,
			Owner:          "owner",
			SourceVerdict:  "EXACT",
			Disposition:    "mapped",
			CurrentMapping: "example.go:Example.Field",
			Rationale:      "covered",
		}
		rows[index].Key = ledgerKey(rows[index].Audit, rows[index].Direction, rows[index].OfficialPath)
	}
	return ledger{
		FormatVersion: expectedFormatVersion,
		Complete:      true,
		SDK: sdkLedger{
			Module:  expectedSDKModule,
			Version: expectedSDKVersion,
			Files:   []string{"zero_trust/example.go"},
			IgnoredTypes: []ignoredTypeRule{
				{Contains: "ResponseEnvelope", Rationale: "transport"},
			},
			IgnoredFields: []ignoredFieldRule{
				{Scope: "response", JSONNames: []string{"success"}, Rationale: "transport"},
			},
			Schema: []sdkStruct{{File: "zero_trust/example.go", Name: "Example", SHA256: strings.Repeat("0", 64)}},
		},
		Owners: []owner{{Name: "owner", Declarations: []declaration{{File: "example.go", Kind: "type", Name: "Example"}}}},
		Rows:   rows,
	}
}

func assertProblemContains(t *testing.T, problems problemList, want string) {
	t.Helper()
	for _, problem := range problems.items {
		if strings.Contains(problem, want) {
			return
		}
	}
	t.Fatalf("problems %q do not contain %q", problems.items, want)
}
