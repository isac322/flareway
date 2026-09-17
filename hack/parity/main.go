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

// parity checks the durable, reviewed mapping between the pinned Cloudflare Go
// SDK schema and Flareway's CRD and client declarations.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	expectedFormatVersion   = 1
	expectedLedgerRows      = 1131
	expectedSDKModule       = "github.com/cloudflare/cloudflare-go/v7"
	expectedSDKVersion      = "v7.10.0"
	expectedLedgerKeySHA256 = "cf76d6450c5b8b84c73039108f7478b7351565de55ec7c2f97f205ceb9bd1d4d"
)

type ledger struct {
	FormatVersion int       `json:"formatVersion"`
	Complete      bool      `json:"complete"`
	SDK           sdkLedger `json:"sdk"`
	Owners        []owner   `json:"owners"`
	Rows          []row     `json:"rows"`
}

type sdkLedger struct {
	Module        string             `json:"module"`
	Version       string             `json:"version"`
	Files         []string           `json:"files"`
	IgnoredTypes  []ignoredTypeRule  `json:"ignoredTypes"`
	IgnoredFields []ignoredFieldRule `json:"ignoredFields"`
	Schema        []sdkStruct        `json:"schema"`
}

type ignoredTypeRule struct {
	Contains  string `json:"contains,omitempty"`
	Suffix    string `json:"suffix,omitempty"`
	Rationale string `json:"rationale"`
}

type ignoredFieldRule struct {
	Scope     string   `json:"scope"`
	JSONNames []string `json:"jsonNames,omitempty"`
	TypeName  string   `json:"typeName,omitempty"`
	Rationale string   `json:"rationale"`
}

type sdkStruct struct {
	File   string `json:"file"`
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type owner struct {
	Name         string        `json:"name"`
	Declarations []declaration `json:"declarations"`
}

type declaration struct {
	File string `json:"file"`
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type row struct {
	Key            string `json:"key"`
	Audit          string `json:"audit"`
	Direction      string `json:"direction"`
	OfficialPath   string `json:"officialPath"`
	OfficialType   string `json:"officialType"`
	Required       string `json:"required"`
	SourceVerdict  string `json:"sourceVerdict"`
	Owner          string `json:"owner"`
	Disposition    string `json:"disposition"`
	CurrentMapping string `json:"currentMapping"`
	Rationale      string `json:"rationale"`
}

type problemList struct {
	items []string
}

func (p *problemList) add(format string, args ...any) {
	p.items = append(p.items, fmt.Sprintf(format, args...))
}

func main() {
	ledgerFlag := flag.String("ledger", "", "path to the parity ledger")
	flag.Parse()

	root, err := repositoryRoot()
	if err != nil {
		fatal(err)
	}
	ledgerPath := *ledgerFlag
	if ledgerPath == "" {
		ledgerPath = filepath.Join(root, "hack", "parity", "ledger.json")
	}

	value, err := readLedger(ledgerPath)
	if err != nil {
		fatal(err)
	}

	var problems problemList
	validateLedger(value, &problems)
	validateSDKVersion(root, value, &problems)
	validateEvidenceMappings(root, value, &problems)
	validateOwners(root, value, &problems)
	validateSDKSchema(value, &problems)
	if len(problems.items) != 0 {
		sort.Strings(problems.items)
		const limit = 20
		for i, problem := range problems.items {
			if i == limit {
				fmt.Fprintf(os.Stderr, "parity: ... and %d more problem(s)\n", len(problems.items)-limit)
				break
			}
			fmt.Fprintf(os.Stderr, "parity: %s\n", problem)
		}
		os.Exit(1)
	}

	fmt.Printf("parity: %d ledger rows, %d SDK structs, %d owners\n", len(value.Rows), len(value.SDK.Schema), len(value.Owners))
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "parity: %v\n", err)
	os.Exit(1)
}

func repositoryRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	for dir := cwd; ; dir = filepath.Dir(dir) {
		if fileExists(filepath.Join(dir, "go.mod")) && fileExists(filepath.Join(dir, "hack", "parity", "ledger.json")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("repository root not found")
		}
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readLedger(path string) (ledger, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return ledger{}, fmt.Errorf("read ledger: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var value ledger
	if err := decoder.Decode(&value); err != nil {
		return ledger{}, fmt.Errorf("decode ledger: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return ledger{}, errors.New("decode ledger: trailing JSON value")
		}
		return ledger{}, fmt.Errorf("decode ledger trailing data: %w", err)
	}
	return value, nil
}

func validateLedger(value ledger, problems *problemList) {
	if value.FormatVersion != expectedFormatVersion {
		problems.add("ledger formatVersion is %d, want %d", value.FormatVersion, expectedFormatVersion)
	}
	if value.SDK.Module != expectedSDKModule {
		problems.add("ledger SDK module is %q, want %q", value.SDK.Module, expectedSDKModule)
	}
	if value.SDK.Version != expectedSDKVersion {
		problems.add("ledger SDK version is %q, want %q", value.SDK.Version, expectedSDKVersion)
	}
	if len(value.Rows) != expectedLedgerRows {
		problems.add("ledger has %d rows, want %d; a ledger key is missing or extra", len(value.Rows), expectedLedgerRows)
	}

	owners := make(map[string]struct{}, len(value.Owners))
	for _, owner := range value.Owners {
		if owner.Name == "" {
			problems.add("owner with an empty name")
			continue
		}
		if _, found := owners[owner.Name]; found {
			problems.add("duplicate owner %q", owner.Name)
		}
		owners[owner.Name] = struct{}{}
		if len(owner.Declarations) == 0 {
			problems.add("owner %q has no Flareway declarations", owner.Name)
		}
	}

	keys := make(map[string]struct{}, len(value.Rows))
	actualKeys := make([]string, 0, len(value.Rows))
	validDispositions := map[string]struct{}{
		"actionable": {},
		"excluded":   {},
		"mapped":     {},
		"transport":  {},
	}
	for index, row := range value.Rows {
		prefix := fmt.Sprintf("row %d", index+1)
		if row.Audit == "" || row.Direction == "" || row.OfficialPath == "" {
			problems.add("%s has an incomplete audit+direction+officialPath key", prefix)
			continue
		}
		expectedKey := ledgerKey(row.Audit, row.Direction, row.OfficialPath)
		if row.Key != expectedKey {
			problems.add("%s key is %q, want %q", prefix, row.Key, expectedKey)
		}
		if _, found := keys[expectedKey]; found {
			problems.add("duplicate ledger key %q", expectedKey)
		}
		keys[expectedKey] = struct{}{}
		actualKeys = append(actualKeys, expectedKey)
		if _, found := validDispositions[row.Disposition]; !found {
			problems.add("%s %q has invalid disposition %q", prefix, expectedKey, row.Disposition)
		}
		mapping := strings.TrimSpace(row.CurrentMapping)
		mappingHead, _, _ := strings.Cut(mapping, "Evidence:")
		mappingHead = strings.TrimSpace(strings.TrimRight(strings.TrimSpace(mappingHead), "."))
		if mapping == "" {
			problems.add("%s %q has no current evidence mapping", prefix, expectedKey)
		} else if placeholderMappingPattern.MatchString(mappingHead) || bareNoneMappingPattern.MatchString(mappingHead) {
			problems.add("%s %q has placeholder currentMapping %q", prefix, expectedKey, row.CurrentMapping)
		}
		if row.Owner == "" {
			problems.add("%s %q is unowned", prefix, expectedKey)
		} else if _, found := owners[row.Owner]; !found {
			problems.add("%s %q names unknown owner %q", prefix, expectedKey, row.Owner)
		}
		if row.Disposition == "actionable" && row.Owner == "" {
			problems.add("actionable ledger key %q is unowned", expectedKey)
		}
		if value.Complete && row.Disposition == "actionable" {
			problems.add("claimed-complete ledger contains actionable key %q", expectedKey)
		}
		if (row.Disposition == "excluded" || row.Disposition == "transport") && strings.TrimSpace(row.Rationale) == "" {
			problems.add("%s %q requires an explicit %s rationale", prefix, expectedKey, row.Disposition)
		}
	}
	sort.Strings(actualKeys)
	keyDigest := sha256.New()
	for _, key := range actualKeys {
		_, _ = io.WriteString(keyDigest, key)
		_, _ = io.WriteString(keyDigest, "\n")
	}
	if actual := hex.EncodeToString(keyDigest.Sum(nil)); actual != expectedLedgerKeySHA256 {
		problems.add("ledger key set does not match the audited %d-row baseline", expectedLedgerRows)
	}

	files := make(map[string]struct{}, len(value.SDK.Files))
	for _, file := range value.SDK.Files {
		if file == "" || filepath.IsAbs(file) || filepath.Clean(file) != file || strings.HasPrefix(file, "..") {
			problems.add("invalid SDK source path %q", file)
		}
		if _, found := files[file]; found {
			problems.add("duplicate SDK source path %q", file)
		}
		files[file] = struct{}{}
	}
	for _, rule := range value.SDK.IgnoredTypes {
		if rule.Contains == "" && rule.Suffix == "" {
			problems.add("SDK ignored-type rule has no matcher")
		}
		if strings.TrimSpace(rule.Rationale) == "" {
			problems.add("SDK ignored-type rule requires an explicit rationale")
		}
	}
	for _, rule := range value.SDK.IgnoredFields {
		if rule.Scope == "" || (len(rule.JSONNames) == 0 && rule.TypeName == "") {
			problems.add("SDK ignored-field rule is incomplete")
		}
		if strings.TrimSpace(rule.Rationale) == "" {
			problems.add("SDK ignored-field rule requires an explicit rationale")
		}
	}

	schemaKeys := make(map[string]struct{}, len(value.SDK.Schema))
	for _, item := range value.SDK.Schema {
		key := item.File + "::" + item.Name
		if _, found := files[item.File]; !found {
			problems.add("SDK schema %q references unselected file %q", item.Name, item.File)
		}
		if item.Name == "" || item.SHA256 == "" {
			problems.add("SDK schema entry %q is incomplete", key)
		}
		if _, err := hex.DecodeString(item.SHA256); err != nil || len(item.SHA256) != sha256.Size*2 {
			problems.add("SDK schema entry %q has invalid SHA-256", key)
		}
		if _, found := schemaKeys[key]; found {
			problems.add("duplicate SDK schema entry %q", key)
		}
		schemaKeys[key] = struct{}{}
	}
}

func ledgerKey(audit, direction, officialPath string) string {
	return audit + "::" + direction + "::" + officialPath
}

var (
	requirePattern            = regexp.MustCompile(`(?m)^\s*(?:require\s+)?github\.com/cloudflare/cloudflare-go/v7\s+(v\S+)\s*$`)
	placeholderMappingPattern = regexp.MustCompile(`(?i)(?:\bnot[\s_-]*mapped\b|\bunmapped\b|\bunimplemented\b|\bplaceholder\b|\btbd\b|\btodo\b)`)
	bareNoneMappingPattern    = regexp.MustCompile(`(?i)^(?:none|\(none\)|<none>)$`)
	evidenceReferencePattern  = regexp.MustCompile(`(?:^|[\s;(])([A-Za-z0-9_./-]+\.go):([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)`)
)

func validateSDKVersion(root string, value ledger, problems *problemList) {
	content, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		problems.add("read go.mod: %v", err)
		return
	}
	match := requirePattern.FindSubmatch(content)
	if match == nil {
		problems.add("go.mod does not directly require %s", expectedSDKModule)
		return
	}
	version := string(match[1])
	if version != expectedSDKVersion || version != value.SDK.Version {
		problems.add("Cloudflare SDK version is %s, ledger requires %s", version, expectedSDKVersion)
	}
}

func validateOwners(root string, value ledger, problems *problemList) {
	parsed := make(map[string]*ast.File)
	for _, owner := range value.Owners {
		for _, declaration := range owner.Declarations {
			path := filepath.Join(root, declaration.File)
			file := parsed[path]
			if file == nil {
				fset := token.NewFileSet()
				parsedFile, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
				if err != nil {
					problems.add("owner %q: parse %s: %v", owner.Name, declaration.File, err)
					continue
				}
				file = parsedFile
				parsed[path] = file
			}
			if !hasDeclaration(file, declaration) {
				problems.add("owner %q: %s %s is missing from %s", owner.Name, declaration.Kind, declaration.Name, declaration.File)
			}
		}
	}
}

func validateEvidenceMappings(root string, value ledger, problems *problemList) {
	parsed := make(map[string]*ast.File)
	checked := make(map[string]struct{})
	for index, row := range value.Rows {
		matches := evidenceReferencePattern.FindAllStringSubmatch(row.CurrentMapping, -1)
		if len(matches) == 0 {
			problems.add("row %d %q has no file/symbol evidence reference", index+1, row.Key)
			continue
		}
		for _, match := range matches {
			relative, symbol := match[1], match[2]
			key := relative + ":" + symbol
			if _, found := checked[key]; found {
				continue
			}
			checked[key] = struct{}{}

			path := filepath.Join(root, filepath.FromSlash(relative))
			file := parsed[path]
			if file == nil {
				fset := token.NewFileSet()
				parsedFile, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
				if err != nil {
					problems.add("row %d evidence %q: parse %s: %v", index+1, key, relative, err)
					continue
				}
				file = parsedFile
				parsed[path] = file
			}
			if !hasEvidenceSymbol(file, symbol) {
				problems.add("row %d evidence %q references a missing symbol", index+1, key)
			}
		}
	}
}

func hasEvidenceSymbol(file *ast.File, symbol string) bool {
	typeName, member, hasMember := strings.Cut(symbol, ".")
	for _, item := range file.Decls {
		switch node := item.(type) {
		case *ast.GenDecl:
			if node.Tok == token.CONST || node.Tok == token.VAR {
				if hasMember {
					continue
				}
				for _, spec := range node.Specs {
					valueSpec, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, name := range valueSpec.Names {
						if name.Name == typeName {
							return true
						}
					}
				}
				continue
			}
			if node.Tok != token.TYPE {
				continue
			}
			for _, spec := range node.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok || typeSpec.Name.Name != typeName {
					continue
				}
				if !hasMember {
					return true
				}
				var fields []*ast.Field
				switch value := typeSpec.Type.(type) {
				case *ast.StructType:
					fields = value.Fields.List
				case *ast.InterfaceType:
					fields = value.Methods.List
				default:
					continue
				}
				for _, field := range fields {
					for _, name := range field.Names {
						if name.Name == member {
							return true
						}
					}
				}
			}
		case *ast.FuncDecl:
			if !hasMember && node.Name.Name == typeName {
				return true
			}
			if hasMember && node.Name.Name == member && receiverTypeName(node.Recv) == typeName {
				return true
			}
		}
	}
	return false
}

func receiverTypeName(fields *ast.FieldList) string {
	if fields == nil || len(fields.List) != 1 {
		return ""
	}
	expression := fields.List[0].Type
	if pointer, ok := expression.(*ast.StarExpr); ok {
		expression = pointer.X
	}
	if identifier, ok := expression.(*ast.Ident); ok {
		return identifier.Name
	}
	return ""
}

func hasDeclaration(file *ast.File, declaration declaration) bool {
	for _, item := range file.Decls {
		switch node := item.(type) {
		case *ast.GenDecl:
			if declaration.Kind != "type" || node.Tok != token.TYPE {
				continue
			}
			for _, spec := range node.Specs {
				if typeSpec, ok := spec.(*ast.TypeSpec); ok && typeSpec.Name.Name == declaration.Name {
					return true
				}
			}
		case *ast.FuncDecl:
			if declaration.Kind == "func" && node.Recv == nil && node.Name.Name == declaration.Name {
				return true
			}
		}
	}
	return false
}

func validateSDKSchema(value ledger, problems *problemList) {
	moduleRoot, err := moduleDirectory(value.SDK.Module, value.SDK.Version)
	if err != nil {
		problems.add("locate pinned SDK module: %v", err)
		return
	}
	expected := make(map[string]sdkStruct, len(value.SDK.Schema))
	for _, item := range value.SDK.Schema {
		expected[item.File+"::"+item.Name] = item
	}
	seen := make(map[string]struct{}, len(expected))

	for _, relative := range value.SDK.Files {
		path := filepath.Join(moduleRoot, filepath.FromSlash(relative))
		content, err := os.ReadFile(path)
		if err != nil {
			problems.add("read SDK source %s: %v", relative, err)
			continue
		}
		validateSDKFile(relative, path, content, value.SDK.IgnoredTypes, expected, seen, problems)
	}
	for key := range expected {
		if _, found := seen[key]; !found {
			problems.add("ledger SDK struct is missing from the pinned SDK: %s", key)
		}
	}
}

func validateSDKFile(
	relative string,
	path string,
	content []byte,
	ignoredTypes []ignoredTypeRule,
	expected map[string]sdkStruct,
	seen map[string]struct{},
	problems *problemList,
) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, content, parser.SkipObjectResolution)
	if err != nil {
		problems.add("parse SDK source %s: %v", relative, err)
		return
	}
	for _, declaration := range file.Decls {
		genDecl, ok := declaration.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			continue
		}
		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || !ast.IsExported(typeSpec.Name.Name) {
				continue
			}
			if _, ok := typeSpec.Type.(*ast.StructType); !ok || ignoredSDKType(typeSpec.Name.Name, ignoredTypes) {
				continue
			}
			key := relative + "::" + typeSpec.Name.Name
			start := fset.Position(typeSpec.Pos()).Offset
			end := fset.Position(typeSpec.End()).Offset
			if start < 0 || end > len(content) || start >= end {
				problems.add("invalid SDK source offsets for %s", key)
				continue
			}
			digest := sha256.Sum256(content[start:end])
			actual := hex.EncodeToString(digest[:])
			want, found := expected[key]
			if !found {
				problems.add("unmapped newly added official SDK struct %s", key)
				continue
			}
			seen[key] = struct{}{}
			if actual != want.SHA256 {
				problems.add("official SDK struct changed without a ledger update: %s", key)
			}
		}
	}
}

func ignoredSDKType(name string, rules []ignoredTypeRule) bool {
	for _, rule := range rules {
		if rule.Contains != "" && strings.Contains(name, rule.Contains) {
			return true
		}
		if rule.Suffix != "" && strings.HasSuffix(name, rule.Suffix) {
			return true
		}
	}
	return false
}

func moduleDirectory(module, version string) (string, error) {
	command := exec.Command("go", "mod", "download", "-json", module+"@"+version)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("go mod download: %s", strings.TrimSpace(string(output)))
	}
	var result struct {
		Path    string
		Version string
		Dir     string
		Error   string
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return "", fmt.Errorf("decode go mod download output: %w", err)
	}
	if result.Error != "" {
		return "", errors.New(result.Error)
	}
	if result.Path != module || result.Version != version {
		return "", fmt.Errorf("downloaded %s@%s, want %s@%s", result.Path, result.Version, module, version)
	}
	if result.Dir == "" {
		return "", errors.New("go mod download returned an empty module directory")
	}
	return result.Dir, nil
}
