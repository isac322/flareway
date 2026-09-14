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

package v1alpha1

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidationArtifactsUseASCIIQuotes(t *testing.T) {
	t.Parallel()

	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	crdFiles, err := filepath.Glob("../../config/crd/bases/*.yaml")
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range goFiles {
		assertNoUnicodeQuotes(t, path, true)
	}
	for _, path := range crdFiles {
		assertNoUnicodeQuotes(t, path, false)
	}
}

func assertNoUnicodeQuotes(t *testing.T, path string, validationMarkersOnly bool) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close %s: %v", path, err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := scanner.Text()
		if validationMarkersOnly && !strings.Contains(line, "kubebuilder:validation:XValidation") {
			continue
		}
		if strings.ContainsAny(line, "“”‘’") {
			t.Errorf("%s:%d contains a Unicode quote in validation source: %q", path, lineNumber, line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}
