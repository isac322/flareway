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

package samples

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	sigsyaml "sigs.k8s.io/yaml"

	flarewayv1alpha1 "github.com/isac322/flareway/api/v1alpha1"
)

func TestAllSamplesStrictDecode(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	for name, add := range map[string]func(*runtime.Scheme) error{
		"Kubernetes":  clientgoscheme.AddToScheme,
		"Gateway API": gatewayv1.Install,
		"Flareway":    flarewayv1alpha1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatalf("register %s scheme: %v", name, err)
		}
	}

	paths, err := filepath.Glob("*.yaml")
	if err != nil {
		t.Fatalf("list samples: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no YAML samples found")
	}

	for _, path := range paths {
		path := path
		t.Run(path, func(t *testing.T) {
			strictDecodeFile(t, scheme, path)
		})
	}
}

func strictDecodeFile(t *testing.T, scheme *runtime.Scheme, path string) {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open sample: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close %s: %v", path, err)
		}
	}()

	reader := utilyaml.NewYAMLReader(bufio.NewReader(file))
	for document := 1; ; document++ {
		raw, err := reader.Read()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("read document %d: %v", document, err)
		}
		if strings.TrimSpace(string(raw)) == "" {
			continue
		}

		jsonData, err := utilyaml.ToJSON(raw)
		if err != nil {
			t.Fatalf("document %d YAML: %v", document, err)
		}
		var typeMeta struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
		}
		if err := json.Unmarshal(jsonData, &typeMeta); err != nil {
			t.Fatalf("document %d type metadata: %v", document, err)
		}
		gv, err := schema.ParseGroupVersion(typeMeta.APIVersion)
		if err != nil {
			t.Fatalf("document %d apiVersion %q: %v", document, typeMeta.APIVersion, err)
		}
		object, err := scheme.New(gv.WithKind(typeMeta.Kind))
		if err != nil {
			t.Fatalf("document %d unknown %s %s: %v", document, typeMeta.APIVersion, typeMeta.Kind, err)
		}
		if err := sigsyaml.UnmarshalStrict(raw, object); err != nil {
			t.Fatalf("document %d strict decode: %v", document, err)
		}
	}
}
