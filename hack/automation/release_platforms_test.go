package automation

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleasePlatformsPreserveArchitecturesAndVariants(t *testing.T) {
	root := repositoryRoot(t)
	manifest := `{
		"manifests": [
			{"platform": {"os": "unknown", "architecture": "unknown"}},
			{"platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}},
			{"platform": {"os": "linux", "architecture": "amd64"}},
			{"platform": {"os": "linux", "architecture": "arm", "variant": "v7"}},
			{"platform": {"os": "windows", "architecture": "amd64"}},
			{"platform": {"os": "linux", "architecture": "386"}},
			{"platform": {"os": "linux", "architecture": "ppc64le"}}
		]
	}`
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(
		"python3",
		filepath.Join(root, "hack", "release-platforms.py"),
		"--dockerfile", filepath.Join(root, "Dockerfile"),
		"--manifest", manifestPath,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("discover release platforms: %v\n%s", err, output)
	}

	got := strings.TrimSpace(string(output))
	want := "linux/386,linux/amd64,linux/arm/v7,linux/arm64,linux/ppc64le"
	if got != want {
		t.Fatalf("release platforms = %q, want %q", got, want)
	}
}
