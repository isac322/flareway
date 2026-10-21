package automation

import (
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"
)

const (
	dependabotCron     = "0 9 * * *"
	dependabotTimezone = "Asia/Seoul"
)

type dependabotConfig struct {
	Version int                `json:"version"`
	Updates []dependabotUpdate `json:"updates"`
}

type dependabotUpdate struct {
	PackageEcosystem      string             `json:"package-ecosystem"`
	Directory             string             `json:"directory"`
	Directories           []string           `json:"directories"`
	Schedule              dependabotSchedule `json:"schedule"`
	OpenPullRequestsLimit int                `json:"open-pull-requests-limit"`
}

type dependabotSchedule struct {
	Interval string `json:"interval"`
	Cronjob  string `json:"cronjob"`
	Timezone string `json:"timezone"`
}

func TestDependabotCoversEveryDependencySurface(t *testing.T) {
	root := repositoryRoot(t)
	payload, err := os.ReadFile(filepath.Join(root, ".github", "dependabot.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var config dependabotConfig
	if err := yaml.Unmarshal(payload, &config); err != nil {
		t.Fatal(err)
	}
	if config.Version != 2 {
		t.Fatalf("Dependabot version = %d, want 2", config.Version)
	}

	expected := map[string]bool{
		"gomod:/":          false,
		"github-actions:/": false,
		"github-actions:/.github/actions/go-cache": false,
		"docker:/":               false,
		"docker:/config/samples": false,
		"helm:/charts/flareway":  false,
		"devcontainers:/":        false,
	}
	for _, update := range config.Updates {
		if update.Schedule.Interval != "cron" || update.Schedule.Cronjob != dependabotCron || update.Schedule.Timezone != dependabotTimezone {
			t.Fatalf("Dependabot schedule for %s = %#v, want cron %q in %s", update.PackageEcosystem, update.Schedule, dependabotCron, dependabotTimezone)
		}
		if update.OpenPullRequestsLimit != 10 {
			t.Fatalf("Dependabot open PR limit for %s = %d, want 10", update.PackageEcosystem, update.OpenPullRequestsLimit)
		}
		directories := update.Directories
		if update.Directory != "" {
			directories = append(directories, update.Directory)
		}
		if len(directories) == 0 {
			t.Fatalf("Dependabot update for %s declares no directory", update.PackageEcosystem)
		}
		for _, directory := range directories {
			key := update.PackageEcosystem + ":" + directory
			if _, found := expected[key]; !found {
				t.Fatalf("unexpected Dependabot update surface %q", key)
			}
			if expected[key] {
				t.Fatalf("duplicate Dependabot update surface %q", key)
			}
			expected[key] = true
		}
	}
	for key, found := range expected {
		if !found {
			t.Errorf("Dependabot update surface %s is missing", key)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
