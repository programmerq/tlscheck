package plan

import (
	"strings"
	"testing"

	"github.com/programmerq/tlscheck/internal/config"
)

func TestDetermineUpgradeSequence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		version  string
		expected []UpgradeAttempt
	}{
		{
			name:    "pre-v15 uses legacy upgrades",
			version: "v14.2.9",
			expected: []UpgradeAttempt{
				{Token: "alpn", Path: upgradeEndpoint},
				{Token: "alpn-ping", Path: upgradeEndpoint},
			},
		},
		{
			name:    "v15.1 adds websocket",
			version: "v15.1.0",
			expected: []UpgradeAttempt{
				{Token: "websocket", Path: upgradeEndpoint},
				{Token: "alpn", Path: upgradeEndpoint},
				{Token: "alpn-ping", Path: upgradeEndpoint},
			},
		},
		{
			name:    "v17 keeps websocket and legacy",
			version: "v17.3.2",
			expected: []UpgradeAttempt{
				{Token: "websocket", Path: upgradeEndpoint},
				{Token: "alpn", Path: upgradeEndpoint},
				{Token: "alpn-ping", Path: upgradeEndpoint},
			},
		},
		{
			name:    "v18 is websocket only",
			version: "v18.0.0",
			expected: []UpgradeAttempt{
				{Token: "websocket", Path: upgradeEndpoint},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := determineUpgradeSequence(tt.version)
			if len(got) != len(tt.expected) {
				t.Fatalf("sequence length mismatch: got %d want %d", len(got), len(tt.expected))
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Fatalf("sequence[%d] = %#v want %#v", i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestBuildFiltersServices(t *testing.T) {
	t.Parallel()

	opts := config.Options{
		PublicAddr:      "cluster.example.com",
		ClusterName:     "example",
		TeleportVersion: "v17.3.2",
		Repeat:          1,
		ServiceFilter:   []string{"proxy_web"},
	}

	plan, err := Build(opts)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if len(plan.Targets) == 0 {
		t.Fatalf("expected at least one target for proxy_web")
	}

	for _, target := range plan.Targets {
		if target.ServiceKey != "proxy_web" {
			t.Fatalf("unexpected service %q in filtered plan", target.ServiceKey)
		}
	}
}

func TestBuildUnknownService(t *testing.T) {
	t.Parallel()

	opts := config.Options{
		PublicAddr:      "cluster.example.com",
		ClusterName:     "example",
		TeleportVersion: "v17.3.2",
		Repeat:          1,
		ServiceFilter:   []string{"proxy_web", "does_not_exist"},
	}

	if _, err := Build(opts); err == nil {
		t.Fatalf("expected error when unknown service requested")
	}
}

func TestBuildBase16Hint(t *testing.T) {
	t.Parallel()

	opts := config.Options{
		PublicAddr:      "cluster.example.com",
		ClusterName:     "example",
		TeleportVersion: "v17.3.2",
		Repeat:          1,
	}

	plan, err := Build(opts)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if plan.Base16ClusterName != "6578616d706c65" { // "example" in hex
		t.Fatalf("unexpected base16 cluster name: %q", plan.Base16ClusterName)
	}

	found := false
	for _, target := range plan.Targets {
		for _, note := range target.Notes {
			if strings.Contains(note, "6578616d706c65") {
				found = true
				break
			}
		}
		if found {
			break
		}
	}

	if !found {
		t.Fatalf("expected at least one target to include base16 hint note")
	}
}
