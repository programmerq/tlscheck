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
		PublicAddr:        "cluster.example.com",
		ClusterName:       "example",
		TeleportVersion:   "v17.3.2",
		Repeat:            1,
		ServiceFilter:     []string{"proxy_web"},
		WebProxyPort:      443,
		TLSRoutingEnabled: true,
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
		if target.Port != opts.WebProxyPort {
			t.Fatalf("unexpected port: got %d want %d", target.Port, opts.WebProxyPort)
		}
	}
}

func TestBuildUnknownService(t *testing.T) {
	t.Parallel()

	opts := config.Options{
		PublicAddr:        "cluster.example.com",
		ClusterName:       "example",
		TeleportVersion:   "v17.3.2",
		Repeat:            1,
		ServiceFilter:     []string{"proxy_web", "does_not_exist"},
		WebProxyPort:      443,
		TLSRoutingEnabled: true,
	}

	if _, err := Build(opts); err == nil {
		t.Fatalf("expected error when unknown service requested")
	}
}

func TestBuildBase16Hint(t *testing.T) {
	t.Parallel()

	opts := config.Options{
		PublicAddr:        "cluster.example.com",
		ClusterName:       "example",
		TeleportVersion:   "v17.3.2",
		Repeat:            1,
		WebProxyPort:      443,
		TLSRoutingEnabled: true,
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

func TestBuildMarksInformationalWhenTLSRoutingDisabled(t *testing.T) {
	t.Parallel()

	opts := config.Options{
		PublicAddr:        "cluster.example.com",
		ClusterName:       "example",
		TeleportVersion:   "v17.3.2",
		Repeat:            1,
		WebProxyPort:      443,
		TLSRoutingEnabled: false,
	}

	plan, err := Build(opts)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if len(plan.Targets) == 0 {
		t.Fatal("expected targets to be generated")
	}

	for _, target := range plan.Targets {
		if target.Port != opts.WebProxyPort {
			t.Fatalf("target %s port = %d, want %d", target.ServiceKey, target.Port, opts.WebProxyPort)
		}
		if target.ServiceKey == "proxy_web" {
			if target.InformationalOnly {
				t.Fatalf("proxy_web target should not be informational: %#v", target)
			}
			continue
		}
		if !target.InformationalOnly {
			t.Fatalf("expected %s to be informational when TLS routing disabled", target.ServiceKey)
		}
	}
}

func TestBuildAssignsUpgradeSequenceOnlyToProxyWeb(t *testing.T) {
	t.Parallel()

	opts := config.Options{
		PublicAddr:        "cluster.example.com",
		ClusterName:       "example",
		TeleportVersion:   "v17.3.2",
		Repeat:            1,
		WebProxyPort:      443,
		TLSRoutingEnabled: true,
	}

	plan, err := Build(opts)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	for _, target := range plan.Targets {
		if target.ServiceKey == "proxy_web" {
			if len(target.UpgradeSequence) == 0 {
				t.Fatalf("expected proxy_web to include upgrade sequence")
			}
			continue
		}
		if len(target.UpgradeSequence) != 0 {
			t.Fatalf("expected %s to omit upgrade sequence", target.ServiceKey)
		}
	}
}

func TestBuildAssignsTrustStrategies(t *testing.T) {
	t.Parallel()

	opts := config.Options{
		PublicAddr:        "cluster.example.com",
		ClusterName:       "example",
		TeleportVersion:   "v17.3.2",
		Repeat:            1,
		WebProxyPort:      443,
		TLSRoutingEnabled: true,
	}

	plan, err := Build(opts)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	var proxyWeb, proxySSH *ProbeTarget
	for i := range plan.Targets {
		target := &plan.Targets[i]
		switch target.ServiceKey {
		case "proxy_web":
			proxyWeb = target
		case "proxy_ssh":
			proxySSH = target
		}
	}

	if proxyWeb == nil {
		t.Fatalf("expected proxy_web target to be present")
	}
	if proxyWeb.Trust != TrustSystemRoots {
		t.Fatalf("proxy_web trust = %q, want %q", proxyWeb.Trust, TrustSystemRoots)
	}

	if proxySSH == nil {
		t.Fatalf("expected proxy_ssh target to be present")
	}
	if proxySSH.Trust != TrustHostCA {
		t.Fatalf("proxy_ssh trust = %q, want %q", proxySSH.Trust, TrustHostCA)
	}
}

func TestBuildAuthViaProxyUsesBase16Identifiers(t *testing.T) {
	t.Parallel()

	opts := config.Options{
		PublicAddr:        "cluster.example.com",
		ClusterName:       "example",
		TeleportVersion:   "v17.3.2",
		Repeat:            1,
		WebProxyPort:      443,
		TLSRoutingEnabled: true,
	}

	plan, err := Build(opts)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	var authTarget *ProbeTarget
	for i := range plan.Targets {
		if plan.Targets[i].ServiceKey == "auth_via_proxy" {
			authTarget = &plan.Targets[i]
			break
		}
	}

	if authTarget == nil {
		t.Fatalf("expected auth_via_proxy target to be present")
	}

	expectedSNI := "6578616d706c65.teleport.cluster.local"
	if authTarget.PrimarySNI != expectedSNI {
		t.Fatalf("auth_via_proxy primary SNI = %q, want %q", authTarget.PrimarySNI, expectedSNI)
	}

	expectedALPNs := []string{"teleport-auth@6578616d706c65.teleport.cluster.local", "h2"}
	if len(authTarget.ALPNs) != len(expectedALPNs) {
		t.Fatalf("auth_via_proxy ALPN length = %d, want %d", len(authTarget.ALPNs), len(expectedALPNs))
	}
	for i := range expectedALPNs {
		if authTarget.ALPNs[i] != expectedALPNs[i] {
			t.Fatalf("auth_via_proxy ALPN[%d] = %q, want %q", i, authTarget.ALPNs[i], expectedALPNs[i])
		}
	}
}

func TestBuildKeepsNonInformationalWhenTLSRoutingEnabled(t *testing.T) {
	t.Parallel()

	opts := config.Options{
		PublicAddr:        "cluster.example.com",
		ClusterName:       "example",
		TeleportVersion:   "v17.3.2",
		Repeat:            1,
		WebProxyPort:      443,
		TLSRoutingEnabled: true,
	}

	plan, err := Build(opts)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	for _, target := range plan.Targets {
		if target.ServiceKey == "proxy_web" {
			continue
		}
		if target.InformationalOnly {
			t.Fatalf("expected %s to require success when TLS routing enabled", target.ServiceKey)
		}
	}
}
