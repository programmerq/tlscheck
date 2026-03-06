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

func TestBuildWithIPAddresses(t *testing.T) {
	t.Parallel()

	opts := config.Options{
		PublicAddr:        "cluster.example.com",
		ClusterName:       "example",
		TeleportVersion:   "v17.3.2",
		Repeat:            1,
		WebProxyPort:      443,
		TLSRoutingEnabled: true,
		IPAddresses:       []string{"192.168.1.1", "10.0.0.1"},
	}

	plan, err := Build(opts)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if len(plan.Targets) == 0 {
		t.Fatal("expected targets to be generated")
	}

	for _, target := range plan.Targets {
		if len(target.OverrideIPs) != 2 {
			t.Fatalf("target %s has %d override IPs, want 2", target.ServiceKey, len(target.OverrideIPs))
		}
		if target.OverrideIPs[0] != "192.168.1.1" {
			t.Fatalf("target %s OverrideIPs[0] = %q, want %q", target.ServiceKey, target.OverrideIPs[0], "192.168.1.1")
		}
		if target.OverrideIPs[1] != "10.0.0.1" {
			t.Fatalf("target %s OverrideIPs[1] = %q, want %q", target.ServiceKey, target.OverrideIPs[1], "10.0.0.1")
		}
	}
}

func TestBuildWithoutIPAddresses(t *testing.T) {
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

	if len(plan.Targets) == 0 {
		t.Fatal("expected targets to be generated")
	}

	for _, target := range plan.Targets {
		if len(target.OverrideIPs) != 0 {
			t.Fatalf("target %s has %d override IPs, want 0 (will be resolved at probe time)", target.ServiceKey, len(target.OverrideIPs))
		}
	}
}

func TestBuildMarksClientCertServices(t *testing.T) {
	t.Parallel()

	t.Run("without client cert", func(t *testing.T) {
		opts := config.Options{
			PublicAddr:        "cluster.example.com",
			ClusterName:       "example",
			TeleportVersion:   "v17.3.2",
			Repeat:            1,
			WebProxyPort:      443,
			TLSRoutingEnabled: true,
			// No ClientCert set
		}

		plan, err := Build(opts)
		if err != nil {
			t.Fatalf("Build returned error: %v", err)
		}

		// When no client cert exists, services should NOT set UseClientCert (should be nil)
		for _, target := range plan.Targets {
			if target.UseClientCert != nil {
				t.Errorf("service %s should have UseClientCert=nil when no cert available, but got %v", target.ServiceKey, *target.UseClientCert)
			}
		}
	})

	t.Run("with client cert", func(t *testing.T) {
		opts := config.Options{
			PublicAddr:        "cluster.example.com",
			ClusterName:       "example",
			TeleportVersion:   "v17.3.2",
			Repeat:            1,
			WebProxyPort:      443,
			TLSRoutingEnabled: true,
			ClientCert: &config.ClientCertInfo{
				Fingerprint: "test-fingerprint",
			},
		}

		plan, err := Build(opts)
		if err != nil {
			t.Fatalf("Build returned error: %v", err)
		}

		// Services that support client certs should generate both with and without
		clientCertServices := map[string]bool{
			"proxy_ssh_grpc": true,
			"auth_via_proxy": true,
		}

		// Count targets for services that support client certs
		serviceCounts := make(map[string]int)
		withCertCount := make(map[string]int)
		withoutCertCount := make(map[string]int)

		for _, target := range plan.Targets {
			if clientCertServices[target.ServiceKey] {
				serviceCounts[target.ServiceKey]++
				if target.UseClientCert != nil && *target.UseClientCert {
					withCertCount[target.ServiceKey]++
				} else if target.UseClientCert != nil && !*target.UseClientCert {
					withoutCertCount[target.ServiceKey]++
				}
			} else {
				// Other services should NOT use client cert (should be nil or false)
				if target.UseClientCert != nil && *target.UseClientCert {
					t.Errorf("service %s should not use client cert but got UseClientCert=true", target.ServiceKey)
				}
			}
		}

		// Each client-cert-supporting service should have 2 targets: one with, one without
		for service := range clientCertServices {
			if serviceCounts[service] != 2 {
				t.Errorf("service %s should have 2 targets (with and without cert) but got %d", service, serviceCounts[service])
			}
			if withCertCount[service] != 1 {
				t.Errorf("service %s should have 1 target with client cert but got %d", service, withCertCount[service])
			}
			if withoutCertCount[service] != 1 {
				t.Errorf("service %s should have 1 target without client cert but got %d", service, withoutCertCount[service])
			}
		}
	})
}

func TestBuildDuplicatesTargetsWhenProxyConfigured(t *testing.T) {
	t.Parallel()

	// Test with proxy configured
	optsWithProxy := config.Options{
		PublicAddr:        "cluster.example.com",
		ClusterName:       "example",
		TeleportVersion:   "v17.3.2",
		Repeat:            1,
		WebProxyPort:      443,
		TLSRoutingEnabled: true,
		ServiceFilter:     []string{"proxy_web"},
		Proxy: config.ProxySettings{
			HTTPSProxy: "http://proxy.example.com:8080",
		},
	}

	planWithProxy, err := Build(optsWithProxy)
	if err != nil {
		t.Fatalf("Build with proxy returned error: %v", err)
	}

	// Without proxy, we should have 1 target
	optsWithoutProxy := optsWithProxy
	optsWithoutProxy.Proxy = config.ProxySettings{}
	planWithoutProxy, err := Build(optsWithoutProxy)
	if err != nil {
		t.Fatalf("Build without proxy returned error: %v", err)
	}

	if len(planWithoutProxy.Targets) == 0 {
		t.Fatal("expected at least one target without proxy")
	}

	// With proxy, we should have 2x targets (with proxy + without proxy)
	expectedTargets := len(planWithoutProxy.Targets) * 2
	if len(planWithProxy.Targets) != expectedTargets {
		t.Fatalf("expected %d targets with proxy (double), got %d", expectedTargets, len(planWithProxy.Targets))
	}

	// Verify that we have both proxy and non-proxy versions
	var withProxyCount, withoutProxyCount int
	for _, target := range planWithProxy.Targets {
		if target.UseProxy {
			withProxyCount++
			if target.ProxyURL != "http://proxy.example.com:8080" {
				t.Errorf("proxy target has wrong ProxyURL: got %q want %q",
					target.ProxyURL, "http://proxy.example.com:8080")
			}
			// Check for proxy note
			foundProxyNote := false
			for _, note := range target.Notes {
				if strings.Contains(note, "Using proxy") {
					foundProxyNote = true
					break
				}
			}
			if !foundProxyNote {
				t.Errorf("proxy target missing 'Using proxy' note")
			}
		} else {
			withoutProxyCount++
			// Check for direct connection note
			foundDirectNote := false
			for _, note := range target.Notes {
				if strings.Contains(note, "Direct connection") {
					foundDirectNote = true
					break
				}
			}
			if !foundDirectNote {
				t.Errorf("direct target missing 'Direct connection' note")
			}
		}
	}

	if withProxyCount != len(planWithoutProxy.Targets) {
		t.Errorf("expected %d proxy targets, got %d", len(planWithoutProxy.Targets), withProxyCount)
	}
	if withoutProxyCount != len(planWithoutProxy.Targets) {
		t.Errorf("expected %d direct targets, got %d", len(planWithoutProxy.Targets), withoutProxyCount)
	}
}

func TestBuildNoProxyDuplicationWithoutProxy(t *testing.T) {
	t.Parallel()

	opts := config.Options{
		PublicAddr:        "cluster.example.com",
		ClusterName:       "example",
		TeleportVersion:   "v17.3.2",
		Repeat:            1,
		WebProxyPort:      443,
		TLSRoutingEnabled: true,
		ServiceFilter:     []string{"proxy_web"},
	}

	plan, err := Build(opts)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	// Should have exactly 1 target since no proxy is configured
	if len(plan.Targets) != 1 {
		t.Fatalf("expected 1 target without proxy, got %d", len(plan.Targets))
	}

	target := plan.Targets[0]
	if target.UseProxy {
		t.Error("target should not use proxy when no proxy configured")
	}
	if target.ProxyURL != "" {
		t.Errorf("target should have empty ProxyURL, got %q", target.ProxyURL)
	}
}

func TestDetermineProxyURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		settings config.ProxySettings
		want     string
	}{
		{
			name: "HTTPS proxy preferred",
			settings: config.ProxySettings{
				HTTPSProxy: "https://secure-proxy:8443",
				HTTPProxy:  "http://insecure-proxy:8080",
			},
			want: "https://secure-proxy:8443",
		},
		{
			name: "HTTP proxy fallback",
			settings: config.ProxySettings{
				HTTPProxy: "http://proxy:8080",
			},
			want: "http://proxy:8080",
		},
		{
			name:     "no proxy",
			settings: config.ProxySettings{},
			want:     "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := determineProxyURL(tt.settings)
			if got != tt.want {
				t.Errorf("determineProxyURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveDNSForTarget(t *testing.T) {
	t.Parallel()

	t.Run("resolves DNS for hostname", func(t *testing.T) {
		target := ProbeTarget{
			Address: "localhost",
		}
		resolveDNSForTarget(&target)

		// localhost should resolve to at least one IP
		if len(target.DNSResolvedIPs) == 0 {
			t.Error("Expected DNS resolution for localhost, got none")
		}
		t.Logf("Resolved localhost to: %v", target.DNSResolvedIPs)
	})

	t.Run("skips DNS resolution when override IPs exist", func(t *testing.T) {
		target := ProbeTarget{
			Address:     "example.com",
			OverrideIPs: []string{"1.2.3.4"},
		}
		resolveDNSForTarget(&target)

		// Should not resolve DNS when override IPs are present
		if len(target.DNSResolvedIPs) != 0 {
			t.Errorf("Expected no DNS resolution when override IPs exist, got: %v", target.DNSResolvedIPs)
		}
	})

	t.Run("handles nil target gracefully", func(t *testing.T) {
		// Should not panic
		resolveDNSForTarget(nil)
	})

	t.Run("handles unresolvable hostname", func(t *testing.T) {
		target := ProbeTarget{
			Address: "nonexistent.invalid.domain.example",
		}
		resolveDNSForTarget(&target)

		// Should not have resolved IPs for invalid domain
		if len(target.DNSResolvedIPs) != 0 {
			t.Errorf("Expected no DNS resolution for invalid domain, got: %v", target.DNSResolvedIPs)
		}
	})
}

func TestBuildIncludesDNSResolution(t *testing.T) {
	t.Parallel()

	opts := config.Options{
		PublicAddr:        "localhost",
		WebProxyPort:      443,
		ClusterName:       "test",
		TeleportVersion:   "v15.0.0",
		TLSRoutingEnabled: true,
		ServiceFilter:     []string{"proxy_web"},
	}

	plan, err := Build(opts)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if len(plan.Targets) == 0 {
		t.Fatal("Expected at least one target")
	}

	// At least one target should have DNS resolved IPs (localhost should resolve)
	foundDNS := false
	for _, target := range plan.Targets {
		if len(target.DNSResolvedIPs) > 0 {
			foundDNS = true
			t.Logf("Target %s has DNS IPs: %v", target.ServiceKey, target.DNSResolvedIPs)
			break
		}
	}

	if !foundDNS {
		t.Error("Expected at least one target to have DNS resolved IPs")
	}
}

func TestBuildDuplicatesTargetsWhenExtraHeadersConfigured(t *testing.T) {
	t.Parallel()

	baseOpts := config.Options{
		PublicAddr:        "cluster.example.com",
		ClusterName:       "example",
		TeleportVersion:   "v18.0.0",
		Repeat:            1,
		WebProxyPort:      443,
		TLSRoutingEnabled: true,
		ServiceFilter:     []string{"proxy_web"},
	}

	// Build without headers to get the baseline count
	planWithout, err := Build(baseOpts)
	if err != nil {
		t.Fatalf("Build without headers returned error: %v", err)
	}
	baselineCount := len(planWithout.Targets)
	if baselineCount == 0 {
		t.Fatal("expected at least one baseline target")
	}

	// Build with extra headers
	optsWithHeaders := baseOpts
	optsWithHeaders.ExtraHeaders = map[string]string{
		"Authorization": "Bearer tokentoken",
	}
	planWith, err := Build(optsWithHeaders)
	if err != nil {
		t.Fatalf("Build with headers returned error: %v", err)
	}

	// Should have 2x targets (without headers + with headers)
	expected := baselineCount * 2
	if len(planWith.Targets) != expected {
		t.Fatalf("expected %d targets with extra headers (double), got %d", expected, len(planWith.Targets))
	}

	// Verify pairs: first target has no extra headers, second has them
	var withHeadersCount, withoutHeadersCount int
	for _, target := range planWith.Targets {
		if len(target.ExtraHeaders) > 0 {
			withHeadersCount++
			if v := target.ExtraHeaders["Authorization"]; v != "Bearer tokentoken" {
				t.Errorf("Authorization header = %q, want %q", v, "Bearer tokentoken")
			}
			foundNote := false
			for _, note := range target.Notes {
				if strings.Contains(note, "With extra headers") {
					foundNote = true
					break
				}
			}
			if !foundNote {
				t.Errorf("target with extra headers missing 'With extra headers' note, notes: %v", target.Notes)
			}
		} else {
			withoutHeadersCount++
			foundNote := false
			for _, note := range target.Notes {
				if strings.Contains(note, "Without extra headers") {
					foundNote = true
					break
				}
			}
			if !foundNote {
				t.Errorf("target without extra headers missing 'Without extra headers' note, notes: %v", target.Notes)
			}
		}
	}

	if withHeadersCount != baselineCount {
		t.Errorf("expected %d targets with headers, got %d", baselineCount, withHeadersCount)
	}
	if withoutHeadersCount != baselineCount {
		t.Errorf("expected %d targets without headers, got %d", baselineCount, withoutHeadersCount)
	}
}

func TestBuildNoHeadersDuplicationWithoutExtraHeaders(t *testing.T) {
	t.Parallel()

	opts := config.Options{
		PublicAddr:        "cluster.example.com",
		ClusterName:       "example",
		TeleportVersion:   "v18.0.0",
		Repeat:            1,
		WebProxyPort:      443,
		TLSRoutingEnabled: true,
		ServiceFilter:     []string{"proxy_web"},
	}

	p, err := Build(opts)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	// Should have exactly 1 target since no extra headers are configured
	if len(p.Targets) != 1 {
		t.Fatalf("expected 1 target without extra headers, got %d", len(p.Targets))
	}
	if len(p.Targets[0].ExtraHeaders) != 0 {
		t.Errorf("expected no ExtraHeaders on target, got %v", p.Targets[0].ExtraHeaders)
	}
}

func TestBuildExtraHeadersAndProxyCombined(t *testing.T) {
	t.Parallel()

	opts := config.Options{
		PublicAddr:        "cluster.example.com",
		ClusterName:       "example",
		TeleportVersion:   "v18.0.0",
		Repeat:            1,
		WebProxyPort:      443,
		TLSRoutingEnabled: true,
		ServiceFilter:     []string{"proxy_web"},
		Proxy: config.ProxySettings{
			HTTPSProxy: "http://proxy.example.com:8080",
		},
		ExtraHeaders: map[string]string{
			"Authorization": "Bearer abc",
		},
	}

	p, err := Build(opts)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	// Each target first gets duplicated for proxy (×2), then for headers (×2) = 4 total
	// for 1 baseline target.
	if len(p.Targets) != 4 {
		t.Fatalf("expected 4 targets (proxy × headers), got %d", len(p.Targets))
	}
}
