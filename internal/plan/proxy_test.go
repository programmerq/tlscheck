package plan

import (
	"testing"

	"github.com/programmerq/tlscheck/internal/config"
)

func TestBuildDuplicatesTargetsWhenProxyConfigured(t *testing.T) {
	// Test without proxy - should have normal targets
	optsNoProxy := config.Options{
		PublicAddr:        "teleport.example.com",
		ClusterName:       "test-cluster",
		TeleportVersion:   "v18.0.0",
		WebProxyPort:      443,
		TLSRoutingEnabled: true,
		Repeat:            1,
		ServiceFilter:     []string{"proxy_web"},
	}

	planNoProxy, err := Build(optsNoProxy)
	if err != nil {
		t.Fatalf("failed to build plan without proxy: %v", err)
	}

	// Test with proxy - should duplicate targets
	optsWithProxy := config.Options{
		PublicAddr:        "teleport.example.com",
		ClusterName:       "test-cluster",
		TeleportVersion:   "v18.0.0",
		WebProxyPort:      443,
		TLSRoutingEnabled: true,
		Repeat:            1,
		ServiceFilter:     []string{"proxy_web"},
		Proxy: config.ProxySettings{
			HTTPSProxy: "http://proxy.example.com:8080",
		},
	}

	planWithProxy, err := Build(optsWithProxy)
	if err != nil {
		t.Fatalf("failed to build plan with proxy: %v", err)
	}

	// Verify duplication - should be 2x targets when proxy is configured
	expectedWithoutProxy := len(planNoProxy.Targets)
	expectedWithProxy := expectedWithoutProxy * 2

	if len(planWithProxy.Targets) != expectedWithProxy {
		t.Errorf("expected %d targets with proxy, got %d", expectedWithProxy, len(planWithProxy.Targets))
	}

	// Verify one target uses proxy, one doesn't
	foundWithProxy := false
	foundWithoutProxy := false
	for _, target := range planWithProxy.Targets {
		if target.UseProxy {
			foundWithProxy = true
			// Check for proxy note
			hasProxyNote := false
			for _, note := range target.Notes {
				if note == "probe using configured proxy" {
					hasProxyNote = true
					break
				}
			}
			if !hasProxyNote {
				t.Error("target with UseProxy=true should have proxy note")
			}
		} else {
			foundWithoutProxy = true
			// Check for direct note
			hasDirectNote := false
			for _, note := range target.Notes {
				if note == "probe bypassing proxy (direct connection)" {
					hasDirectNote = true
					break
				}
			}
			if !hasDirectNote {
				t.Error("target with UseProxy=false should have direct connection note")
			}
		}
	}

	if !foundWithProxy {
		t.Error("no target found with UseProxy=true")
	}
	if !foundWithoutProxy {
		t.Error("no target found with UseProxy=false")
	}

	// Verify no duplication when no proxy
	for _, target := range planNoProxy.Targets {
		if target.UseProxy {
			t.Error("target without proxy should not have UseProxy=true")
		}
	}
}

func TestBuildMultipleServicesWithProxy(t *testing.T) {
	opts := config.Options{
		PublicAddr:        "teleport.example.com",
		ClusterName:       "test-cluster",
		TeleportVersion:   "v18.0.0",
		WebProxyPort:      443,
		TLSRoutingEnabled: true,
		Repeat:            1,
		ServiceFilter:     []string{"proxy_web", "reverse_tunnel"},
		Proxy: config.ProxySettings{
			HTTPSProxy: "http://proxy.example.com:8080",
		},
	}

	plan, err := Build(opts)
	if err != nil {
		t.Fatalf("failed to build plan: %v", err)
	}

	// Should have 2 services * 2 (with/without proxy) = 4 targets
	if len(plan.Targets) != 4 {
		t.Errorf("expected 4 targets (2 services * 2 proxy modes), got %d", len(plan.Targets))
	}

	// Count by service and proxy mode
	proxyWebWithProxy := 0
	proxyWebWithoutProxy := 0
	reverseTunnelWithProxy := 0
	reverseTunnelWithoutProxy := 0

	for _, target := range plan.Targets {
		switch target.ServiceKey {
		case "proxy_web":
			if target.UseProxy {
				proxyWebWithProxy++
			} else {
				proxyWebWithoutProxy++
			}
		case "reverse_tunnel":
			if target.UseProxy {
				reverseTunnelWithProxy++
			} else {
				reverseTunnelWithoutProxy++
			}
		}
	}

	if proxyWebWithProxy != 1 {
		t.Errorf("expected 1 proxy_web with proxy, got %d", proxyWebWithProxy)
	}
	if proxyWebWithoutProxy != 1 {
		t.Errorf("expected 1 proxy_web without proxy, got %d", proxyWebWithoutProxy)
	}
	if reverseTunnelWithProxy != 1 {
		t.Errorf("expected 1 reverse_tunnel with proxy, got %d", reverseTunnelWithProxy)
	}
	if reverseTunnelWithoutProxy != 1 {
		t.Errorf("expected 1 reverse_tunnel without proxy, got %d", reverseTunnelWithoutProxy)
	}
}
