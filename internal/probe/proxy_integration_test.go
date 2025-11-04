package probe

import (
	"context"
	"testing"
	"time"

	"github.com/programmerq/tlscheck/internal/plan"
)

// TestEngineUsesProxyDialerWhenTargetSpecifies verifies that the engine
// uses a proxy dialer when the target has UseProxy=true.
func TestEngineUsesProxyDialerWhenTargetSpecifies(t *testing.T) {
	engine := NewEngine()

	// Create a target that uses proxy
	targetWithProxy := plan.ProbeTarget{
		ServiceKey:  "test_service",
		DisplayName: "Test Service",
		Address:     "example.com",
		Port:        443,
		PrimarySNI:  "example.com",
		ALPNs:       []string{"h2"},
		Trust:       plan.TrustSystemRoots,
		Repeat:      1,
		UseProxy:    true,
		ProxyURL:    "http://invalid-proxy.local:9999", // Invalid proxy to force failure
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result := engine.probeOnce(ctx, targetWithProxy, 1)

	// The probe should fail because the proxy is invalid/unreachable
	if result.Failure == nil {
		t.Error("expected probe to fail with invalid proxy")
	}

	// Verify the result includes the target configuration
	if !result.Target.UseProxy {
		t.Error("result target should have UseProxy=true")
	}
	if result.Target.ProxyURL != "http://invalid-proxy.local:9999" {
		t.Errorf("result target ProxyURL = %q, want %q",
			result.Target.ProxyURL, "http://invalid-proxy.local:9999")
	}
}

// TestEngineUsesDirectDialerWhenNoProxy verifies that the engine uses
// a direct dialer when UseProxy=false.
func TestEngineUsesDirectDialerWhenNoProxy(t *testing.T) {
	engine := NewEngine()

	// Create a target that doesn't use proxy
	targetDirect := plan.ProbeTarget{
		ServiceKey:  "test_service",
		DisplayName: "Test Service",
		Address:     "example.com",
		Port:        443,
		PrimarySNI:  "example.com",
		ALPNs:       []string{"h2"},
		Trust:       plan.TrustSystemRoots,
		Repeat:      1,
		UseProxy:    false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := engine.probeOnce(ctx, targetDirect, 1)

	// The probe may fail or succeed depending on network, but it should
	// NOT fail with a proxy-related error
	if result.Failure != nil {
		if result.Failure.Kind == "proxy_config_error" {
			t.Errorf("unexpected proxy error when UseProxy=false: %s", result.Failure.Message)
		}
	}

	// Verify the result reflects no proxy usage
	if result.Target.UseProxy {
		t.Error("result target should have UseProxy=false")
	}
	if result.Target.ProxyURL != "" {
		t.Errorf("result target ProxyURL should be empty, got %q", result.Target.ProxyURL)
	}
}
