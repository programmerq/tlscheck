package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchClusterInfo(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webapi/ping" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		payload := map[string]any{
			"cluster_name":   "root.example.com",
			"server_version": "v17.3.2",
			"proxy": map[string]any{
				"tls_routing_enabled": false,
				"ssh": map[string]any{
					"public_addr": "root.example.com:443",
				},
			},
		}
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			t.Fatalf("failed to encode payload: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	info, err := FetchClusterInfo(context.Background(), srv.URL, ProxySettings{})
	if err != nil {
		t.Fatalf("FetchClusterInfo returned error: %v", err)
	}

	if info.ClusterName != "root.example.com" {
		t.Fatalf("ClusterName = %q, want root.example.com", info.ClusterName)
	}
	if info.ServerVersion != "v17.3.2" {
		t.Fatalf("ServerVersion = %q, want v17.3.2", info.ServerVersion)
	}
	if info.Proxy.WebProxyPublicAddr != "root.example.com:443" {
		t.Fatalf("WebProxyPublicAddr = %q, want root.example.com:443", info.Proxy.WebProxyPublicAddr)
	}
	if info.Proxy.TLSRoutingEnabled {
		t.Fatal("expected TLSRoutingEnabled to be false")
	}
}

func TestFetchClusterInfoSkipsTLSVerification(t *testing.T) {
	t.Parallel()

	// Use a TLS server with self-signed certificate - this would fail
	// certificate verification if InsecureSkipVerify was not set
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webapi/ping" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		payload := map[string]any{
			"cluster_name":   "test-cluster",
			"server_version": "v18.0.0",
			"proxy": map[string]any{
				"tls_routing_enabled": true,
				"ssh": map[string]any{
					"public_addr": "test.example.com:443",
				},
			},
		}
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			t.Fatalf("failed to encode payload: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	// This request would fail with "x509: certificate signed by unknown authority"
	// if InsecureSkipVerify was not set to true in the transport
	info, err := FetchClusterInfo(context.Background(), srv.URL, ProxySettings{})
	if err != nil {
		t.Fatalf("FetchClusterInfo returned error (expected to skip TLS verification): %v", err)
	}

	if info.ClusterName != "test-cluster" {
		t.Fatalf("ClusterName = %q, want test-cluster", info.ClusterName)
	}
	if info.ServerVersion != "v18.0.0" {
		t.Fatalf("ServerVersion = %q, want v18.0.0", info.ServerVersion)
	}

	// Verify InsecureSkipVerify flag is set in response
	if !info.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify to be true")
	}
	if info.TLSVerificationNote == "" {
		t.Fatal("expected TLSVerificationNote to be set")
	}
}
