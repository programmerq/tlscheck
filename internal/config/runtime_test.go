package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const runtimeHostCAPEM = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUGzJrped1IovnHgwlHGhEq+y3OCkwCgYIKoZIzj0EAwIw\nFDESMBAGA1UEAwwJdGVzdC5jYS5pbyAwHhcNMjQwMTAxMDAwMDAwWhcNMzQwMTAx\nMDAwMDAwWjAUMRIwEAYDVQQDDAl0ZXN0LmNhLmlvMFkwEwYHKoZIzj0CAQYIKoZI\nzj0DAQcDQgAE6yOD87o5iV/mQJu1WDVYj1WFJsbgx5caX5/C/PObbIVdQydb9h9t\nW7x1YgnSUZXoqBYwygJyI072QtdgQXMMB6NTMFEwHQYDVR0OBBYEFNyEJD7BqXc9\n4HIX66D+QP9enZ5hMB8GA1UdIwQYMBaAFNyEJD7BqXc94HIX66D+QP9enZ5hMA8G\nA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgCZ3swaP42gnikIze8ihc\nYtL6vhfVqlhK/SXxPxq8npACIQDB0Gooy2cuglRez2oJ6TP2PzefDs2fzGEylh4G\nWXNoWA==\n-----END CERTIFICATE-----\n"

func TestResolveRuntimeFromProfile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/webapi/ping":
			payload := map[string]any{
				"cluster_name":   "root.example.com",
				"server_version": "v17.9.1",
				"proxy": map[string]any{
					"tls_routing_enabled": false,
					"ssh": map[string]any{
						"public_addr": "cluster.example.com:443",
					},
				},
			}
			if err := json.NewEncoder(w).Encode(payload); err != nil {
				t.Fatalf("encode ping payload: %v", err)
			}
		case "/webapi/auth/export":
			if got := r.URL.Query().Get("type"); got != "tls-host" {
				t.Fatalf("unexpected type: %q", got)
			}
			if _, err := w.Write([]byte(runtimeHostCAPEM)); err != nil {
				t.Fatalf("write host CA: %v", err)
			}
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	t.Setenv("TELEPORT_HOME", dir)

	if err := os.WriteFile(filepath.Join(dir, "current-profile"), []byte("example.com"), 0o600); err != nil {
		t.Fatalf("write current-profile: %v", err)
	}

	profileContent := []byte(fmt.Sprintf(`public_addr: cluster.example.com
web_proxy_addr: %s
ssh_proxy_addr: cluster.example.com:3080
cluster: root.example.com
`, srv.URL))
	if err := os.WriteFile(filepath.Join(dir, "example.com.yaml"), profileContent, 0o600); err != nil {
		t.Fatalf("write profile yaml: %v", err)
	}

	opts := Options{Repeat: 1}

	resolved, err := ResolveRuntime(context.Background(), opts)
	if err != nil {
		t.Fatalf("ResolveRuntime returned error: %v", err)
	}

	if resolved.PublicAddr != "cluster.example.com" {
		t.Fatalf("PublicAddr = %q, want cluster.example.com", resolved.PublicAddr)
	}
	if resolved.ClusterName != "root.example.com" {
		t.Fatalf("ClusterName = %q, want root.example.com", resolved.ClusterName)
	}
	if resolved.TeleportVersion != "v17.9.1" {
		t.Fatalf("TeleportVersion = %q, want v17.9.1", resolved.TeleportVersion)
	}
	if resolved.ProfileSource == nil || resolved.ProfileSource.Name != "example.com" {
		t.Fatalf("ProfileSource = %#v, expected example.com", resolved.ProfileSource)
	}
	wantPath := filepath.Join(dir, "example.com.yaml")
	if resolved.ProfileSource.Path != wantPath {
		t.Fatalf("ProfileSource.Path = %q, want %q", resolved.ProfileSource.Path, wantPath)
	}
	if resolved.WebProxyPort != 443 {
		t.Fatalf("WebProxyPort = %d, want 443", resolved.WebProxyPort)
	}
	if resolved.TLSRoutingEnabled {
		t.Fatal("expected TLSRoutingEnabled to be false")
	}
	if string(resolved.HostCAPEM) != runtimeHostCAPEM {
		t.Fatalf("unexpected HostCAPEM contents: %q", string(resolved.HostCAPEM))
	}
}

func TestResolveRuntimeRequiresProxy(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TELEPORT_HOME", dir)

	opts := Options{Repeat: 1}
	_, err := ResolveRuntime(context.Background(), opts)
	if err == nil {
		t.Fatal("expected error when no profile present")
	}
	if err != ErrProxyServerRequired {
		t.Fatalf("error = %v, want %v", err, ErrProxyServerRequired)
	}
}

func TestResolveRuntimeWithExplicitProxy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/webapi/ping":
			payload := map[string]any{
				"cluster_name":   "root.example.com",
				"server_version": "v17.9.1",
				"proxy": map[string]any{
					"tls_routing_enabled": true,
					"ssh": map[string]any{
						"public_addr": "root.example.com:443",
					},
				},
			}
			if err := json.NewEncoder(w).Encode(payload); err != nil {
				t.Fatalf("encode ping payload: %v", err)
			}
		case "/webapi/auth/export":
			if _, err := w.Write([]byte(runtimeHostCAPEM)); err != nil {
				t.Fatalf("write host CA: %v", err)
			}
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	opts := Options{PublicAddr: srv.URL, Repeat: 1}

	resolved, err := ResolveRuntime(context.Background(), opts)
	if err != nil {
		t.Fatalf("ResolveRuntime returned error: %v", err)
	}
	if resolved.PublicAddr == "" {
		t.Fatalf("expected PublicAddr to be populated")
	}
	if resolved.ClusterName != "root.example.com" {
		t.Fatalf("ClusterName = %q, want root.example.com", resolved.ClusterName)
	}
	if resolved.TeleportVersion != "v17.9.1" {
		t.Fatalf("TeleportVersion = %q, want v17.9.1", resolved.TeleportVersion)
	}
	if resolved.WebProxyPort != 443 {
		t.Fatalf("WebProxyPort = %d, want 443", resolved.WebProxyPort)
	}
	if !resolved.TLSRoutingEnabled {
		t.Fatal("expected TLSRoutingEnabled to be true")
	}
	if string(resolved.HostCAPEM) != runtimeHostCAPEM {
		t.Fatalf("unexpected HostCAPEM contents: %q", string(resolved.HostCAPEM))
	}
}

func TestResolveRuntimeFailsWhenHostCAUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/webapi/ping":
			payload := map[string]any{
				"cluster_name":   "root.example.com",
				"server_version": "v17.9.1",
				"proxy": map[string]any{
					"tls_routing_enabled": true,
					"ssh": map[string]any{
						"public_addr": "root.example.com:443",
					},
				},
			}
			if err := json.NewEncoder(w).Encode(payload); err != nil {
				t.Fatalf("encode ping payload: %v", err)
			}
		case "/webapi/auth/export":
			http.Error(w, "not found", http.StatusNotFound)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	opts := Options{PublicAddr: srv.URL, Repeat: 1}
	if _, err := ResolveRuntime(context.Background(), opts); err == nil {
		t.Fatal("expected error when host CA fetch fails")
	}
}
