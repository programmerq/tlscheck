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

	"github.com/programmerq/tlscheck/internal/discovery"
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

func TestResolveRuntimeLoadsClientCertInfo(t *testing.T) {
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

	profileName := "example.com"
	if err := os.WriteFile(filepath.Join(dir, "current-profile"), []byte(profileName), 0o600); err != nil {
		t.Fatalf("write current-profile: %v", err)
	}

	profileContent := []byte(fmt.Sprintf(`public_addr: cluster.example.com
web_proxy_addr: %s
ssh_proxy_addr: cluster.example.com:3080
cluster: root.example.com
`, srv.URL))
	if err := os.WriteFile(filepath.Join(dir, profileName+".yaml"), profileContent, 0o600); err != nil {
		t.Fatalf("write profile yaml: %v", err)
	}

	// Create keys directory and add a test client certificate
	keysDir := filepath.Join(dir, "keys", profileName)
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatalf("create keys directory: %v", err)
	}

	// Generate a test certificate dynamically to avoid expiry issues
	testCertPEM, testKeyPEM, err := discovery.GenerateTestCertificate()
	if err != nil {
		t.Fatalf("generate test certificate: %v", err)
	}

	// Use Teleport 17+ format
	certPath := filepath.Join(keysDir, profileName+".crt")
	keyPath := filepath.Join(keysDir, profileName+".key")
	if err := os.WriteFile(certPath, testCertPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, testKeyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	opts := Options{Repeat: 1}

	resolved, err := ResolveRuntime(context.Background(), opts)
	if err != nil {
		t.Fatalf("ResolveRuntime returned error: %v", err)
	}

	// Verify client cert info is populated
	if resolved.ClientCert == nil {
		t.Fatal("ClientCert should not be nil")
	}
	if resolved.ClientCert.CertPath != certPath {
		t.Errorf("ClientCert.CertPath = %q, want %q", resolved.ClientCert.CertPath, certPath)
	}
	if resolved.ClientCert.KeyPath != keyPath {
		t.Errorf("ClientCert.KeyPath = %q, want %q", resolved.ClientCert.KeyPath, keyPath)
	}
	if resolved.ClientCert.Subject == "" {
		t.Error("ClientCert.Subject should not be empty")
	}
	if resolved.ClientCert.Issuer == "" {
		t.Error("ClientCert.Issuer should not be empty")
	}
	if resolved.ClientCert.NotBefore == "" {
		t.Error("ClientCert.NotBefore should not be empty")
	}
	if resolved.ClientCert.NotAfter == "" {
		t.Error("ClientCert.NotAfter should not be empty")
	}
	if resolved.ClientCert.Fingerprint == "" {
		t.Error("ClientCert.Fingerprint should not be empty")
	}
	if resolved.ClientCert.SerialNumber == "" {
		t.Error("ClientCert.SerialNumber should not be empty")
	}
	if resolved.ClientCert.SignatureAlgo == "" {
		t.Error("ClientCert.SignatureAlgo should not be empty")
	}
	if resolved.ClientCert.PublicKeyAlgo == "" {
		t.Error("ClientCert.PublicKeyAlgo should not be empty")
	}

	t.Logf("Client cert info successfully loaded:")
	t.Logf("  CertPath: %s", resolved.ClientCert.CertPath)
	t.Logf("  KeyPath: %s", resolved.ClientCert.KeyPath)
	t.Logf("  Fingerprint: %s", resolved.ClientCert.Fingerprint)
	t.Logf("  Subject: %s", resolved.ClientCert.Subject)
	t.Logf("  Issuer: %s", resolved.ClientCert.Issuer)
	t.Logf("  NotBefore: %s", resolved.ClientCert.NotBefore)
	t.Logf("  NotAfter: %s", resolved.ClientCert.NotAfter)
	t.Logf("  SerialNumber: %s", resolved.ClientCert.SerialNumber)
	t.Logf("  SignatureAlgo: %s", resolved.ClientCert.SignatureAlgo)
	t.Logf("  PublicKeyAlgo: %s", resolved.ClientCert.PublicKeyAlgo)
	t.Logf("  KeyUsage: %v", resolved.ClientCert.KeyUsage)
	t.Logf("  ExtKeyUsage: %v", resolved.ClientCert.ExtKeyUsage)
	t.Logf("  Extensions count: %d", len(resolved.ClientCert.Extensions))
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

// newPingServer returns a test HTTP server that responds to /webapi/ping and
// /webapi/auth/export with canned responses.  publicAddr is included in the
// ping response as proxy.ssh.public_addr.
func newPingServer(t *testing.T, publicAddr string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/webapi/ping":
			payload := map[string]any{
				"cluster_name":   "root.example.com",
				"server_version": "v17.9.1",
				"proxy": map[string]any{
					"tls_routing_enabled": false,
					"ssh": map[string]any{
						"public_addr": publicAddr,
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
}

func TestResolveRuntimeTSHConfigHeadersWithProfile(t *testing.T) {
	srv := newPingServer(t, "cluster.example.com:443")
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

	tshConfigContent := []byte(`add_headers:
  - proxy: "cluster.example.com"
    headers:
      "Authorization": "Bearer profile-token"
`)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), tshConfigContent, 0o600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	opts := Options{Repeat: 1}
	resolved, err := ResolveRuntime(context.Background(), opts)
	if err != nil {
		t.Fatalf("ResolveRuntime returned error: %v", err)
	}

	if resolved.ExtraHeaders["Authorization"] != "Bearer profile-token" {
		t.Fatalf("ExtraHeaders[Authorization] = %q, want %q", resolved.ExtraHeaders["Authorization"], "Bearer profile-token")
	}
}

func TestResolveRuntimeTSHConfigHeadersWithoutProfile(t *testing.T) {
	srv := newPingServer(t, "127.0.0.1:443")
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	t.Setenv("TELEPORT_HOME", dir)

	// No active profile — user supplies --proxy-server directly.
	tshConfigContent := []byte(`add_headers:
  - proxy: "127.0.0.1"
    headers:
      "X-Token": "from-config"
`)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), tshConfigContent, 0o600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	opts := Options{PublicAddr: srv.URL, Repeat: 1}
	resolved, err := ResolveRuntime(context.Background(), opts)
	if err != nil {
		t.Fatalf("ResolveRuntime returned error: %v", err)
	}

	if resolved.ExtraHeaders["X-Token"] != "from-config" {
		t.Fatalf("ExtraHeaders[X-Token] = %q, want %q", resolved.ExtraHeaders["X-Token"], "from-config")
	}
}

func TestResolveRuntimeTSHConfigHeadersCLIOverride(t *testing.T) {
	srv := newPingServer(t, "127.0.0.1:443")
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	t.Setenv("TELEPORT_HOME", dir)

	// config.yaml sets Authorization; CLI -H should override it.
	tshConfigContent := []byte(`add_headers:
  - proxy: "127.0.0.1"
    headers:
      "Authorization": "from-config"
      "X-Base": "base-value"
`)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), tshConfigContent, 0o600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	opts := Options{
		PublicAddr:   srv.URL,
		Repeat:       1,
		ExtraHeaders: map[string]string{"Authorization": "from-cli"},
	}
	resolved, err := ResolveRuntime(context.Background(), opts)
	if err != nil {
		t.Fatalf("ResolveRuntime returned error: %v", err)
	}

	// CLI value must win.
	if resolved.ExtraHeaders["Authorization"] != "from-cli" {
		t.Fatalf("ExtraHeaders[Authorization] = %q, want %q (CLI should override config)", resolved.ExtraHeaders["Authorization"], "from-cli")
	}
	// Config-only header must still be present.
	if resolved.ExtraHeaders["X-Base"] != "base-value" {
		t.Fatalf("ExtraHeaders[X-Base] = %q, want %q", resolved.ExtraHeaders["X-Base"], "base-value")
	}
}
