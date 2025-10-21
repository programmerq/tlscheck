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

func TestResolveRuntimeFromProfile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webapi/ping" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		payload := map[string]string{
			"cluster_name":   "root.example.com",
			"server_version": "v17.9.1",
		}
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			t.Fatalf("encode ping payload: %v", err)
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
		if r.URL.Path != "/webapi/ping" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		payload := map[string]string{
			"cluster_name":   "root.example.com",
			"server_version": "v17.9.1",
		}
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			t.Fatalf("encode ping payload: %v", err)
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
}
