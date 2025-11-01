package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadActiveProfileCurrentProfile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "current-profile"), []byte("teleport.example.com"), 0o600); err != nil {
		t.Fatalf("failed to write current-profile: %v", err)
	}

	profileContent := []byte(`public_addr: cluster.example.com
web_proxy_addr: cluster.example.com:443
ssh_proxy_addr: cluster.example.com:3080
cluster: root.example.com
`)
	if err := os.WriteFile(filepath.Join(dir, "teleport.example.com.yaml"), profileContent, 0o600); err != nil {
		t.Fatalf("failed to write profile yaml: %v", err)
	}

	profile, err := LoadActiveProfile(dir)
	if err != nil {
		t.Fatalf("LoadActiveProfile returned error: %v", err)
	}

	if profile.Name != "teleport.example.com" {
		t.Fatalf("Name = %q, want teleport.example.com", profile.Name)
	}
	if profile.PublicAddr != "cluster.example.com" {
		t.Fatalf("PublicAddr = %q, want cluster.example.com", profile.PublicAddr)
	}
	if profile.WebProxyAddr != "cluster.example.com:443" {
		t.Fatalf("WebProxyAddr = %q, want cluster.example.com:443", profile.WebProxyAddr)
	}
	if profile.ClusterName != "root.example.com" {
		t.Fatalf("ClusterName = %q, want root.example.com", profile.ClusterName)
	}
	wantPath := filepath.Join(dir, "teleport.example.com.yaml")
	if profile.Path != wantPath {
		t.Fatalf("Path = %q, want %q", profile.Path, wantPath)
	}
}

func TestLoadActiveProfileLegacy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := []byte(`current_profile: example.com
profiles:
  - name: example.com
    public_addr: cluster.example.com
    proxy_url: cluster.example.com:3080
    web_proxy_addr: cluster.example.com:3080
    cluster: root.example.com
`)
	if err := os.WriteFile(filepath.Join(dir, "profiles.yaml"), content, 0o600); err != nil {
		t.Fatalf("failed to write profiles.yaml: %v", err)
	}

	profile, err := LoadActiveProfile(dir)
	if err != nil {
		t.Fatalf("LoadActiveProfile returned error: %v", err)
	}

	if profile.PublicAddr != "cluster.example.com" {
		t.Fatalf("PublicAddr = %q, want cluster.example.com", profile.PublicAddr)
	}

	if profile.WebProxyAddr != "cluster.example.com:3080" {
		t.Fatalf("WebProxyAddr = %q, want cluster.example.com:3080", profile.WebProxyAddr)
	}

	if profile.ClusterName != "root.example.com" {
		t.Fatalf("ClusterName = %q, want root.example.com", profile.ClusterName)
	}

	wantPath := filepath.Join(dir, "example.com.yaml")
	if profile.Path != wantPath {
		t.Fatalf("Path = %q, want %q", profile.Path, wantPath)
	}
}
