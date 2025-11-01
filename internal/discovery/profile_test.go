package discovery

import (
	"os"
	"path/filepath"
	"strings"
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

func TestDefaultTeleportHome(t *testing.T) {
	t.Run("uses TELEPORT_HOME when set", func(t *testing.T) {
		customHome := "/custom/teleport/home"
		t.Setenv("TELEPORT_HOME", customHome)

		home := DefaultTeleportHome()
		if home != customHome {
			t.Errorf("DefaultTeleportHome() = %q, want %q", home, customHome)
		}
	})

	t.Run("falls back to ~/.tsh when TELEPORT_HOME not set", func(t *testing.T) {
		t.Setenv("TELEPORT_HOME", "")

		home := DefaultTeleportHome()
		// Should end with .tsh
		if home == "" {
			t.Error("DefaultTeleportHome() returned empty string")
		}
		if !strings.HasSuffix(home, ".tsh") {
			t.Errorf("DefaultTeleportHome() = %q, expected to end with .tsh", home)
		}
	})

	t.Run("trims whitespace from TELEPORT_HOME", func(t *testing.T) {
		customHome := "/custom/teleport/home"
		t.Setenv("TELEPORT_HOME", "  "+customHome+"  ")

		home := DefaultTeleportHome()
		if home != customHome {
			t.Errorf("DefaultTeleportHome() = %q, want %q (should trim whitespace)", home, customHome)
		}
	})
}

func TestLoadClientCert(t *testing.T) {
	t.Parallel()

	t.Run("loads valid cert and key", func(t *testing.T) {
		dir := t.TempDir()
		profileName := "test.example.com"

		// Create keys directory structure
		keysDir := filepath.Join(dir, "keys", profileName)
		if err := os.MkdirAll(keysDir, 0o700); err != nil {
			t.Fatalf("failed to create keys directory: %v", err)
		}

		// Generate a test certificate dynamically to avoid expiry issues
		certPEM, keyPEM, err := GenerateTestCertificate()
		if err != nil {
			t.Fatalf("failed to generate test certificate: %v", err)
		}

		certPath := filepath.Join(keysDir, profileName+"-x509.pem")
		keyPath := filepath.Join(keysDir, profileName)

		if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
			t.Fatalf("failed to write cert: %v", err)
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			t.Fatalf("failed to write key: %v", err)
		}

		// Load client cert
		clientCert := LoadClientCert(dir, profileName)
		if clientCert == nil {
			t.Fatal("LoadClientCert returned nil, expected valid cert")
		}

		if string(clientCert.CertPEM) != string(certPEM) {
			t.Errorf("CertPEM = %q, want %q", clientCert.CertPEM, certPEM)
		}
		if string(clientCert.KeyPEM) != string(keyPEM) {
			t.Errorf("KeyPEM = %q, want %q", clientCert.KeyPEM, keyPEM)
		}
		if clientCert.CertPath != certPath {
			t.Errorf("CertPath = %q, want %q", clientCert.CertPath, certPath)
		}
		if clientCert.KeyPath != keyPath {
			t.Errorf("KeyPath = %q, want %q", clientCert.KeyPath, keyPath)
		}

		// Check certificate metadata parsing
		if clientCert.Subject == "" {
			t.Error("Subject should not be empty")
		}
		if !strings.Contains(clientCert.Subject, "test-user@example.com") {
			t.Errorf("Subject = %q, should contain test-user@example.com", clientCert.Subject)
		}
		if clientCert.Issuer == "" {
			t.Error("Issuer should not be empty")
		}
		if clientCert.NotBefore == "" {
			t.Error("NotBefore should not be empty")
		}
		if clientCert.NotAfter == "" {
			t.Error("NotAfter should not be empty")
		}
		// Verify it's in RFC3339 format
		if !strings.Contains(clientCert.NotBefore, "T") {
			t.Errorf("NotBefore = %q, expected RFC3339 format with 'T'", clientCert.NotBefore)
		}
	})

	t.Run("returns nil when cert file missing", func(t *testing.T) {
		dir := t.TempDir()
		profileName := "missing.example.com"

		clientCert := LoadClientCert(dir, profileName)
		if clientCert != nil {
			t.Error("LoadClientCert should return nil when cert file is missing")
		}
	})

	t.Run("returns nil with empty home", func(t *testing.T) {
		clientCert := LoadClientCert("", "test.example.com")
		if clientCert != nil {
			t.Error("LoadClientCert should return nil with empty home")
		}
	})

	t.Run("returns nil with empty profile name", func(t *testing.T) {
		dir := t.TempDir()
		clientCert := LoadClientCert(dir, "")
		if clientCert != nil {
			t.Error("LoadClientCert should return nil with empty profile name")
		}
	})
}
