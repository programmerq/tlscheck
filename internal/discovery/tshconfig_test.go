package discovery

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadTSHConfig_FileNotExist(t *testing.T) {
	t.Parallel()

	cfg, err := LoadTSHConfig(t.TempDir())
	if err != nil {
		t.Fatalf("expected no error for missing config.yaml, got %v", err)
	}
	if len(cfg.AddHeaders) != 0 {
		t.Fatalf("expected empty config, got %+v", cfg)
	}
}

func TestLoadTSHConfig_EmptyHome(t *testing.T) {
	t.Parallel()

	cfg, err := LoadTSHConfig("")
	if err != nil {
		t.Fatalf("expected no error for empty home, got %v", err)
	}
	if len(cfg.AddHeaders) != 0 {
		t.Fatalf("expected empty config, got %+v", cfg)
	}
}

func TestLoadTSHConfig_ValidFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := `add_headers:
  - proxy: "*.infra.corp.xyz"
    headers:
      "Authorization": "Bearer tokentokentoken"
      "X-Custom-Header": "custom-value"
  - proxy: "other.example.com"
    headers:
      "X-Other": "other-value"
`
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(content), 0600); err != nil {
		t.Fatalf("writing config.yaml: %v", err)
	}

	cfg, err := LoadTSHConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.AddHeaders) != 2 {
		t.Fatalf("expected 2 add_headers entries, got %d", len(cfg.AddHeaders))
	}

	first := cfg.AddHeaders[0]
	if first.Proxy != "*.infra.corp.xyz" {
		t.Errorf("first proxy = %q, want %q", first.Proxy, "*.infra.corp.xyz")
	}
	if first.Headers["Authorization"] != "Bearer tokentokentoken" {
		t.Errorf("Authorization = %q, want %q", first.Headers["Authorization"], "Bearer tokentokentoken")
	}
}

func TestLoadTSHConfig_InvalidYAML(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("add_headers: [\ninvalid yaml"), 0600); err != nil {
		t.Fatalf("writing config.yaml: %v", err)
	}

	_, err := LoadTSHConfig(dir)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestTSHConfigMatchingHeaders(t *testing.T) {
	t.Parallel()

	cfg := TSHConfig{
		AddHeaders: []TSHProxyHeaders{
			{
				Proxy:   "*.infra.corp.xyz",
				Headers: map[string]string{"Authorization": "Bearer abc"},
			},
			{
				Proxy:   "other.example.com",
				Headers: map[string]string{"X-Other": "other"},
			},
			{
				Proxy:   "multi.example.com",
				Headers: map[string]string{"A": "first"},
			},
			{
				Proxy:   "multi.example.com",
				Headers: map[string]string{"A": "second", "B": "b-val"},
			},
		},
	}

	tests := []struct {
		name      string
		proxyAddr string
		want      map[string]string
	}{
		{
			name:      "wildcard match single subdomain",
			proxyAddr: "teleport.infra.corp.xyz",
			want:      map[string]string{"Authorization": "Bearer abc"},
		},
		{
			name:      "wildcard match with port",
			proxyAddr: "teleport.infra.corp.xyz:443",
			want:      map[string]string{"Authorization": "Bearer abc"},
		},
		{
			name:      "exact match",
			proxyAddr: "other.example.com",
			want:      map[string]string{"X-Other": "other"},
		},
		{
			name:      "no match",
			proxyAddr: "unrelated.example.com",
			want:      nil,
		},
		{
			name:      "later entry overrides earlier for same key",
			proxyAddr: "multi.example.com",
			want:      map[string]string{"A": "second", "B": "b-val"},
		},
		{
			name:      "empty proxy addr",
			proxyAddr: "",
			want:      nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := cfg.MatchingHeaders(tt.proxyAddr)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MatchingHeaders(%q) = %v, want %v", tt.proxyAddr, got, tt.want)
			}
		})
	}
}

func TestTSHConfigMatchingHeaders_EmptyPattern(t *testing.T) {
	t.Parallel()

	cfg := TSHConfig{
		AddHeaders: []TSHProxyHeaders{
			{
				Proxy:   "",
				Headers: map[string]string{"X-Skip": "skipped"},
			},
		},
	}
	got := cfg.MatchingHeaders("any.example.com")
	if got != nil {
		t.Errorf("expected nil for empty pattern, got %v", got)
	}
}
