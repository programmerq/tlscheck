package discovery

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// TSHConfig represents the relevant portions of ~/.tsh/config.yaml.
// Only the add_headers section is parsed; all other fields are ignored.
type TSHConfig struct {
	AddHeaders []TSHProxyHeaders `yaml:"add_headers"`
}

// TSHProxyHeaders pairs a proxy glob pattern with the HTTP headers to inject.
type TSHProxyHeaders struct {
	Proxy   string            `yaml:"proxy"`
	Headers map[string]string `yaml:"headers"`
}

// LoadTSHConfig reads and parses the tsh config.yaml from the given Teleport home
// directory.  If the file does not exist an empty TSHConfig is returned without
// error, matching the behaviour of other profile-loading helpers in this package.
func LoadTSHConfig(home string) (TSHConfig, error) {
	if strings.TrimSpace(home) == "" {
		return TSHConfig{}, nil
	}

	configPath := filepath.Join(home, "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return TSHConfig{}, nil
		}
		return TSHConfig{}, fmt.Errorf("reading tsh config.yaml: %w", err)
	}

	var cfg TSHConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return TSHConfig{}, fmt.Errorf("decoding tsh config.yaml: %w", err)
	}

	return cfg, nil
}

// MatchingHeaders returns a merged map of HTTP headers whose proxy pattern
// matches proxyAddr.  When multiple patterns match, later entries in
// add_headers override earlier ones for the same header name.
//
// proxyAddr should be a bare hostname or hostname:port; any scheme prefix is
// stripped before matching so that the patterns in config.yaml work against the
// same address format tsh uses.
func (c TSHConfig) MatchingHeaders(proxyAddr string) map[string]string {
	proxyAddr = normalizeHost(proxyAddr)

	result := make(map[string]string)
	for _, entry := range c.AddHeaders {
		pattern := strings.TrimSpace(entry.Proxy)
		if pattern == "" {
			continue
		}

		matched, err := path.Match(pattern, proxyAddr)
		if err != nil {
			// path.Match only returns an error for a malformed pattern.
			continue
		}
		if !matched {
			continue
		}

		for k, v := range entry.Headers {
			k = strings.TrimSpace(k)
			if k != "" {
				result[k] = v
			}
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}
