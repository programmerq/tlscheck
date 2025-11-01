package discovery

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Profile describes a Teleport profile entry discovered on disk.
type Profile struct {
	Name         string
	PublicAddr   string
	ClusterName  string
	Path         string
	WebProxyAddr string
}

// ClientCert holds the TLS client certificate and key for a profile.
type ClientCert struct {
	CertPEM []byte
	KeyPEM  []byte
}

// ErrNoActiveProfile indicates that no active Teleport profile could be located.
var ErrNoActiveProfile = errors.New("no active Teleport profile")

// DefaultTeleportHome resolves the Teleport home directory.
func DefaultTeleportHome() string {
	if env := strings.TrimSpace(os.Getenv("TELEPORT_HOME")); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".tsh")
}

// LoadActiveProfile locates the active Teleport profile from the current-profile marker.
func LoadActiveProfile(home string) (Profile, error) {
	if strings.TrimSpace(home) == "" {
		return Profile{}, ErrNoActiveProfile
	}

	name, err := readCurrentProfileName(home)
	if err != nil {
		if errors.Is(err, ErrNoActiveProfile) {
			return loadFromProfilesYAML(home)
		}
		return Profile{}, err
	}

	return loadProfileFile(home, name)
}

func readCurrentProfileName(home string) (string, error) {
	path := filepath.Join(home, "current-profile")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNoActiveProfile
		}
		return "", fmt.Errorf("reading current-profile: %w", err)
	}
	name := strings.TrimSpace(string(data))
	if name == "" {
		return "", ErrNoActiveProfile
	}
	return name, nil
}

func loadProfileFile(home, name string) (Profile, error) {
	path := filepath.Join(home, fmt.Sprintf("%s.yaml", name))
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Profile{}, ErrNoActiveProfile
		}
		return Profile{}, fmt.Errorf("reading profile %q: %w", name, err)
	}

	var parsed tshProfile
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return Profile{}, fmt.Errorf("decoding profile %q: %w", name, err)
	}

	publicAddr := normalizeHost(parsed.PublicAddr)
	if publicAddr == "" {
		publicAddr = normalizeHost(parsed.SSHProxyAddr)
	}
	if publicAddr == "" {
		publicAddr = normalizeHost(parsed.WebProxyAddr)
	}
	if publicAddr == "" {
		return Profile{}, fmt.Errorf("profile %q does not define a proxy address", name)
	}

	profile := Profile{
		Name:         name,
		PublicAddr:   publicAddr,
		ClusterName:  strings.TrimSpace(firstNonEmpty(parsed.Cluster, name)),
		Path:         path,
		WebProxyAddr: strings.TrimSpace(firstNonEmpty(parsed.WebProxyAddr, parsed.SSHProxyAddr, parsed.PublicAddr)),
	}

	if profile.WebProxyAddr == "" {
		profile.WebProxyAddr = publicAddr
	}

	return profile, nil
}

func loadFromProfilesYAML(home string) (Profile, error) {
	path := filepath.Join(home, "profiles.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Profile{}, ErrNoActiveProfile
		}
		return Profile{}, fmt.Errorf("reading profiles.yaml: %w", err)
	}

	var parsed profilesFile
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return Profile{}, fmt.Errorf("decoding profiles.yaml: %w", err)
	}

	profileName := strings.TrimSpace(parsed.CurrentProfile)
	if profileName == "" && len(parsed.Profiles) == 1 {
		profileName = parsed.Profiles[0].Name
	}
	if profileName == "" {
		return Profile{}, ErrNoActiveProfile
	}

	entry, ok := parsed.byName(profileName)
	if !ok {
		return Profile{}, fmt.Errorf("profile %q not present in profiles.yaml", profileName)
	}

	publicAddr := normalizeHost(entry.PublicAddr)
	if publicAddr == "" {
		publicAddr = normalizeHost(entry.ProxyURL)
	}
	if publicAddr == "" {
		publicAddr = normalizeHost(entry.WebProxyAddr)
	}
	if publicAddr == "" {
		return Profile{}, fmt.Errorf("profile %q does not define a proxy address", entry.Name)
	}

	profile := Profile{
		Name:         entry.Name,
		PublicAddr:   publicAddr,
		ClusterName:  strings.TrimSpace(firstNonEmpty(entry.Cluster, entry.Name)),
		Path:         filepath.Join(home, fmt.Sprintf("%s.yaml", entry.Name)),
		WebProxyAddr: strings.TrimSpace(firstNonEmpty(entry.WebProxyAddr, entry.ProxyURL, entry.PublicAddr)),
	}
	if profile.WebProxyAddr == "" {
		profile.WebProxyAddr = publicAddr
	}

	return profile, nil
}

type tshProfile struct {
	WebProxyAddr string `yaml:"web_proxy_addr"`
	SSHProxyAddr string `yaml:"ssh_proxy_addr"`
	PublicAddr   string `yaml:"public_addr"`
	Cluster      string `yaml:"cluster"`
}

type profilesFile struct {
	CurrentProfile string          `yaml:"current_profile"`
	Profiles       []profileRecord `yaml:"profiles"`
}

type profileRecord struct {
	Name         string `yaml:"name"`
	PublicAddr   string `yaml:"public_addr"`
	ProxyURL     string `yaml:"proxy_url"`
	WebProxyAddr string `yaml:"web_proxy_addr"`
	Cluster      string `yaml:"cluster"`
}

func (p profilesFile) byName(name string) (profileRecord, bool) {
	for _, rec := range p.Profiles {
		if rec.Name == name {
			return rec, true
		}
	}
	return profileRecord{}, false
}

func normalizeHost(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		if u, err := url.Parse(value); err == nil {
			host := u.Hostname()
			if host != "" {
				return host
			}
			if u.Host != "" {
				if host, _, err := net.SplitHostPort(u.Host); err == nil {
					return host
				}
				return u.Host
			}
		}
	}

	if host, _, err := net.SplitHostPort(value); err == nil {
		return host
	}

	return value
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// LoadClientCert attempts to load the TLS client certificate and key from the profile directory.
// Returns nil if the certificate files don't exist or can't be read.
func LoadClientCert(home, profileName string) *ClientCert {
	if strings.TrimSpace(home) == "" || strings.TrimSpace(profileName) == "" {
		return nil
	}

	// tsh stores user TLS certificates as <profile>-x509.pem in the profile directory
	certPath := filepath.Join(home, "keys", profileName, fmt.Sprintf("%s-x509.pem", profileName))
	keyPath := filepath.Join(home, "keys", profileName, profileName)

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)

	if certErr != nil || keyErr != nil {
		return nil
	}

	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil
	}

	return &ClientCert{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}
}
