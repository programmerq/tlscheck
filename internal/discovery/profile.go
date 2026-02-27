package discovery

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Profile describes a Teleport profile entry discovered on disk.
type Profile struct {
	Name         string
	Username     string
	PublicAddr   string
	ClusterName  string
	Path         string
	WebProxyAddr string
}

// ClientCert holds the TLS client certificate and key for a profile, along with metadata.
type ClientCert struct {
	CertPEM        []byte
	KeyPEM         []byte
	CertPath       string
	KeyPath        string
	Fingerprint    string
	Subject        string
	Issuer         string
	NotBefore      string
	NotAfter       string
	SerialNumber   string
	SignatureAlgo  string
	PublicKeyAlgo  string
	KeyUsage       []string
	ExtKeyUsage    []string
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []string
	URIs           []string
	IsCA           bool
	Extensions     []certExtension
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
		Username:     strings.TrimSpace(parsed.User),
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
	User         string `yaml:"user"`
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

// GetClientCertPaths returns the expected paths for client certificate and key files.
// It returns the Teleport 17+ format paths (preferred).
// It does not check if the files exist.
func GetClientCertPaths(home, profileName, username string) (certPath, keyPath string) {
	if strings.TrimSpace(home) == "" || strings.TrimSpace(profileName) == "" {
		return "", ""
	}

	// If username is not provided, fall back to using profileName for backwards compatibility
	if strings.TrimSpace(username) == "" {
		username = profileName
	}

	// Teleport 17+ format (preferred)
	// cert: ~/.tsh/keys/{profile}/{username}.crt
	// key: ~/.tsh/keys/{profile}/{username}.key
	certPath = filepath.Join(home, "keys", profileName, fmt.Sprintf("%s.crt", username))
	keyPath = filepath.Join(home, "keys", profileName, fmt.Sprintf("%s.key", username))
	return certPath, keyPath
}

// getLegacyClientCertPaths returns the Teleport 16 and below format paths.
func getLegacyClientCertPaths(home, profileName, username string) (certPath, keyPath string) {
	if strings.TrimSpace(home) == "" || strings.TrimSpace(profileName) == "" {
		return "", ""
	}

	// If username is not provided, fall back to using profileName for backwards compatibility
	if strings.TrimSpace(username) == "" {
		username = profileName
	}

	// Teleport 16 and below format (legacy)
	// cert: ~/.tsh/keys/{profile}/{username}-x509.pem
	// key: ~/.tsh/keys/{profile}/{username}
	certPath = filepath.Join(home, "keys", profileName, fmt.Sprintf("%s-x509.pem", username))
	keyPath = filepath.Join(home, "keys", profileName, username)
	return certPath, keyPath
}

// LoadClientCert attempts to load the TLS client certificate and key from the profile directory.
// Returns nil if the certificate files don't exist or can't be read.
// The username parameter should come from the profile's user field, and profileName is used for the directory path.
// It tries Teleport 17+ format first, then falls back to Teleport 16 and below format.
func LoadClientCert(home, profileName, username string) *ClientCert {
	// Try Teleport 17+ format first
	certPath, keyPath := GetClientCertPaths(home, profileName, username)
	if certPath == "" || keyPath == "" {
		return nil
	}

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)

	// If modern format doesn't exist, try legacy format
	if certErr != nil || keyErr != nil {
		certPath, keyPath = getLegacyClientCertPaths(home, profileName, username)
		if certPath == "" || keyPath == "" {
			return nil
		}
		certPEM, certErr = os.ReadFile(certPath)
		keyPEM, keyErr = os.ReadFile(keyPath)

		if certErr != nil || keyErr != nil {
			return nil
		}
	}

	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil
	}

	result := &ClientCert{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		CertPath: certPath,
		KeyPath:  keyPath,
	}

	// Parse the certificate to extract metadata
	if cert := parseCertificateMetadata(certPEM); cert != nil {
		result.Fingerprint = cert.Fingerprint
		result.Subject = cert.Subject
		result.Issuer = cert.Issuer
		result.NotBefore = cert.NotBefore
		result.NotAfter = cert.NotAfter
		result.SerialNumber = cert.SerialNumber
		result.SignatureAlgo = cert.SignatureAlgo
		result.PublicKeyAlgo = cert.PublicKeyAlgo
		result.KeyUsage = cert.KeyUsage
		result.ExtKeyUsage = cert.ExtKeyUsage
		result.DNSNames = cert.DNSNames
		result.EmailAddresses = cert.EmailAddresses
		result.IPAddresses = cert.IPAddresses
		result.URIs = cert.URIs
		result.IsCA = cert.IsCA
		result.Extensions = cert.Extensions
	}

	return result
}

type certMetadata struct {
	Fingerprint    string
	Subject        string
	Issuer         string
	NotBefore      string
	NotAfter       string
	SerialNumber   string
	SignatureAlgo  string
	PublicKeyAlgo  string
	KeyUsage       []string
	ExtKeyUsage    []string
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []string
	URIs           []string
	IsCA           bool
	Extensions     []certExtension
}

type certExtension struct {
	OID      string
	Critical bool
	Value    string
}

func parseCertificateMetadata(certPEM []byte) *certMetadata {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}

	// Calculate fingerprint (SHA-256)
	sum := sha256.Sum256(cert.Raw)
	fingerprint := fmt.Sprintf("%X", sum[:])

	// Parse key usage
	keyUsages := parseKeyUsage(cert.KeyUsage)

	// Parse extended key usage
	extKeyUsages := parseExtKeyUsage(cert.ExtKeyUsage)

	// Convert IP addresses to strings
	ipAddresses := make([]string, len(cert.IPAddresses))
	for i, ip := range cert.IPAddresses {
		ipAddresses[i] = ip.String()
	}

	// Convert URIs to strings
	uris := make([]string, len(cert.URIs))
	for i, uri := range cert.URIs {
		uris[i] = uri.String()
	}

	// Parse extensions
	extensions := make([]certExtension, 0, len(cert.Extensions))
	for _, ext := range cert.Extensions {
		extensions = append(extensions, certExtension{
			OID:      ext.Id.String(),
			Critical: ext.Critical,
			Value:    fmt.Sprintf("%X", ext.Value),
		})
	}

	return &certMetadata{
		Fingerprint:    fingerprint,
		Subject:        cert.Subject.String(),
		Issuer:         cert.Issuer.String(),
		NotBefore:      cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:       cert.NotAfter.UTC().Format(time.RFC3339),
		SerialNumber:   cert.SerialNumber.String(),
		SignatureAlgo:  cert.SignatureAlgorithm.String(),
		PublicKeyAlgo:  cert.PublicKeyAlgorithm.String(),
		KeyUsage:       keyUsages,
		ExtKeyUsage:    extKeyUsages,
		DNSNames:       cert.DNSNames,
		EmailAddresses: cert.EmailAddresses,
		IPAddresses:    ipAddresses,
		URIs:           uris,
		IsCA:           cert.IsCA,
		Extensions:     extensions,
	}
}

func parseKeyUsage(usage x509.KeyUsage) []string {
	var usages []string
	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "EncipherOnly")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DecipherOnly")
	}
	return usages
}

func parseExtKeyUsage(usage []x509.ExtKeyUsage) []string {
	var usages []string
	for _, u := range usage {
		switch u {
		case x509.ExtKeyUsageAny:
			usages = append(usages, "Any")
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "EmailProtection")
		case x509.ExtKeyUsageIPSECEndSystem:
			usages = append(usages, "IPSECEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			usages = append(usages, "IPSECTunnel")
		case x509.ExtKeyUsageIPSECUser:
			usages = append(usages, "IPSECUser")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSPSigning")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			usages = append(usages, "MicrosoftServerGatedCrypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			usages = append(usages, "NetscapeServerGatedCrypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			usages = append(usages, "MicrosoftCommercialCodeSigning")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			usages = append(usages, "MicrosoftKernelCodeSigning")
		}
	}
	return usages
}
