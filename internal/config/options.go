package config

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Options captures runtime inputs supplied via the CLI.
type Options struct {
	PublicAddr        string          `json:"public_addr"`
	ClusterName       string          `json:"cluster_name"`
	TeleportVersion   string          `json:"teleport_version"`
	WebProxyPort      int             `json:"web_proxy_port,omitempty"`
	TLSRoutingEnabled bool            `json:"tls_routing_enabled"`
	Repeat            int             `json:"repeat"`
	ServiceFilter     []string        `json:"service_filter,omitempty"`
	IPAddresses       []string        `json:"ip_addresses,omitempty"`
	Proxy             ProxySettings   `json:"proxy"`
	ProfileSource     *ProfileInfo    `json:"profile_source,omitempty"`
	ClientCert        *ClientCertInfo `json:"-"` // Client cert info moved to top-level client_certs
	HostCAPEM         []byte          `json:"-"`
	ClientCertPEM     []byte          `json:"-"`
	ClientKeyPEM      []byte          `json:"-"`
}

// ProxySettings captures HTTP(S) proxy configuration sourced from the environment.
type ProxySettings struct {
	HTTPSProxy string `json:"https_proxy,omitempty"`
	HTTPProxy  string `json:"http_proxy,omitempty"`
	NoProxy    string `json:"no_proxy,omitempty"`
}

// ProfileInfo records the Teleport profile location used for automatic defaults.
type ProfileInfo struct {
	Name            string `json:"name"`
	Path            string `json:"path"`
	Username        string `json:"username,omitempty"`
	ClientCertPath  string `json:"client_cert_path,omitempty"`
	ClientKeyPath   string `json:"client_key_path,omitempty"`
	ClientCertFound bool   `json:"client_cert_found"`
}

// ClientCertInfo contains metadata about the client certificate used for mutual TLS.
type ClientCertInfo struct {
	CertPath       string          `json:"cert_path"`
	KeyPath        string          `json:"key_path"`
	Fingerprint    string          `json:"fingerprint"`
	Subject        string          `json:"subject"`
	Issuer         string          `json:"issuer"`
	NotBefore      string          `json:"not_before"`
	NotAfter       string          `json:"not_after"`
	SerialNumber   string          `json:"serial_number"`
	SignatureAlgo  string          `json:"signature_algorithm"`
	PublicKeyAlgo  string          `json:"public_key_algorithm"`
	KeyUsage       []string        `json:"key_usage,omitempty"`
	ExtKeyUsage    []string        `json:"ext_key_usage,omitempty"`
	DNSNames       []string        `json:"dns_names,omitempty"`
	EmailAddresses []string        `json:"email_addresses,omitempty"`
	IPAddresses    []string        `json:"ip_addresses,omitempty"`
	URIs           []string        `json:"uris,omitempty"`
	IsCA           bool            `json:"is_ca"`
	Extensions     []CertExtension `json:"extensions,omitempty"`
}

// CertExtension represents a certificate extension.
type CertExtension struct {
	OID      string `json:"oid"`
	Critical bool   `json:"critical"`
	Value    string `json:"value"` // hex-encoded value
}

var usage func()

// Usage prints the most recently configured flag usage output.
func Usage() {
	if usage != nil {
		usage()
	}
}

// ParseArgs converts CLI arguments into strongly-typed options.
func ParseArgs(args []string, serviceKeys []string) (Options, bool, error) {
	fs := flag.NewFlagSet("tlscheck", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	sort.Strings(serviceKeys)
	servicesHelp := "Comma-separated service keys or 'all'"
	if len(serviceKeys) > 0 {
		servicesHelp = fmt.Sprintf("Comma-separated service keys (%s) or 'all'", strings.Join(serviceKeys, ", "))
	}

	var opts Options
	var services string
	var ipAddresses string
	var showVersion bool

	fs.StringVar(&opts.PublicAddr, "proxy-server", "", "Teleport proxy public address (DNS name)")
	fs.IntVar(&opts.Repeat, "repeat", 1, "Attempts per SNI/ALPN/IP combination (default 1)")
	fs.StringVar(&services, "services", "all", servicesHelp)
	fs.StringVar(&ipAddresses, "ip-addresses", "", "Comma-separated list of IP addresses to use instead of DNS resolution")
	fs.BoolVar(&showVersion, "version", false, "Print tlscheck version and exit")
	fs.BoolVar(&showVersion, "v", false, "Print tlscheck version and exit")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s [options]\n\n", fs.Name())
		fmt.Fprintln(fs.Output(), "Options:")
		fmt.Fprintf(fs.Output(), "  --proxy-server string\n\tTeleport proxy public address (DNS name)\n")
		fmt.Fprintf(fs.Output(), "  --repeat int\n\tAttempts per SNI/ALPN/IP combination (default 1)\n")
		fmt.Fprintf(fs.Output(), "  --services string\n\t%s\n", servicesHelp)
		fmt.Fprintf(fs.Output(), "  --ip-addresses string\n\tComma-separated list of IP addresses to use instead of DNS resolution\n")
		fmt.Fprintf(fs.Output(), "  -v, --version\n\tPrint tlscheck version and exit\n")
	}
	usage = fs.Usage

	if err := fs.Parse(args); err != nil {
		return Options{}, false, err
	}

	if opts.Repeat <= 0 {
		return Options{}, false, fmt.Errorf("repeat must be positive (got %d)", opts.Repeat)
	}

	services = strings.TrimSpace(services)
	if services != "" && !strings.EqualFold(services, "all") {
		opts.ServiceFilter = splitCSV(services)
	}

	ipAddresses = strings.TrimSpace(ipAddresses)
	if ipAddresses != "" {
		opts.IPAddresses = splitList(ipAddresses, false)
	}

	opts.Proxy = detectProxySettings()

	return opts, showVersion, nil
}

func splitCSV(value string) []string {
	return splitList(value, true)
}

func splitList(value string, lowercase bool) []string {
	raw := strings.Split(value, ",")
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if lowercase {
			v = strings.ToLower(v)
		}
		out = append(out, v)
	}
	return out
}

func detectProxySettings() ProxySettings {
	return ProxySettings{
		HTTPSProxy: firstNonEmpty(os.Getenv("HTTPS_PROXY"), os.Getenv("https_proxy")),
		HTTPProxy:  firstNonEmpty(os.Getenv("HTTP_PROXY"), os.Getenv("http_proxy")),
		NoProxy:    firstNonEmpty(os.Getenv("NO_PROXY"), os.Getenv("no_proxy")),
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// WantsService reports whether the options request a specific service key.
func (o Options) WantsService(key string) bool {
	if len(o.ServiceFilter) == 0 {
		return true
	}
	key = strings.ToLower(key)
	for _, selected := range o.ServiceFilter {
		if selected == key {
			return true
		}
	}
	return false
}
