package config

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Output format constants
const (
	OutputFormatJSON = "json"
	OutputFormatHTML = "html"
)

// Options captures runtime inputs supplied via the CLI.
type Options struct {
	PublicAddr        string            `json:"public_addr" jsonschema:"description=Public DNS name or IP address of the Teleport proxy server"`
	ClusterName       string            `json:"cluster_name" jsonschema:"description=Teleport cluster name as reported by /webapi/ping"`
	TeleportVersion   string            `json:"teleport_version" jsonschema:"description=Semantic version of the Teleport cluster (e.g. v18.0.0)"`
	WebProxyPort      int               `json:"web_proxy_port,omitempty" jsonschema:"description=TCP port number for the Teleport proxy web listener (typically 443 or 3080)"`
	TLSRoutingEnabled bool              `json:"tls_routing_enabled" jsonschema:"description=Whether TLS routing is enabled on the Teleport cluster (multiplexes all services on one port)"`
	Repeat            int               `json:"repeat" jsonschema:"description=Number of probe attempts to execute per target combination"`
	ServiceFilter     []string          `json:"service_filter,omitempty" jsonschema:"description=Optional list of service keys to probe (e.g. proxy_web, proxy_ssh). When empty, all services are probed"`
	IPAddresses       []string          `json:"ip_addresses,omitempty" jsonschema:"description=Optional list of specific IP addresses to probe instead of DNS resolution"`
	UseProfileCredentials bool              `json:"use_profile_credentials" jsonschema:"description=Whether to load and use client certificates from the tsh profile for mutual TLS probes"`
	ExtraHeaders          map[string]string `json:"extra_headers,omitempty" jsonschema:"description=Extra HTTP headers to inject when connecting (e.g. Authorization). Each test runs both with and without these headers. Loaded from ~/.tsh/config.yaml add_headers or -H/--header flag"`
	OutputFormat         string            `json:"output_format,omitempty" jsonschema:"description=Output format: html (default) or json"`
	OutputFile           string            `json:"-"`
	OutputFormatExplicit bool              `json:"-"`
	Verbose              bool              `json:"verbose,omitempty" jsonschema:"description=Enable verbose logging to stderr for debugging"`
	Proxy             ProxySettings     `json:"proxy" jsonschema:"description=HTTP/HTTPS proxy configuration detected from environment variables"`
	ProfileSource     *ProfileInfo      `json:"profile_source,omitempty" jsonschema:"description=Information about the tsh profile used to populate default values"`
	ClientCert        *ClientCertInfo   `json:"-"` // Client cert info moved to top-level client_certs
	HostCAPEM         []byte            `json:"-"`
	ClientCertPEM     []byte            `json:"-"`
	ClientKeyPEM      []byte            `json:"-"`
}

// ProxySettings captures HTTP(S) proxy configuration sourced from the environment.
type ProxySettings struct {
	HTTPSProxy string `json:"https_proxy,omitempty" jsonschema:"description=HTTPS proxy URL from HTTPS_PROXY environment variable"`
	HTTPProxy  string `json:"http_proxy,omitempty" jsonschema:"description=HTTP proxy URL from HTTP_PROXY environment variable"`
	NoProxy    string `json:"no_proxy,omitempty" jsonschema:"description=Comma-separated list of hosts to bypass proxy from NO_PROXY environment variable"`
}

// ProfileInfo records the Teleport profile location used for automatic defaults.
type ProfileInfo struct {
	Name            string `json:"name" jsonschema:"description=Name of the tsh profile (typically matches the proxy address)"`
	Path            string `json:"path" jsonschema:"description=Filesystem path to the tsh profile directory"`
	Username        string `json:"username,omitempty" jsonschema:"description=Teleport username from the profile"`
	ClientCertPath  string `json:"client_cert_path,omitempty" jsonschema:"description=Path to the client certificate file for mutual TLS"`
	ClientKeyPath   string `json:"client_key_path,omitempty" jsonschema:"description=Path to the client certificate private key file"`
	ClientCertFound bool   `json:"client_cert_found" jsonschema:"description=Whether a valid client certificate was found and loaded"`
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

// headerFlag is a repeatable flag.Value that accumulates "Name: Value" header
// pairs across multiple flag invocations.  It mirrors curl's -H behaviour:
//   - Each invocation adds one header: -H "Authorization: Bearer token"
//   - Passing @filename reads one header per non-blank, non-comment line.
type headerFlag struct {
	headers map[string]string
}

// String returns a display representation of the accumulated headers.
func (h *headerFlag) String() string {
	if h == nil || len(h.headers) == 0 {
		return ""
	}
	keys := make([]string, 0, len(h.headers))
	for k := range h.headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+": "+h.headers[k])
	}
	return strings.Join(parts, ", ")
}

// Set processes a single flag value.  If val starts with '@', the rest is
// treated as a path to a file containing one header per line.  Otherwise val
// must be in "Name: Value" format.
func (h *headerFlag) Set(val string) error {
	if strings.HasPrefix(val, "@") {
		return h.loadFromFile(strings.TrimPrefix(val, "@"))
	}
	return h.parseOne(val)
}

func (h *headerFlag) parseOne(val string) error {
	idx := strings.IndexByte(val, ':')
	if idx < 0 {
		return fmt.Errorf("header %q is missing a colon separator (expected \"Name: Value\")", val)
	}
	name := strings.TrimSpace(val[:idx])
	value := strings.TrimSpace(val[idx+1:])
	if name == "" {
		return fmt.Errorf("empty header name in %q", val)
	}
	if h.headers == nil {
		h.headers = make(map[string]string)
	}
	h.headers[name] = value
	return nil
}

func (h *headerFlag) loadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading header file %q: %w", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := h.parseOne(line); err != nil {
			return fmt.Errorf("in file %q: %w", path, err)
		}
	}
	return nil
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
	var headerFlagVal headerFlag
	var showVersion bool

	fs.StringVar(&opts.PublicAddr, "proxy-server", "", "Teleport proxy public address (DNS name)")
	fs.IntVar(&opts.Repeat, "repeat", 1, "Attempts per SNI/ALPN/IP combination (default 1)")
	fs.StringVar(&services, "services", "all", servicesHelp)
	fs.StringVar(&ipAddresses, "ip-addresses", "", "Comma-separated list of IP addresses to use instead of DNS resolution")
	// -H and --header are aliases, both pointing at the same headerFlag value.
	const headerUsage = `Add an extra HTTP header (format: "Name: Value"). May be repeated. Use @filename to load headers from a file. Each probe runs both with and without these headers.`
	fs.Var(&headerFlagVal, "H", headerUsage)
	fs.Var(&headerFlagVal, "header", headerUsage)
	fs.BoolVar(&opts.UseProfileCredentials, "use-profile-credentials", false, "Load and use client certificates from tsh profile for mutual TLS probes")
	fs.StringVar(&opts.OutputFormat, "output-format", OutputFormatHTML, fmt.Sprintf("Output format: %s (default) or %s", OutputFormatHTML, OutputFormatJSON))
	fs.StringVar(&opts.OutputFile, "output", "", "Write output to file instead of stdout")
	fs.StringVar(&opts.OutputFile, "o", "", "Write output to file instead of stdout")
	fs.BoolVar(&opts.Verbose, "verbose", false, "Enable verbose logging to stderr for debugging")
	fs.BoolVar(&showVersion, "version", false, "Print tlscheck version and exit")
	fs.BoolVar(&showVersion, "v", false, "Print tlscheck version and exit")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s [options]\n\n", fs.Name())
		fmt.Fprintln(fs.Output(), "Options:")
		fmt.Fprintf(fs.Output(), "  --proxy-server string\n\tTeleport proxy public address (DNS name)\n")
		fmt.Fprintf(fs.Output(), "  --repeat int\n\tAttempts per SNI/ALPN/IP combination (default 1)\n")
		fmt.Fprintf(fs.Output(), "  --services string\n\t%s\n", servicesHelp)
		fmt.Fprintf(fs.Output(), "  --ip-addresses string\n\tComma-separated list of IP addresses to use instead of DNS resolution\n")
		fmt.Fprintf(fs.Output(), "  -H / --header \"Name: Value\"\n\tAdd an extra HTTP header. May be repeated. Use @filename to load from file.\n\tEach probe runs both with and without these headers.\n")
		fmt.Fprintf(fs.Output(), "  --use-profile-credentials\n\tLoad and use client certificates from tsh profile for mutual TLS probes (default: false)\n")
		fmt.Fprintf(fs.Output(), "  --output-format string\n\tOutput format: html (default) or json\n")
		fmt.Fprintf(fs.Output(), "  -o, --output string\n\tWrite output to file instead of stdout (format auto-detected from extension)\n")
		fmt.Fprintf(fs.Output(), "  --verbose\n\tEnable verbose logging to stderr for debugging\n")
		fmt.Fprintf(fs.Output(), "  -v, --version\n\tPrint tlscheck version and exit\n")
	}
	usage = fs.Usage

	if err := fs.Parse(args); err != nil {
		return Options{}, false, err
	}

	// Track whether --output-format was explicitly set (for extension-based auto-detection)
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "output-format" {
			opts.OutputFormatExplicit = true
		}
	})

	if opts.Repeat <= 0 {
		return Options{}, false, fmt.Errorf("repeat must be positive (got %d)", opts.Repeat)
	}

	// Validate output format
	opts.OutputFormat = strings.ToLower(strings.TrimSpace(opts.OutputFormat))
	if opts.OutputFormat != OutputFormatJSON && opts.OutputFormat != OutputFormatHTML {
		return Options{}, false, fmt.Errorf("output-format must be %q or %q (got %q)", OutputFormatJSON, OutputFormatHTML, opts.OutputFormat)
	}

	services = strings.TrimSpace(services)
	if services != "" && !strings.EqualFold(services, "all") {
		opts.ServiceFilter = splitCSV(services)
	}

	ipAddresses = strings.TrimSpace(ipAddresses)
	if ipAddresses != "" {
		opts.IPAddresses = splitList(ipAddresses, false)
	}

	if len(headerFlagVal.headers) > 0 {
		opts.ExtraHeaders = headerFlagVal.headers
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

// RedactHeaders returns a copy of the header map with sensitive values replaced
// by "[REDACTED]". Headers considered sensitive: Authorization, Proxy-Authorization,
// Cookie, Set-Cookie, and any key containing "token" or "secret" (case-insensitive).
func RedactHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return headers
	}
	redacted := make(map[string]string, len(headers))
	for k, v := range headers {
		lower := strings.ToLower(k)
		if lower == "authorization" || lower == "proxy-authorization" ||
			lower == "cookie" || lower == "set-cookie" ||
			strings.Contains(lower, "token") || strings.Contains(lower, "secret") {
			redacted[k] = "[REDACTED]"
		} else {
			redacted[k] = v
		}
	}
	return redacted
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
