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
	PublicAddr      string        `json:"public_addr"`
	ClusterName     string        `json:"cluster_name"`
	TeleportVersion string        `json:"teleport_version"`
	Repeat          int           `json:"repeat"`
	ServiceFilter   []string      `json:"service_filter,omitempty"`
	Proxy           ProxySettings `json:"proxy"`
	ProfileSource   *ProfileInfo  `json:"profile_source,omitempty"`
}

// ProxySettings captures HTTP(S) proxy configuration sourced from the environment.
type ProxySettings struct {
	HTTPSProxy string `json:"https_proxy,omitempty"`
	HTTPProxy  string `json:"http_proxy,omitempty"`
	NoProxy    string `json:"no_proxy,omitempty"`
}

// ProfileInfo records the Teleport profile location used for automatic defaults.
type ProfileInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
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
	var showVersion bool

	fs.StringVar(&opts.PublicAddr, "proxy-server", "", "Teleport proxy public address (DNS name)")
	fs.IntVar(&opts.Repeat, "repeat", 1, "Attempts per SNI/ALPN/IP combination (default 1)")
	fs.StringVar(&services, "services", "all", servicesHelp)
	fs.BoolVar(&showVersion, "version", false, "Print tlscheck version and exit")
	fs.BoolVar(&showVersion, "v", false, "Print tlscheck version and exit")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s [options]\n\n", fs.Name())
		fmt.Fprintln(fs.Output(), "Options:")
		fmt.Fprintf(fs.Output(), "  --proxy-server string\n\tTeleport proxy public address (DNS name)\n")
		fmt.Fprintf(fs.Output(), "  --repeat int\n\tAttempts per SNI/ALPN/IP combination (default 1)\n")
		fmt.Fprintf(fs.Output(), "  --services string\n\t%s\n", servicesHelp)
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

	opts.Proxy = detectProxySettings()

	return opts, showVersion, nil
}

func splitCSV(value string) []string {
	raw := strings.Split(value, ",")
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out = append(out, strings.ToLower(v))
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
