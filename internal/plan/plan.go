package plan

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/programmerq/tlscheck/internal/config"
)

// Plan captures the probe blueprint derived from CLI inputs.
type Plan struct {
	GeneratedAt        time.Time        `json:"generated_at"`
	Options            config.Options   `json:"options"`
	VersionBand        string           `json:"version_band"`
	Base16ClusterName  string           `json:"base16_cluster_name"`
	DefaultUpgradePath []UpgradeAttempt `json:"default_upgrade_path"`
	Targets            []ProbeTarget    `json:"targets"`
}

// ProbeTarget represents a specific (port, SNI, ALPN) combination to execute.
type ProbeTarget struct {
	ServiceKey        string           `json:"service_key"`
	DisplayName       string           `json:"display_name"`
	Address           string           `json:"address"`
	DNSResolvedIPs    []string         `json:"dns_resolved_ips,omitempty"`
	OverrideIPs       []string         `json:"override_ips,omitempty"`
	Port              int              `json:"port"`
	PrimarySNI        string           `json:"primary_sni"`
	AdditionalSNIs    []string         `json:"additional_snis,omitempty"`
	ALPNs             []string         `json:"alpns"`
	UpgradeSequence   []UpgradeAttempt `json:"upgrade_sequence"`
	Trust             TrustStrategy    `json:"trust"`
	InformationalOnly bool             `json:"informational_only,omitempty"`
	Repeat            int              `json:"repeat"`
	Notes             []string         `json:"notes,omitempty"`
	UseProxy          bool             `json:"use_proxy"`
	UseClientCert     bool             `json:"use_client_cert,omitempty"`
}

// TrustStrategy describes which certificate authorities should be trusted for a probe target.
type TrustStrategy string

const (
	// TrustSystemRoots relies on the operating system certificate store.
	TrustSystemRoots TrustStrategy = "system"
	// TrustHostCA relies on the Teleport host CA bundle discovered at runtime.
	TrustHostCA TrustStrategy = "host_ca"
)

// UpgradeAttempt documents the sequence of Upgrade headers to send behind L7 load balancers.
type UpgradeAttempt struct {
	Token string `json:"token"`
	Path  string `json:"path"`
}

const upgradeEndpoint = "/webapi/connectionupgrade"

// Build assembles a probe plan according to user options and version defaults.
func Build(opts config.Options) (Plan, error) {
	seq := determineUpgradeSequence(opts.TeleportVersion)
	versionBand := describeVersionBand(opts.TeleportVersion)
	base16Name := strings.ToLower(hex.EncodeToString([]byte(opts.ClusterName)))

	tmplFilter := map[string]struct{}{}
	filtering := len(opts.ServiceFilter) > 0
	if filtering {
		for _, key := range makeUnique(opts.ServiceFilter) {
			tmplFilter[key] = struct{}{}
		}
	}

	plan := Plan{
		GeneratedAt:        time.Now().UTC(),
		Options:            opts,
		VersionBand:        versionBand,
		Base16ClusterName:  base16Name,
		DefaultUpgradePath: seq,
	}

	// Determine if proxy is configured
	proxyConfigured := opts.Proxy.HTTPSProxy != "" || opts.Proxy.HTTPProxy != ""

	for _, tmpl := range serviceTemplates {
		if filtering {
			if _, ok := tmplFilter[tmpl.Key]; !ok {
				continue
			}
			delete(tmplFilter, tmpl.Key)
		}

		targets := tmpl.instantiate(opts, base16Name, seq)

		// If proxy is configured, duplicate targets: one with proxy, one without
		if proxyConfigured {
			for _, target := range targets {
				// Add target with proxy
				withProxy := target
				withProxy.UseProxy = true
				withProxy.Notes = append(cloneSlice(withProxy.Notes), "probe using configured proxy")
				plan.Targets = append(plan.Targets, withProxy)

				// Add target without proxy
				withoutProxy := target
				withoutProxy.UseProxy = false
				withoutProxy.Notes = append(cloneSlice(withoutProxy.Notes), "probe bypassing proxy (direct connection)")
				plan.Targets = append(plan.Targets, withoutProxy)
			}
		} else {
			// No proxy configured, add targets as-is
			plan.Targets = append(plan.Targets, targets...)
		}
	}

	if len(tmplFilter) > 0 {
		remaining := make([]string, 0, len(tmplFilter))
		for key := range tmplFilter {
			remaining = append(remaining, key)
		}
		return Plan{}, fmt.Errorf("unknown services requested: %s", strings.Join(remaining, ", "))
	}

	return plan, nil
}

type serviceTemplate struct {
	Key           string
	DisplayName   string
	Ports         func(config.Options) []int
	ALPNs         func(config.Options, string) []string
	SNIs          func(config.Options, string) (string, []string)
	Notes         []string
	NeedsUpgrade  bool
	Base16Hint    bool
	Informational func(config.Options) bool
	Trust         TrustStrategy
}

func (t serviceTemplate) instantiate(opts config.Options, base16Name string, seq []UpgradeAttempt) []ProbeTarget {
	alpns := t.ALPNs(opts, base16Name)
	primarySNI, additionalSNIs := t.SNIs(opts, base16Name)

	ports := t.Ports(opts)
	if len(ports) == 0 {
		return nil
	}

	targets := make([]ProbeTarget, 0, len(ports))
	trust := t.Trust
	if trust == "" {
		trust = TrustSystemRoots
	}
	for _, port := range ports {
		target := ProbeTarget{
			ServiceKey:     t.Key,
			DisplayName:    t.DisplayName,
			Address:        opts.PublicAddr,
			OverrideIPs:    cloneSlice(opts.IPAddresses),
			Port:           port,
			PrimarySNI:     primarySNI,
			AdditionalSNIs: cloneSlice(additionalSNIs),
			ALPNs:          cloneSlice(alpns),
			Trust:          trust,
			Repeat:         opts.Repeat,
			Notes:          cloneSlice(t.Notes),
		}

		if t.NeedsUpgrade {
			target.UpgradeSequence = cloneUpgrades(seq)
		}

		if t.Informational != nil && t.Informational(opts) {
			target.InformationalOnly = true
			target.Notes = append(target.Notes, "TLS routing disabled; treating probe outcome as informational only.")
		}

		targets = append(targets, target)
	}

	// Some services implicitly need to record the base16 cluster hint.
	if t.Base16Hint && len(targets) > 0 && base16Name != "" {
		targets[0].Notes = append(targets[0].Notes,
			fmt.Sprintf("base16 cluster name hint: %s", base16Name))
	}

	return targets
}

func cloneSlice(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	out := make([]string, len(input))
	copy(out, input)
	return out
}

func cloneUpgrades(input []UpgradeAttempt) []UpgradeAttempt {
	if len(input) == 0 {
		return nil
	}
	out := make([]UpgradeAttempt, len(input))
	copy(out, input)
	return out
}

var serviceTemplates = []serviceTemplate{
	{
		Key:         "proxy_web",
		DisplayName: "Proxy Web UI & HTTPS API",
		Ports:       webPortList,
		ALPNs: func(config.Options, string) []string {
			return []string{"h2", "http/1.1"}
		},
		SNIs: func(opts config.Options, _ string) (string, []string) {
			return opts.PublicAddr, nil
		},
		Notes: []string{
			"Hit /webapi/ping before attempting upgrade",
		},
		NeedsUpgrade: true,
	},
	{
		Key:         "reverse_tunnel",
		DisplayName: "Reverse tunnel entry",
		Ports:       webPortList,
		ALPNs: func(config.Options, string) []string {
			return []string{"teleport-reversetunnel"}
		},
		SNIs: func(opts config.Options, _ string) (string, []string) {
			return opts.PublicAddr, nil
		},
		Notes: []string{
			"Probe direct IPs returned for the proxy host as well",
		},
		Base16Hint:    true,
		Informational: informationalWhenSeparateListeners,
	},
	{
		Key:         "proxy_ssh",
		DisplayName: "Proxy SSH",
		Ports:       webPortList,
		ALPNs: func(config.Options, string) []string {
			return []string{"teleport-proxy-ssh"}
		},
		SNIs: func(opts config.Options, _ string) (string, []string) {
			return opts.PublicAddr, nil
		},
		Notes: []string{
			"Include base16 cluster SNI when dialing resolved IPs",
		},
		Base16Hint:    true,
		Informational: informationalWhenSeparateListeners,
		Trust:         TrustHostCA,
	},
	{
		Key:         "proxy_ssh_grpc",
		DisplayName: "Proxy SSH gRPC",
		Ports:       webPortList,
		ALPNs: func(config.Options, string) []string {
			return []string{"teleport-proxy-ssh-grpc"}
		},
		SNIs: func(opts config.Options, _ string) (string, []string) {
			return opts.PublicAddr, nil
		},
		Informational: informationalWhenSeparateListeners,
		Trust:         TrustHostCA,
	},
	{
		Key:         "auth_via_proxy",
		DisplayName: "Auth via proxy",
		Ports:       webPortList,
		ALPNs: func(opts config.Options, base16 string) []string {
			authALPN := makeAuthALPN(base16)
			if authALPN == "" {
				return []string{"h2"}
			}
			return []string{authALPN, "h2"}
		},
		SNIs: func(opts config.Options, base16 string) (string, []string) {
			authHost := makeBase16Host(base16)
			if authHost == "" {
				return opts.PublicAddr, nil
			}
			return authHost, nil
		},
		Notes: []string{
			"Expect Host CA issued leaf cert with auth identity",
		},
		Informational: informationalWhenSeparateListeners,
		Trust:         TrustHostCA,
	},
	{
		Key:         "kubernetes",
		DisplayName: "Kubernetes API via proxy",
		Ports:       webPortList,
		ALPNs: func(config.Options, string) []string {
			return []string{"h2", "http/1.1"}
		},
		SNIs: func(opts config.Options, _ string) (string, []string) {
			return fmt.Sprintf("kube-teleport-proxy-alpn.%s", opts.ClusterName), []string{opts.PublicAddr}
		},
		Informational: informationalWhenSeparateListeners,
		Trust:         TrustHostCA,
	},
	{
		Key:         "db_postgres",
		DisplayName: "Database listener (Postgres)",
		Ports:       webPortList,
		ALPNs: func(config.Options, string) []string {
			return nil
		},
		SNIs: func(opts config.Options, _ string) (string, []string) {
			return opts.PublicAddr, nil
		},
		Notes: []string{
			"ALPN negotiated by tsh db proxy; harness verifies upstream reachability",
		},
		Informational: informationalWhenSeparateListeners,
	},
	{
		Key:         "db_mysql",
		DisplayName: "Database listener (MySQL)",
		Ports:       webPortList,
		ALPNs: func(config.Options, string) []string {
			return nil
		},
		SNIs: func(opts config.Options, _ string) (string, []string) {
			return opts.PublicAddr, nil
		},
		Notes: []string{
			"ALPN negotiated by tsh db proxy; harness verifies upstream reachability",
		},
		Informational: informationalWhenSeparateListeners,
	},
	{
		Key:         "db_mongodb",
		DisplayName: "Database listener (MongoDB)",
		Ports:       webPortList,
		ALPNs: func(config.Options, string) []string {
			return nil
		},
		SNIs: func(opts config.Options, _ string) (string, []string) {
			return opts.PublicAddr, nil
		},
		Notes: []string{
			"ALPN negotiated by tsh db proxy; harness verifies upstream reachability",
		},
		Informational: informationalWhenSeparateListeners,
	},
	{
		Key:         "db_redis",
		DisplayName: "Database listener (Redis)",
		Ports:       webPortList,
		ALPNs: func(config.Options, string) []string {
			return nil
		},
		SNIs: func(opts config.Options, _ string) (string, []string) {
			return opts.PublicAddr, nil
		},
		Notes: []string{
			"ALPN negotiated by tsh db proxy; harness verifies upstream reachability",
		},
		Informational: informationalWhenSeparateListeners,
	},
	{
		Key:         "app_access",
		DisplayName: "App Access",
		Ports:       webPortList,
		ALPNs: func(config.Options, string) []string {
			return []string{"h2", "http/1.1"}
		},
		SNIs: func(opts config.Options, _ string) (string, []string) {
			return opts.PublicAddr, nil
		},
		Informational: informationalWhenSeparateListeners,
	},
	{
		Key:         "desktop_access",
		DisplayName: "Desktop Access",
		Ports:       webPortList,
		ALPNs: func(config.Options, string) []string {
			return []string{"h2", "http/1.1"}
		},
		SNIs: func(opts config.Options, _ string) (string, []string) {
			return opts.PublicAddr, nil
		},
		Notes: []string{
			"Desktop Access uses gRPC over HTTP/2",
		},
		Informational: informationalWhenSeparateListeners,
	},
}

func webPortList(opts config.Options) []int {
	port := opts.WebProxyPort
	if port <= 0 {
		port = 443
	}
	return []int{port}
}

func informationalWhenSeparateListeners(opts config.Options) bool {
	return !opts.TLSRoutingEnabled
}

func makeBase16Host(base16 string) string {
	base16 = strings.TrimSpace(base16)
	if base16 == "" {
		return ""
	}
	return fmt.Sprintf("%s.teleport.cluster.local", base16)
}

func makeAuthALPN(base16 string) string {
	base16 = strings.TrimSpace(base16)
	if base16 == "" {
		return ""
	}
	return fmt.Sprintf("teleport-auth@%s.teleport.cluster.local", base16)
}

// ServiceKeys returns the valid service identifiers that can be filtered via CLI flags.
func ServiceKeys() []string {
	keys := make([]string, 0, len(serviceTemplates))
	for _, tmpl := range serviceTemplates {
		keys = append(keys, tmpl.Key)
	}
	return keys
}

func determineUpgradeSequence(version string) []UpgradeAttempt {
	major, minor := parseVersion(version)

	switch {
	case major >= 18:
		return []UpgradeAttempt{{Token: "websocket", Path: upgradeEndpoint}}
	case major == 17:
		return []UpgradeAttempt{
			{Token: "websocket", Path: upgradeEndpoint},
			{Token: "alpn", Path: upgradeEndpoint},
			{Token: "alpn-ping", Path: upgradeEndpoint},
		}
	case major == 16:
		fallthrough
	case major == 15 && minor >= 1:
		return []UpgradeAttempt{
			{Token: "websocket", Path: upgradeEndpoint},
			{Token: "alpn", Path: upgradeEndpoint},
			{Token: "alpn-ping", Path: upgradeEndpoint},
		}
	default:
		return []UpgradeAttempt{
			{Token: "alpn", Path: upgradeEndpoint},
			{Token: "alpn-ping", Path: upgradeEndpoint},
		}
	}
}

func describeVersionBand(version string) string {
	major, _ := parseVersion(version)
	switch {
	case major >= 18:
		return "v18+"
	case major >= 15:
		return "v15–v17"
	default:
		return "pre-v15"
	}
}

func parseVersion(input string) (int, int) {
	trimmed := strings.TrimSpace(input)
	trimmed = strings.TrimPrefix(trimmed, "v")
	parts := strings.Split(trimmed, ".")

	major := atoi(parts, 0)
	minor := atoi(parts, 1)
	return major, minor
}

func atoi(parts []string, idx int) int {
	if idx >= len(parts) {
		return 0
	}
	value := parts[idx]
	if value == "" {
		return 0
	}
	n := 0
	for _, r := range value {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func makeUnique(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
