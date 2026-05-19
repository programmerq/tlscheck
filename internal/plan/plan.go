package plan

import (
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/programmerq/tlscheck/internal/config"
	"github.com/programmerq/tlscheck/internal/log"
	"github.com/programmerq/tlscheck/internal/sliceutil"
)

// Plan captures the probe blueprint derived from CLI inputs.
type Plan struct {
	GeneratedAt        time.Time        `json:"generated_at" jsonschema:"description=Timestamp when this probe plan was generated (UTC)"`
	Options            config.Options   `json:"options" jsonschema:"description=Configuration options that were used to generate this plan"`
	VersionBand        string           `json:"version_band" jsonschema:"description=Teleport version category (e.g. v18+, v15-v17) used to determine upgrade sequence behavior"`
	Base16ClusterName  string           `json:"base16_cluster_name" jsonschema:"description=Hexadecimal-encoded cluster name used in SNI for some Teleport services"`
	DefaultUpgradePath []UpgradeAttempt `json:"default_upgrade_path" jsonschema:"description=Default HTTP upgrade header sequence to use for connection upgrade attempts"`
	Targets            []ProbeTarget    `json:"targets" jsonschema:"description=List of all probe targets to execute, each representing a unique (service, port, SNI, ALPN) combination"`
}

// ProbeTarget represents a specific (port, SNI, ALPN) combination to execute.
type ProbeTarget struct {
	ServiceKey        string            `json:"service_key" jsonschema:"description=Identifier for the Teleport service being probed (e.g. proxy_web, proxy_ssh, kubernetes)"`
	DisplayName       string            `json:"display_name" jsonschema:"description=Human-readable name for the service being probed"`
	Address           string            `json:"address" jsonschema:"description=DNS name or IP address to connect to"`
	DNSResolvedIPs    []string          `json:"dns_resolved_ips,omitempty" jsonschema:"description=IP addresses resolved from DNS for this target (in order returned by resolver)"`
	OverrideIPs       []string          `json:"override_ips,omitempty" jsonschema:"description=User-specified IP addresses to use instead of DNS resolution"`
	Port              int               `json:"port" jsonschema:"description=TCP port number to connect to"`
	PrimarySNI        string            `json:"primary_sni" jsonschema:"description=Server Name Indication (SNI) value to use in the TLS handshake"`
	AdditionalSNIs    []string          `json:"additional_snis,omitempty" jsonschema:"description=Alternative SNI values to try if primary fails"`
	ALPNs             []string          `json:"alpns" jsonschema:"description=Application-Layer Protocol Negotiation (ALPN) protocols to request (e.g. h2, http/1.1, teleport-proxy-ssh)"`
	UpgradeSequence   []UpgradeAttempt  `json:"upgrade_sequence" jsonschema:"description=HTTP upgrade header sequence to use for this target"`
	Trust             TrustStrategy     `json:"trust" jsonschema:"description=Certificate trust strategy: system (OS cert store) or host_ca (Teleport host CA bundle)"`
	InformationalOnly bool              `json:"informational_only,omitempty" jsonschema:"description=When true, failures for this target are informational and not critical (used when TLS routing is disabled)"`
	Repeat            int               `json:"repeat" jsonschema:"description=Number of times to probe this target"`
	Notes             []string          `json:"notes,omitempty" jsonschema:"description=Human-readable notes about this probe target's purpose or expected behavior"`
	UseClientCert     *bool             `json:"use_client_cert,omitempty" jsonschema:"description=Whether to use client certificate for mutual TLS authentication"`
	UseProxy          bool              `json:"use_proxy,omitempty" jsonschema:"description=Whether to use HTTP/HTTPS proxy for this connection"`
	ProxyURL          string            `json:"proxy_url,omitempty" jsonschema:"description=Proxy URL to use if use_proxy is true"`
	ExtraHeaders      map[string]string `json:"extra_headers,omitempty" jsonschema:"description=Extra HTTP headers to include when connecting to this target (e.g. Authorization for auth-gated proxies)"`
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
	Token string `json:"token" jsonschema:"description=Upgrade token to send in the Upgrade HTTP header (e.g. websocket, alpn)"`
	Path  string `json:"path" jsonschema:"description=HTTP path to request for the upgrade attempt (e.g. /webapi/connectionupgrade)"`
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

	hasClientCert := opts.ClientCert != nil

	for _, tmpl := range serviceTemplates {
		if filtering {
			if _, ok := tmplFilter[tmpl.Key]; !ok {
				continue
			}
			delete(tmplFilter, tmpl.Key)
		}

		targets := tmpl.instantiate(opts, base16Name, seq, hasClientCert)
		plan.Targets = append(plan.Targets, targets...)
	}

	if len(tmplFilter) > 0 {
		remaining := make([]string, 0, len(tmplFilter))
		for key := range tmplFilter {
			remaining = append(remaining, key)
		}
		return Plan{}, fmt.Errorf("unknown services requested: %s", strings.Join(remaining, ", "))
	}

	// Resolve DNS for all targets before proxy duplication
	log.Printf("resolving DNS for %d targets", len(plan.Targets))
	for i := range plan.Targets {
		resolveDNSForTarget(&plan.Targets[i])
	}

	// If a proxy is configured, duplicate all targets to test both with and without proxy
	proxyURL := determineProxyURL(opts.Proxy)
	if proxyURL != "" {
		log.Printf("proxy configured: %s - duplicating targets for proxy and direct connections", log.SanitizeURL(proxyURL))
		originalTargets := plan.Targets
		plan.Targets = make([]ProbeTarget, 0, len(originalTargets)*2)

		for _, target := range originalTargets {
			// First, add the target with proxy
			withProxy := target
			withProxy.UseProxy = true
			withProxy.ProxyURL = proxyURL
			withProxy.Notes = append(sliceutil.CloneStrings(withProxy.Notes), "Using proxy: "+proxyURL)
			plan.Targets = append(plan.Targets, withProxy)

			// Then, add the target without proxy
			withoutProxy := target
			withoutProxy.UseProxy = false
			withoutProxy.Notes = append(sliceutil.CloneStrings(withoutProxy.Notes), "Direct connection (bypassing proxy)")
			plan.Targets = append(plan.Targets, withoutProxy)
		}
	}

	// If extra headers are configured, duplicate all targets to test both with and without headers.
	if len(opts.ExtraHeaders) > 0 {
		headerNames := joinMapKeys(opts.ExtraHeaders)
		log.Printf("extra headers configured (%s) - duplicating targets for with and without headers", headerNames)
		originalTargets := plan.Targets
		plan.Targets = make([]ProbeTarget, 0, len(originalTargets)*2)

		for _, target := range originalTargets {
			// First, add the target without extra headers (baseline)
			withoutHeaders := deepCopyProbeTarget(target)
			withoutHeaders.Notes = append(withoutHeaders.Notes, "Without extra headers")
			plan.Targets = append(plan.Targets, withoutHeaders)

			// Then, add the target with extra headers
			withHeaders := deepCopyProbeTarget(target)
			withHeaders.ExtraHeaders = cloneMap(opts.ExtraHeaders)
			withHeaders.Notes = append(withHeaders.Notes, "With extra headers: "+headerNames)
			plan.Targets = append(plan.Targets, withHeaders)
		}
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
	UseClientCert bool
}

func (t serviceTemplate) instantiate(opts config.Options, base16Name string, seq []UpgradeAttempt, hasClientCert bool) []ProbeTarget {
	alpns := t.ALPNs(opts, base16Name)
	primarySNI, additionalSNIs := t.SNIs(opts, base16Name)

	ports := t.Ports(opts)
	if len(ports) == 0 {
		return nil
	}

	trust := t.Trust
	if trust == "" {
		trust = TrustSystemRoots
	}

	// If this service supports client certs and we have one, generate both with and without
	needsDualTargets := t.UseClientCert && hasClientCert

	var targets []ProbeTarget
	if needsDualTargets {
		// Double capacity for both with and without client cert
		targets = make([]ProbeTarget, 0, len(ports)*2)
	} else {
		targets = make([]ProbeTarget, 0, len(ports))
	}

	for _, port := range ports {
		// Create base target configuration
		baseTarget := ProbeTarget{
			ServiceKey:     t.Key,
			DisplayName:    t.DisplayName,
			Address:        opts.PublicAddr,
			OverrideIPs:    sliceutil.CloneStrings(opts.IPAddresses),
			Port:           port,
			PrimarySNI:     primarySNI,
			AdditionalSNIs: sliceutil.CloneStrings(additionalSNIs),
			ALPNs:          sliceutil.CloneStrings(alpns),
			Trust:          trust,
			Repeat:         opts.Repeat,
			Notes:          sliceutil.CloneStrings(t.Notes),
		}

		if t.NeedsUpgrade {
			baseTarget.UpgradeSequence = cloneUpgrades(seq)
		}

		if t.Informational != nil && t.Informational(opts) {
			baseTarget.InformationalOnly = true
			baseTarget.Notes = append(baseTarget.Notes, "TLS routing disabled; treating probe outcome as informational only.")
		}

		if needsDualTargets {
			// First, add target WITH client cert
			withCert := deepCopyProbeTarget(baseTarget)
			trueVal := true
			withCert.UseClientCert = &trueVal
			withCert.Notes = append(withCert.Notes, "Using client certificate for mutual TLS")
			targets = append(targets, withCert)

			// Then, add target WITHOUT client cert
			withoutCert := deepCopyProbeTarget(baseTarget)
			falseVal := false
			withoutCert.UseClientCert = &falseVal
			withoutCert.Notes = append(withoutCert.Notes, "No client certificate (server-only TLS)")
			targets = append(targets, withoutCert)
		} else {
			// Only add one target
			// If we have a client cert, explicitly set the value (true or false)
			// If we don't have a client cert, leave it nil (omitted from JSON)
			if hasClientCert {
				useClientCert := t.UseClientCert
				baseTarget.UseClientCert = &useClientCert
			}
			// else: UseClientCert remains nil and will be omitted from JSON
			targets = append(targets, baseTarget)
		}
	}

	// Some services implicitly need to record the base16 cluster hint.
	if t.Base16Hint && len(targets) > 0 && base16Name != "" {
		targets[0].Notes = append(targets[0].Notes,
			fmt.Sprintf("Uses base16-encoded cluster name in SNI: %s", base16Name))
	}

	return targets
}

func cloneUpgrades(input []UpgradeAttempt) []UpgradeAttempt {
	if len(input) == 0 {
		return nil
	}
	out := make([]UpgradeAttempt, len(input))
	copy(out, input)
	return out
}

func cloneMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}

// deepCopyProbeTarget creates a deep copy of a ProbeTarget, cloning all slice fields.
func deepCopyProbeTarget(src ProbeTarget) ProbeTarget {
	dst := src
	dst.DNSResolvedIPs = sliceutil.CloneStrings(src.DNSResolvedIPs)
	dst.OverrideIPs = sliceutil.CloneStrings(src.OverrideIPs)
	dst.AdditionalSNIs = sliceutil.CloneStrings(src.AdditionalSNIs)
	dst.ALPNs = sliceutil.CloneStrings(src.ALPNs)
	dst.UpgradeSequence = cloneUpgrades(src.UpgradeSequence)
	dst.Notes = sliceutil.CloneStrings(src.Notes)
	dst.ExtraHeaders = cloneMap(src.ExtraHeaders)
	return dst
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
		UseClientCert: true,
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
		UseClientCert: true,
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
	dbTemplate("db_postgres", "Database listener (Postgres)"),
	dbTemplate("db_mysql", "Database listener (MySQL)"),
	dbTemplate("db_mongodb", "Database listener (MongoDB)"),
	dbTemplate("db_redis", "Database listener (Redis)"),
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

func dbTemplate(key, displayName string) serviceTemplate {
	return serviceTemplate{
		Key:         key,
		DisplayName: displayName,
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
	}
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
	case major >= 16, major == 15 && minor >= 1:
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

// determineProxyURL selects the appropriate proxy URL from the proxy settings.
// HTTPS_PROXY is preferred for TLS connections, falling back to HTTP_PROXY.
func determineProxyURL(proxy config.ProxySettings) string {
	if proxy.HTTPSProxy != "" {
		return proxy.HTTPSProxy
	}
	if proxy.HTTPProxy != "" {
		return proxy.HTTPProxy
	}
	return ""
}

// resolveDNSForTarget resolves DNS for a target's address and populates DNSResolvedIPs.
// It preserves the order returned by the resolver.
func resolveDNSForTarget(target *ProbeTarget) {
	if target == nil {
		return
	}

	// Skip DNS resolution if we have override IPs
	if len(target.OverrideIPs) > 0 {
		log.Printf("DNS resolution skipped for %s (using override IPs: %v)", target.Address, target.OverrideIPs)
		return
	}

	// Try to resolve the address
	log.Printf("resolving DNS for %s", target.Address)
	resolved, err := net.LookupIP(target.Address)
	if err != nil || len(resolved) == 0 {
		if err != nil {
			log.Printf("DNS resolution failed for %s: %v", target.Address, err)
		} else {
			log.Printf("DNS resolution returned no IPs for %s", target.Address)
		}
		return
	}

	// Preserve the order of IPs returned by the resolver
	dnsIPs := make([]string, 0, len(resolved))
	for _, ip := range resolved {
		dnsIPs = append(dnsIPs, ip.String())
	}
	target.DNSResolvedIPs = dnsIPs
	log.Printf("resolved %s to %d IP(s): %v", target.Address, len(dnsIPs), dnsIPs)
}

// joinMapKeys returns a sorted, comma-separated list of the map's keys.
func joinMapKeys(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}
