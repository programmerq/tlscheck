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
	ServiceKey      string           `json:"service_key"`
	DisplayName     string           `json:"display_name"`
	Address         string           `json:"address"`
	Port            int              `json:"port"`
	PrimarySNI      string           `json:"primary_sni"`
	AdditionalSNIs  []string         `json:"additional_snis,omitempty"`
	ALPNs           []string         `json:"alpns"`
	UpgradeSequence []UpgradeAttempt `json:"upgrade_sequence"`
	Repeat          int              `json:"repeat"`
	Notes           []string         `json:"notes,omitempty"`
}

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

	for _, tmpl := range serviceTemplates {
		if filtering {
			if _, ok := tmplFilter[tmpl.Key]; !ok {
				continue
			}
			delete(tmplFilter, tmpl.Key)
		}

		targets := tmpl.instantiate(opts, base16Name, seq)
		plan.Targets = append(plan.Targets, targets...)
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
	Key          string
	DisplayName  string
	Ports        []int
	ALPNs        func(config.Options) []string
	SNIs         func(config.Options) (string, []string)
	Notes        []string
	NeedsUpgrade bool
	Base16Hint   bool
}

func (t serviceTemplate) instantiate(opts config.Options, base16Name string, seq []UpgradeAttempt) []ProbeTarget {
	alpns := t.ALPNs(opts)
	primarySNI, additionalSNIs := t.SNIs(opts)

	targets := make([]ProbeTarget, 0, len(t.Ports))
	for _, port := range t.Ports {
		target := ProbeTarget{
			ServiceKey:     t.Key,
			DisplayName:    t.DisplayName,
			Address:        opts.PublicAddr,
			Port:           port,
			PrimarySNI:     primarySNI,
			AdditionalSNIs: cloneSlice(additionalSNIs),
			ALPNs:          cloneSlice(alpns),
			Repeat:         opts.Repeat,
			Notes:          cloneSlice(t.Notes),
		}

		if t.NeedsUpgrade {
			target.UpgradeSequence = cloneUpgrades(seq)
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
		Ports:       []int{3080, 443},
		ALPNs: func(config.Options) []string {
			return []string{"h2", "http/1.1"}
		},
		SNIs: func(opts config.Options) (string, []string) {
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
		Ports:       []int{3024},
		ALPNs: func(config.Options) []string {
			return []string{"teleport-reversetunnel"}
		},
		SNIs: func(opts config.Options) (string, []string) {
			return opts.PublicAddr, nil
		},
		Notes: []string{
			"Probe direct IPs returned for the proxy host as well",
		},
		NeedsUpgrade: true,
		Base16Hint:   true,
	},
	{
		Key:         "proxy_ssh",
		DisplayName: "Proxy SSH",
		Ports:       []int{3023},
		ALPNs: func(config.Options) []string {
			return []string{"teleport-proxy-ssh"}
		},
		SNIs: func(opts config.Options) (string, []string) {
			return opts.PublicAddr, nil
		},
		Notes: []string{
			"Include base16 cluster SNI when dialing resolved IPs",
		},
		NeedsUpgrade: true,
		Base16Hint:   true,
	},
	{
		Key:         "proxy_ssh_grpc",
		DisplayName: "Proxy SSH gRPC",
		Ports:       []int{3023},
		ALPNs: func(config.Options) []string {
			return []string{"teleport-proxy-ssh-grpc"}
		},
		SNIs: func(opts config.Options) (string, []string) {
			return opts.PublicAddr, nil
		},
		NeedsUpgrade: true,
	},
	{
		Key:         "auth_via_proxy",
		DisplayName: "Auth via proxy",
		Ports:       []int{3025},
		ALPNs: func(opts config.Options) []string {
			return []string{fmt.Sprintf("teleport-auth@%s", opts.ClusterName)}
		},
		SNIs: func(opts config.Options) (string, []string) {
			return opts.PublicAddr, nil
		},
		Notes: []string{
			"Expect Host CA issued leaf cert with auth identity",
		},
		NeedsUpgrade: true,
	},
	{
		Key:         "kubernetes",
		DisplayName: "Kubernetes API via proxy",
		Ports:       []int{3026},
		ALPNs: func(config.Options) []string {
			return []string{"h2", "http/1.1"}
		},
		SNIs: func(opts config.Options) (string, []string) {
			return fmt.Sprintf("kube-teleport-proxy-alpn.%s", opts.ClusterName), []string{opts.PublicAddr}
		},
		NeedsUpgrade: true,
	},
	{
		Key:         "db_postgres",
		DisplayName: "Database listener (Postgres)",
		Ports:       []int{5432},
		ALPNs: func(config.Options) []string {
			return nil
		},
		SNIs: func(opts config.Options) (string, []string) {
			return opts.PublicAddr, nil
		},
		Notes: []string{
			"ALPN negotiated by tsh db proxy; harness verifies upstream reachability",
		},
		NeedsUpgrade: true,
	},
	{
		Key:         "db_mysql",
		DisplayName: "Database listener (MySQL)",
		Ports:       []int{3036},
		ALPNs: func(config.Options) []string {
			return nil
		},
		SNIs: func(opts config.Options) (string, []string) {
			return opts.PublicAddr, nil
		},
		Notes: []string{
			"ALPN negotiated by tsh db proxy; harness verifies upstream reachability",
		},
		NeedsUpgrade: true,
	},
	{
		Key:         "db_mongodb",
		DisplayName: "Database listener (MongoDB)",
		Ports:       []int{27017},
		ALPNs: func(config.Options) []string {
			return nil
		},
		SNIs: func(opts config.Options) (string, []string) {
			return opts.PublicAddr, nil
		},
		Notes: []string{
			"ALPN negotiated by tsh db proxy; harness verifies upstream reachability",
		},
		NeedsUpgrade: true,
	},
	{
		Key:         "db_redis",
		DisplayName: "Database listener (Redis)",
		Ports:       []int{6379},
		ALPNs: func(config.Options) []string {
			return nil
		},
		SNIs: func(opts config.Options) (string, []string) {
			return opts.PublicAddr, nil
		},
		Notes: []string{
			"ALPN negotiated by tsh db proxy; harness verifies upstream reachability",
		},
		NeedsUpgrade: true,
	},
	{
		Key:         "app_access",
		DisplayName: "App Access",
		Ports:       []int{3080, 443},
		ALPNs: func(config.Options) []string {
			return []string{"h2", "http/1.1"}
		},
		SNIs: func(opts config.Options) (string, []string) {
			return opts.PublicAddr, nil
		},
		NeedsUpgrade: true,
	},
	{
		Key:         "desktop_access",
		DisplayName: "Desktop Access",
		Ports:       []int{3080, 443},
		ALPNs: func(config.Options) []string {
			return []string{"h2", "http/1.1"}
		},
		SNIs: func(opts config.Options) (string, []string) {
			return opts.PublicAddr, nil
		},
		Notes: []string{
			"Desktop Access uses gRPC over HTTP/2",
		},
		NeedsUpgrade: true,
	},
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
