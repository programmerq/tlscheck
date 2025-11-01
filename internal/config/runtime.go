package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/programmerq/tlscheck/internal/discovery"
)

// ErrProxyServerRequired indicates that no proxy address could be discovered automatically.
var ErrProxyServerRequired = errors.New("proxy server address required")

// ResolveRuntime fills derived fields by consulting local profiles and the remote Teleport proxy.
func ResolveRuntime(ctx context.Context, opts Options) (Options, error) {
	resolved := opts

	home := discovery.DefaultTeleportHome()
	profile, profileErr := discovery.LoadActiveProfile(home)
	if profileErr == nil {
		if resolved.PublicAddr == "" {
			resolved.PublicAddr = profile.PublicAddr
		}
		resolved.ProfileSource = &ProfileInfo{Name: profile.Name, Path: profile.Path}

		// Try to load the client certificate for this profile
		if clientCert := discovery.LoadClientCert(home, profile.Name); clientCert != nil {
			resolved.ClientCertPEM = clientCert.CertPEM
			resolved.ClientKeyPEM = clientCert.KeyPEM
		}
	} else if resolved.PublicAddr == "" {
		if errors.Is(profileErr, discovery.ErrNoActiveProfile) {
			return Options{}, ErrProxyServerRequired
		}
		return Options{}, fmt.Errorf("failed to load Teleport profile: %w", profileErr)
	}

	if resolved.PublicAddr == "" {
		return Options{}, ErrProxyServerRequired
	}

	if host, port := parseHostAndPort(resolved.PublicAddr); host != "" {
		resolved.PublicAddr = host
		if port > 0 {
			resolved.WebProxyPort = port
		}
	}

	pingAddr := resolved.PublicAddr
	if profileErr == nil && profile.WebProxyAddr != "" {
		pingAddr = profile.WebProxyAddr
		if host, port := parseHostAndPort(profile.WebProxyAddr); host != "" {
			if port > 0 {
				resolved.WebProxyPort = port
			}
		}
	}
	if opts.PublicAddr != "" {
		pingAddr = opts.PublicAddr
		if host, port := parseHostAndPort(opts.PublicAddr); host != "" {
			resolved.PublicAddr = host
			if port > 0 {
				resolved.WebProxyPort = port
			}
		}
	}

	info, err := discovery.FetchClusterInfo(ctx, pingAddr, discovery.ProxySettings{
		HTTPSProxy: resolved.Proxy.HTTPSProxy,
		HTTPProxy:  resolved.Proxy.HTTPProxy,
	})
	if err != nil {
		return Options{}, fmt.Errorf("failed to fetch cluster info: %w", err)
	}

	resolved.ClusterName = info.ClusterName
	resolved.TeleportVersion = info.ServerVersion
	resolved.TLSRoutingEnabled = info.Proxy.TLSRoutingEnabled

	if host, port := parseHostAndPort(info.Proxy.WebProxyPublicAddr); host != "" {
		resolved.PublicAddr = host
		if port > 0 {
			resolved.WebProxyPort = port
		}
	}

	if resolved.WebProxyPort == 0 {
		resolved.WebProxyPort = 443
	}

	var hostCAEndpoints []string
	if info.Proxy.WebProxyPublicAddr != "" {
		hostCAEndpoints = append(hostCAEndpoints, info.Proxy.WebProxyPublicAddr)
	}
	if resolved.PublicAddr != "" {
		host := resolved.PublicAddr
		if resolved.WebProxyPort > 0 {
			host = net.JoinHostPort(host, strconv.Itoa(resolved.WebProxyPort))
		}
		hostCAEndpoints = append(hostCAEndpoints, host)
	}
	if pingAddr != "" {
		hostCAEndpoints = append(hostCAEndpoints, pingAddr)
	}

	var bundle []byte
	var fetchErr error
	tried := make(map[string]struct{})
	for _, endpoint := range hostCAEndpoints {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			continue
		}
		if _, seen := tried[endpoint]; seen {
			continue
		}
		tried[endpoint] = struct{}{}

		bundle, fetchErr = discovery.FetchHostCAs(ctx, endpoint, discovery.ProxySettings{
			HTTPSProxy: resolved.Proxy.HTTPSProxy,
			HTTPProxy:  resolved.Proxy.HTTPProxy,
		})
		if fetchErr == nil {
			resolved.HostCAPEM = bundle
			break
		}
	}

	if len(resolved.HostCAPEM) == 0 {
		if fetchErr == nil {
			fetchErr = fmt.Errorf("host CA bundle unavailable")
		}
		return Options{}, fmt.Errorf("failed to fetch host CA bundle: %w", fetchErr)
	}

	return resolved, nil
}

func parseHostAndPort(value string) (string, int) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0
	}

	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil {
			host := parsed.Hostname()
			portStr := parsed.Port()
			port := atoi(portStr)
			return host, port
		}
	}

	host, portStr, err := net.SplitHostPort(value)
	if err != nil {
		return value, 0
	}
	return host, atoi(portStr)
}

func atoi(s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}
