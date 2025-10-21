package config

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	} else if resolved.PublicAddr == "" {
		if errors.Is(profileErr, discovery.ErrNoActiveProfile) {
			return Options{}, ErrProxyServerRequired
		}
		return Options{}, fmt.Errorf("failed to load Teleport profile: %w", profileErr)
	}

	if resolved.PublicAddr == "" {
		return Options{}, ErrProxyServerRequired
	}

	if host, _, err := net.SplitHostPort(resolved.PublicAddr); err == nil {
		resolved.PublicAddr = host
	}

	pingAddr := resolved.PublicAddr
	if profileErr == nil && profile.WebProxyAddr != "" {
		pingAddr = profile.WebProxyAddr
	}
	if strings.Contains(opts.PublicAddr, ":") {
		pingAddr = opts.PublicAddr
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

	return resolved, nil
}
