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
	"github.com/programmerq/tlscheck/internal/log"
)

// ErrProxyServerRequired indicates that no proxy address could be discovered automatically.
var ErrProxyServerRequired = errors.New("proxy server address required")

// ResolveRuntime fills derived fields by consulting local profiles and the remote Teleport proxy.
func ResolveRuntime(ctx context.Context, opts Options) (Options, error) {
	resolved := opts

	home := discovery.DefaultTeleportHome()
	log.Printf("resolving runtime configuration from Teleport home: %s", home)
	profile, profileErr := discovery.LoadActiveProfile(home)
	if profileErr == nil {
		log.Printf("loaded profile: %s (user: %s)", profile.Name, profile.Username)
		if resolved.PublicAddr == "" {
			resolved.PublicAddr = profile.PublicAddr
			log.Printf("using proxy address from profile: %s", resolved.PublicAddr)
		}

		// Calculate expected client cert paths
		certPath, keyPath := discovery.GetClientCertPaths(home, profile.Name, profile.Username)

		// Initialize ProfileInfo with all available information
		resolved.ProfileSource = &ProfileInfo{
			Name:            profile.Name,
			Path:            profile.Path,
			Username:        profile.Username,
			ClientCertPath:  certPath,
			ClientKeyPath:   keyPath,
			ClientCertFound: false, // Will be set to true if cert is successfully loaded
		}

		// Try to load the client certificate for this profile
		if clientCert := discovery.LoadClientCert(home, profile.Name, profile.Username); clientCert != nil {
			log.Printf("loaded client certificate: %s", clientCert.Fingerprint)
			resolved.ProfileSource.ClientCertFound = true
			resolved.ClientCertPEM = clientCert.CertPEM
			resolved.ClientKeyPEM = clientCert.KeyPEM

			// Convert extensions to config package type
			extensions := make([]CertExtension, len(clientCert.Extensions))
			for i, ext := range clientCert.Extensions {
				extensions[i] = CertExtension{
					OID:      ext.OID,
					Critical: ext.Critical,
					Value:    ext.Value,
				}
			}

			resolved.ClientCert = &ClientCertInfo{
				CertPath:       clientCert.CertPath,
				KeyPath:        clientCert.KeyPath,
				Fingerprint:    clientCert.Fingerprint,
				Subject:        clientCert.Subject,
				Issuer:         clientCert.Issuer,
				NotBefore:      clientCert.NotBefore,
				NotAfter:       clientCert.NotAfter,
				SerialNumber:   clientCert.SerialNumber,
				SignatureAlgo:  clientCert.SignatureAlgo,
				PublicKeyAlgo:  clientCert.PublicKeyAlgo,
				KeyUsage:       clientCert.KeyUsage,
				ExtKeyUsage:    clientCert.ExtKeyUsage,
				DNSNames:       clientCert.DNSNames,
				EmailAddresses: clientCert.EmailAddresses,
				IPAddresses:    clientCert.IPAddresses,
				URIs:           clientCert.URIs,
				IsCA:           clientCert.IsCA,
				Extensions:     extensions,
			}
		}

		// Load extra headers from ~/.tsh/config.yaml and apply headers that
		// match the target proxy address.  Headers supplied via -H/--header
		// take precedence over those loaded from the config file.
		tshCfg, cfgErr := discovery.LoadTSHConfig(home)
		if cfgErr != nil {
			log.Printf("warning: could not load tsh config.yaml: %v", cfgErr)
		} else if len(tshCfg.AddHeaders) > 0 {
			proxyAddr := resolved.PublicAddr
			if proxyAddr == "" {
				proxyAddr = profile.PublicAddr
			}
			matching := tshCfg.MatchingHeaders(proxyAddr)
			if len(matching) > 0 {
				log.Printf("loaded %d extra header(s) from ~/.tsh/config.yaml for proxy %s", len(matching), proxyAddr)
				// Merge: CLI-provided headers take precedence over config-file headers.
				merged := make(map[string]string)
				for k, v := range matching {
					merged[k] = v
				}
				for k, v := range resolved.ExtraHeaders {
					merged[k] = v
				}
				resolved.ExtraHeaders = merged
			}
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
	log.Printf("resolved proxy: %s:%d (cluster: %s, version: %s, tls_routing: %v)",
		resolved.PublicAddr, resolved.WebProxyPort, resolved.ClusterName,
		resolved.TeleportVersion, resolved.TLSRoutingEnabled)

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

		log.Printf("fetching host CA bundle from %s", endpoint)
		bundle, fetchErr = discovery.FetchHostCAs(ctx, endpoint, discovery.ProxySettings{
			HTTPSProxy: resolved.Proxy.HTTPSProxy,
			HTTPProxy:  resolved.Proxy.HTTPProxy,
		})
		if fetchErr == nil {
			log.Printf("successfully fetched host CA bundle from %s (%d bytes)", endpoint, len(bundle))
			resolved.HostCAPEM = bundle
			break
		}
		log.Printf("failed to fetch host CA from %s: %v", endpoint, fetchErr)
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
