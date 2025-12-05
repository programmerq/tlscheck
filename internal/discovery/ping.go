package discovery

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ProxySettings mirrors the subset of proxy configuration required for HTTP discovery.
type ProxySettings struct {
	HTTPSProxy string
	HTTPProxy  string
}

// PingInfo represents the fields gathered from /webapi/ping.
type PingInfo struct {
	ClusterName         string
	ServerVersion       string
	Proxy               ProxyInfo
	InsecureSkipVerify  bool   // Whether TLS verification was skipped
	TLSVerificationNote string // Note about TLS verification status
}

// ProxyInfo describes the proxy configuration surfaced by /webapi/ping.
type ProxyInfo struct {
	WebProxyPublicAddr string
	TLSRoutingEnabled  bool
}

// FetchClusterInfo retrieves cluster metadata from the proxy's /webapi/ping endpoint.
// TLS certificate verification is skipped to allow the tool to run in environments
// without a complete CA trust store (e.g., bare containers). The verification status
// is captured in PingInfo for diagnostic reporting.
func FetchClusterInfo(ctx context.Context, publicAddr string, proxy ProxySettings) (PingInfo, error) {
	pingURL, err := buildPingURL(publicAddr)
	if err != nil {
		return PingInfo{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pingURL, nil)
	if err != nil {
		return PingInfo{}, fmt.Errorf("creating ping request: %w", err)
	}

	transport := &http.Transport{
		Proxy: proxyFunc(proxy),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		return PingInfo{}, fmt.Errorf("performing ping request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return PingInfo{}, fmt.Errorf("unexpected ping status: %s", resp.Status)
	}

	var payload pingResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return PingInfo{}, fmt.Errorf("decoding ping response: %w", err)
	}

	info := PingInfo{
		ClusterName:        strings.TrimSpace(payload.ClusterName),
		ServerVersion:      strings.TrimSpace(payload.ServerVersion),
		InsecureSkipVerify: true,
		TLSVerificationNote: "TLS certificate verification was skipped for initial discovery; " +
			"the probe engine performs detailed certificate validation during probing",
	}

	if payload.Proxy != nil {
		info.Proxy.TLSRoutingEnabled = payload.Proxy.TLSRoutingEnabled
		if payload.Proxy.SSH != nil {
			info.Proxy.WebProxyPublicAddr = strings.TrimSpace(payload.Proxy.SSH.PublicAddr)
		}
	}

	if info.ClusterName == "" {
		return PingInfo{}, fmt.Errorf("ping response missing cluster_name")
	}
	if info.ServerVersion == "" {
		return PingInfo{}, fmt.Errorf("ping response missing server_version")
	}

	return info, nil
}

func buildPingURL(publicAddr string) (string, error) {
	value := strings.TrimSpace(publicAddr)
	if value == "" {
		return "", fmt.Errorf("public address is empty")
	}

	if !strings.Contains(value, "://") {
		value = "https://" + value
	}

	u, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("invalid public address %q: %w", publicAddr, err)
	}

	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if u.Host == "" {
		u.Host = value
	}

	u.Path = strings.TrimSuffix(u.Path, "/") + "/webapi/ping"

	return u.String(), nil
}

func proxyFunc(settings ProxySettings) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		if req == nil {
			return nil, nil
		}

		if strings.EqualFold(req.URL.Scheme, "https") {
			if parsed := parseProxyURL(settings.HTTPSProxy); parsed != nil {
				return parsed, nil
			}
			if parsed := parseProxyURL(settings.HTTPProxy); parsed != nil {
				return parsed, nil
			}
		}

		if strings.EqualFold(req.URL.Scheme, "http") {
			if parsed := parseProxyURL(settings.HTTPProxy); parsed != nil {
				return parsed, nil
			}
		}

		return nil, nil
	}
}

func parseProxyURL(raw string) *url.URL {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	return parsed
}

type pingResponse struct {
	ClusterName   string        `json:"cluster_name"`
	ServerVersion string        `json:"server_version"`
	Proxy         *proxySection `json:"proxy"`
}

type proxySection struct {
	TLSRoutingEnabled bool             `json:"tls_routing_enabled"`
	SSH               *sshProxySection `json:"ssh"`
}

type sshProxySection struct {
	PublicAddr string `json:"public_addr"`
}
