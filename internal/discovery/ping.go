package discovery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/programmerq/tlscheck/internal/log"
)

// ProxySettings mirrors the subset of proxy configuration required for HTTP discovery.
type ProxySettings struct {
	HTTPSProxy string
	HTTPProxy  string
}

// PingInfo represents the fields gathered from /webapi/ping.
type PingInfo struct {
	ClusterName              string
	ServerVersion            string
	Proxy                    ProxyInfo
	InsecureSkipVerify       bool   // Whether TLS verification was skipped
	TLSVerificationError     string // The certificate verification error if any
	TLSVerificationSucceeded bool   // Whether TLS verification succeeded
}

// ProxyInfo describes the proxy configuration surfaced by /webapi/ping.
type ProxyInfo struct {
	WebProxyPublicAddr string
	TLSRoutingEnabled  bool
}

// isCertVerificationError checks if the error is related to TLS certificate verification.
// This uses both error type checking (errors.As) and string pattern matching because
// TLS errors are often wrapped in a way that errors.As cannot unwrap.
func isCertVerificationError(err error) bool {
	if err == nil {
		return false
	}
	// Check for specific error types using errors.As first
	var certErr x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var certInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certErr) || errors.As(err, &hostErr) || errors.As(err, &certInvalidErr) {
		return true
	}
	// Fall back to string pattern matching for wrapped errors
	// Use specific patterns to minimize false positives
	errStr := err.Error()
	if strings.Contains(errStr, "x509: certificate") ||
		strings.Contains(errStr, "tls: failed to verify certificate") {
		return true
	}
	return false
}

// FetchClusterInfo retrieves cluster metadata from the proxy's /webapi/ping endpoint.
// It first attempts with TLS verification enabled. If that fails due to certificate
// verification issues, it retries with InsecureSkipVerify and captures the error.
func FetchClusterInfo(ctx context.Context, publicAddr string, proxy ProxySettings) (PingInfo, error) {
	pingURL, err := buildPingURL(publicAddr)
	if err != nil {
		return PingInfo{}, err
	}

	log.Printf("fetching cluster info from %s", pingURL)
	if proxy.HTTPSProxy != "" || proxy.HTTPProxy != "" {
		log.Printf("using proxy: https_proxy=%s http_proxy=%s",
			log.SanitizeURL(proxy.HTTPSProxy), log.SanitizeURL(proxy.HTTPProxy))
	}

	// First try with TLS verification enabled
	log.Printf("attempting secure TLS connection to %s", pingURL)
	info, secureErr := fetchClusterInfoWithTLS(ctx, pingURL, proxy, false)
	if secureErr == nil {
		// Success with verification
		log.Printf("successfully fetched cluster info with TLS verification (cluster: %s, version: %s)",
			info.ClusterName, info.ServerVersion)
		info.TLSVerificationSucceeded = true
		return info, nil
	}

	log.Printf("TLS verification failed: %v", secureErr)
	// Check if it's a certificate verification error
	if !isCertVerificationError(secureErr) {
		// Not a cert error, return the original error
		return PingInfo{}, secureErr
	}

	// Retry with InsecureSkipVerify
	log.Printf("retrying with InsecureSkipVerify due to certificate verification error")
	info, insecureErr := fetchClusterInfoWithTLS(ctx, pingURL, proxy, true)
	if insecureErr != nil {
		// Both attempts failed. Return the insecure error because if both fail,
		// the insecure error is more likely to indicate the actual connectivity
		// problem (e.g., server unreachable) rather than a trust store issue.
		// The original cert error is captured in TLSVerificationError on success.
		return PingInfo{}, insecureErr
	}

	// Succeeded with InsecureSkipVerify - capture the original verification error
	info.InsecureSkipVerify = true
	info.TLSVerificationError = secureErr.Error()
	info.TLSVerificationSucceeded = false
	return info, nil
}

// fetchClusterInfoWithTLS performs the actual HTTP request with configurable TLS verification.
func fetchClusterInfoWithTLS(ctx context.Context, pingURL string, proxy ProxySettings, insecureSkipVerify bool) (PingInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pingURL, nil)
	if err != nil {
		return PingInfo{}, fmt.Errorf("creating ping request: %w", err)
	}

	transport := &http.Transport{
		Proxy: proxyFunc(proxy),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
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
		ClusterName:   strings.TrimSpace(payload.ClusterName),
		ServerVersion: strings.TrimSpace(payload.ServerVersion),
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
