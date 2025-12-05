package discovery

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HostCAResult contains the Host CA bundle and verification status.
type HostCAResult struct {
	Bundle                   []byte
	InsecureSkipVerify       bool   // Whether TLS verification was skipped
	TLSVerificationError     string // The certificate verification error if any
	TLSVerificationSucceeded bool   // Whether TLS verification succeeded
}

// FetchHostCAs downloads the Teleport Host CA bundle from the proxy.
// It first attempts with TLS verification enabled. If that fails due to certificate
// verification issues, it retries with InsecureSkipVerify and captures the error.
func FetchHostCAs(ctx context.Context, publicAddr string, proxy ProxySettings) ([]byte, error) {
	result, err := FetchHostCAsWithStatus(ctx, publicAddr, proxy)
	if err != nil {
		return nil, err
	}
	return result.Bundle, nil
}

// FetchHostCAsWithStatus downloads the Teleport Host CA bundle from the proxy
// and returns detailed status about TLS verification.
func FetchHostCAsWithStatus(ctx context.Context, publicAddr string, proxy ProxySettings) (HostCAResult, error) {
	exportURL, err := buildExportURL(publicAddr)
	if err != nil {
		return HostCAResult{}, err
	}

	// First try with TLS verification enabled
	bundle, secureErr := fetchHostCAsWithTLS(ctx, exportURL, proxy, false)
	if secureErr == nil {
		// Success with verification
		return HostCAResult{
			Bundle:                   bundle,
			TLSVerificationSucceeded: true,
		}, nil
	}

	// Check if it's a certificate verification error
	if !isCertVerificationError(secureErr) {
		// Not a cert error, return the original error
		return HostCAResult{}, secureErr
	}

	// Retry with InsecureSkipVerify
	bundle, insecureErr := fetchHostCAsWithTLS(ctx, exportURL, proxy, true)
	if insecureErr != nil {
		// Both attempts failed, return the insecure error (more relevant)
		return HostCAResult{}, insecureErr
	}

	// Succeeded with InsecureSkipVerify - capture the original verification error
	return HostCAResult{
		Bundle:                   bundle,
		InsecureSkipVerify:       true,
		TLSVerificationError:     secureErr.Error(),
		TLSVerificationSucceeded: false,
	}, nil
}

// fetchHostCAsWithTLS performs the actual HTTP request with configurable TLS verification.
func fetchHostCAsWithTLS(ctx context.Context, exportURL string, proxy ProxySettings, insecureSkipVerify bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, exportURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating host CA request: %w", err)
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
		return nil, fmt.Errorf("performing host CA request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected host CA status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading host CA response: %w", err)
	}

	if len(bytes.TrimSpace(body)) == 0 {
		return nil, fmt.Errorf("host CA response empty")
	}

	return body, nil
}

func buildExportURL(publicAddr string) (string, error) {
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

	u.Path = strings.TrimSuffix(u.Path, "/") + "/webapi/auth/export"
	q := u.Query()
	q.Set("type", "tls-host")
	u.RawQuery = q.Encode()

	return u.String(), nil
}
