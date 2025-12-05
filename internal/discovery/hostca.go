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

// FetchHostCAs downloads the Teleport Host CA bundle from the proxy.
// TLS certificate verification is skipped to allow the tool to run in environments
// without a complete CA trust store (e.g., bare containers).
func FetchHostCAs(ctx context.Context, publicAddr string, proxy ProxySettings) ([]byte, error) {
	exportURL, err := buildExportURL(publicAddr)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, exportURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating host CA request: %w", err)
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
