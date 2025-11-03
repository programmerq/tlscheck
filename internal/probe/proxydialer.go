package probe

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ProxyDialer wraps a dialer to route connections through an HTTP/HTTPS proxy using CONNECT.
type ProxyDialer struct {
	proxyURL *url.URL
	dialer   *net.Dialer
}

// NewProxyDialer creates a dialer that routes connections through the specified proxy.
// The proxyURL should be in the form "http://host:port" or "https://host:port".
func NewProxyDialer(proxyURL string, timeout time.Duration) (*ProxyDialer, error) {
	if proxyURL == "" {
		return nil, fmt.Errorf("proxy URL cannot be empty")
	}

	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported proxy scheme %q (only http/https supported)", parsed.Scheme)
	}

	return &ProxyDialer{
		proxyURL: parsed,
		dialer:   &net.Dialer{Timeout: timeout},
	}, nil
}

// DialContext establishes a connection through the proxy using HTTP CONNECT.
func (p *ProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("proxy dialer only supports tcp connections, got %q", network)
	}

	// Connect to the proxy server
	proxyAddr := p.proxyURL.Host
	if !strings.Contains(proxyAddr, ":") {
		// Add default port if not specified
		if p.proxyURL.Scheme == "https" {
			proxyAddr = proxyAddr + ":443"
		} else {
			proxyAddr = proxyAddr + ":80"
		}
	}

	conn, err := p.dialer.DialContext(ctx, network, proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy %s: %w", proxyAddr, err)
	}

	// Send CONNECT request
	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: address},
		Host:   address,
		Header: make(http.Header),
	}

	// Add proxy authentication if credentials are present
	if p.proxyURL.User != nil {
		username := p.proxyURL.User.Username()
		password, _ := p.proxyURL.User.Password()
		auth := username + ":" + password
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
		connectReq.Header.Set("Proxy-Authorization", basicAuth)
	}

	// Write the CONNECT request
	if err := connectReq.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	// Read the response
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}

	return conn, nil
}
