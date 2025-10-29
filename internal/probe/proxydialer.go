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

// ProxyDialer wraps a net.Dialer to support HTTP/HTTPS CONNECT proxies for TCP connections.
type ProxyDialer struct {
	Dialer    *net.Dialer
	ProxyURL  *url.URL
	ProxyAuth string // optional Basic auth in "username:password" format
}

// DialContext connects to the target address, optionally through an HTTP CONNECT proxy.
func (pd *ProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if pd.ProxyURL == nil {
		// No proxy configured, use direct connection
		if pd.Dialer != nil {
			return pd.Dialer.DialContext(ctx, network, address)
		}
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		return dialer.DialContext(ctx, network, address)
	}

	// Connect to the proxy server
	dialer := pd.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 10 * time.Second}
	}

	proxyAddr := pd.ProxyURL.Host
	if !strings.Contains(proxyAddr, ":") {
		// Add default port for HTTP proxy
		if pd.ProxyURL.Scheme == "https" {
			proxyAddr = net.JoinHostPort(proxyAddr, "443")
		} else {
			proxyAddr = net.JoinHostPort(proxyAddr, "80")
		}
	}

	conn, err := dialer.DialContext(ctx, network, proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connecting to proxy %s: %w", proxyAddr, err)
	}

	// Send HTTP CONNECT request
	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Host: address},
		Host:   address,
		Header: make(http.Header),
	}

	// Add proxy authentication if provided
	if pd.ProxyAuth != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(pd.ProxyAuth))
		req.Header.Set("Proxy-Authorization", "Basic "+auth)
	} else if pd.ProxyURL.User != nil {
		// Extract auth from proxy URL
		username := pd.ProxyURL.User.Username()
		password, _ := pd.ProxyURL.User.Password()
		if username != "" {
			auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
			req.Header.Set("Proxy-Authorization", "Basic "+auth)
		}
	}

	// Write CONNECT request
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("writing CONNECT request: %w", err)
	}

	// Read CONNECT response
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading CONNECT response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}

	// Connection established through proxy
	return conn, nil
}
