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

// bufferedConn wraps a connection with a buffered reader to preserve any buffered data.
type bufferedConn struct {
	*bufio.Reader
	net.Conn
}

// Read reads from the buffered reader first, then falls back to the underlying connection.
func (bc *bufferedConn) Read(b []byte) (int, error) {
	return bc.Reader.Read(b)
}

// DialContext connects to the target address, optionally through an HTTP CONNECT proxy.
func (pd *ProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// fmt.Fprintf(os.Stderr, "[DEBUG] ProxyDialer.DialContext called: address=%s, proxyURL=%v\n", address, pd.ProxyURL)

	if pd.ProxyURL == nil {
		// No proxy configured, use direct connection
		// fmt.Fprintf(os.Stderr, "[DEBUG] ProxyDialer: ProxyURL is nil, using direct connection\n")
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

	// fmt.Fprintf(os.Stderr, "[DEBUG] ProxyDialer: Connecting to proxy %s for target %s\n", proxyAddr, address)
	conn, err := dialer.DialContext(ctx, network, proxyAddr)
	if err != nil {
		// fmt.Fprintf(os.Stderr, "[DEBUG] ProxyDialer: Failed to connect to proxy: %v\n", err)
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
	// fmt.Fprintf(os.Stderr, "[DEBUG] ProxyDialer: Sending CONNECT request to %s\n", address)
	if err := req.Write(conn); err != nil {
		conn.Close()
		// fmt.Fprintf(os.Stderr, "[DEBUG] ProxyDialer: Failed to write CONNECT request: %v\n", err)
		return nil, fmt.Errorf("writing CONNECT request: %w", err)
	}

	// Read CONNECT response
	// Note: We must not defer resp.Body.Close() here because the response body
	// is connected to the underlying connection that we're about to return.
	// Closing the response body would close our connection!
	// Also, we need to preserve the bufio.Reader because it may have buffered
	// data beyond the HTTP response headers.
	// fmt.Fprintf(os.Stderr, "[DEBUG] ProxyDialer: Reading CONNECT response\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		// fmt.Fprintf(os.Stderr, "[DEBUG] ProxyDialer: Failed to read CONNECT response: %v\n", err)
		return nil, fmt.Errorf("reading CONNECT response: %w", err)
	}

	// fmt.Fprintf(os.Stderr, "[DEBUG] ProxyDialer: CONNECT response status: %s\n", resp.Status)
	if resp.StatusCode != http.StatusOK {
		// Read and discard the response body for error responses
		if resp.Body != nil {
			resp.Body.Close()
		}
		conn.Close()
		// fmt.Fprintf(os.Stderr, "[DEBUG] ProxyDialer: CONNECT failed with status %s\n", resp.Status)
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}

	// For successful CONNECT, the response body should be empty and we must not close it.
	// The connection is now ready for the TLS handshake.
	// However, we need to return a connection that includes any buffered data.
	// fmt.Fprintf(os.Stderr, "[DEBUG] ProxyDialer: CONNECT successful, returning connection\n")

	// If the buffered reader has buffered any data beyond the response headers,
	// we need to wrap the connection to provide that data first.
	if br.Buffered() > 0 {
		// fmt.Fprintf(os.Stderr, "[DEBUG] ProxyDialer: Reader has %d buffered bytes, wrapping connection\n", br.Buffered())
		return &bufferedConn{
			Reader: br,
			Conn:   conn,
		}, nil
	}

	return conn, nil
}
