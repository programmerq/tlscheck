package probe

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNewProxyDialer(t *testing.T) {
	tests := []struct {
		name      string
		proxyURL  string
		wantErr   bool
		errString string
	}{
		{
			name:     "valid http proxy",
			proxyURL: "http://proxy.example.com:8080",
			wantErr:  false,
		},
		{
			name:     "valid https proxy",
			proxyURL: "https://proxy.example.com:8443",
			wantErr:  false,
		},
		{
			name:      "empty URL",
			proxyURL:  "",
			wantErr:   true,
			errString: "cannot be empty",
		},
		{
			name:      "invalid URL",
			proxyURL:  "://invalid",
			wantErr:   true,
			errString: "invalid proxy URL",
		},
		{
			name:      "unsupported scheme",
			proxyURL:  "socks5://proxy.example.com:1080",
			wantErr:   true,
			errString: "unsupported proxy scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dialer, err := NewProxyDialer(tt.proxyURL, 10*time.Second)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errString)
				} else if !strings.Contains(err.Error(), tt.errString) {
					t.Errorf("expected error containing %q, got %q", tt.errString, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if dialer == nil {
					t.Error("expected non-nil dialer")
				}
			}
		})
	}
}

func TestProxyDialerConnect(t *testing.T) {
	// Start a mock proxy server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test proxy: %v", err)
	}
	defer listener.Close()

	proxyAddr := listener.Addr().String()

	// Handle CONNECT requests in the background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				req, err := http.ReadRequest(reader)
				if err != nil {
					return
				}

				if req.Method == "CONNECT" {
					// Send success response
					resp := "HTTP/1.1 200 Connection Established\r\n\r\n"
					if _, err := c.Write([]byte(resp)); err != nil {
						return
					}
					// Keep connection open for TLS handshake
					time.Sleep(100 * time.Millisecond)
				}
			}(conn)
		}
	}()

	// Test dialing through the proxy
	proxyURL := fmt.Sprintf("http://%s", proxyAddr)
	dialer, err := NewProxyDialer(proxyURL, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to create proxy dialer: %v", err)
	}

	ctx := context.Background()
	conn, err := dialer.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("failed to dial through proxy: %v", err)
	}
	if conn != nil {
		conn.Close()
	}
}

func TestProxyDialerInvalidNetwork(t *testing.T) {
	dialer, err := NewProxyDialer("http://proxy.example.com:8080", 5*time.Second)
	if err != nil {
		t.Fatalf("failed to create proxy dialer: %v", err)
	}

	ctx := context.Background()
	_, err = dialer.DialContext(ctx, "udp", "example.com:443")
	if err == nil {
		t.Error("expected error for non-tcp network")
	}
	if !strings.Contains(err.Error(), "only supports tcp") {
		t.Errorf("expected error about tcp support, got: %v", err)
	}
}
