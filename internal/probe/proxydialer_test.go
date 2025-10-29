package probe

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestProxyDialerDirect(t *testing.T) {
	// Test direct connection (no proxy)
	pd := &ProxyDialer{
		Dialer: &net.Dialer{Timeout: 5 * time.Second},
	}

	// Start a test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()
	done := make(chan struct{})

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Write([]byte("hello"))
		conn.Close()
		close(done)
	}()

	ctx := context.Background()
	conn, err := pd.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		t.Fatalf("direct dial failed: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 5)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "hello" {
		t.Errorf("expected 'hello', got %q", string(buf[:n]))
	}

	<-done
}

func TestProxyDialerWithProxy(t *testing.T) {
	// Start a mock proxy server
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start proxy server: %v", err)
	}
	defer proxyListener.Close()

	proxyAddr := proxyListener.Addr().String()

	// Start the target server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start target server: %v", err)
	}
	defer targetListener.Close()

	targetAddr := targetListener.Addr().String()

	// Mock proxy handler
	go func() {
		for {
			conn, err := proxyListener.Accept()
			if err != nil {
				return
			}

			go func(proxyConn net.Conn) {
				defer proxyConn.Close()

				// Read CONNECT request
				reader := bufio.NewReader(proxyConn)
				req, err := http.ReadRequest(reader)
				if err != nil {
					return
				}

				if req.Method != "CONNECT" {
					proxyConn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
					return
				}

				// Connect to target
				targetConn, err := net.Dial("tcp", req.URL.Host)
				if err != nil {
					proxyConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer targetConn.Close()

				// Send 200 OK response
				proxyConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

				// Relay data bidirectionally
				done := make(chan struct{}, 2)
				go func() {
					buf := make([]byte, 4096)
					for {
						n, err := proxyConn.Read(buf)
						if err != nil || n == 0 {
							break
						}
						targetConn.Write(buf[:n])
					}
					done <- struct{}{}
				}()
				go func() {
					buf := make([]byte, 4096)
					for {
						n, err := targetConn.Read(buf)
						if err != nil || n == 0 {
							break
						}
						proxyConn.Write(buf[:n])
					}
					done <- struct{}{}
				}()
				<-done
			}(conn)
		}
	}()

	// Target server handler
	targetReady := make(chan struct{})
	go func() {
		close(targetReady)
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(10 * time.Millisecond) // Small delay to ensure proxy setup
		conn.Write([]byte("proxied-hello"))
	}()

	<-targetReady

	// Create proxy dialer
	proxyURL, _ := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	pd := &ProxyDialer{
		Dialer:   &net.Dialer{Timeout: 5 * time.Second},
		ProxyURL: proxyURL,
	}

	ctx := context.Background()
	conn, err := pd.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		t.Fatalf("proxy dial failed: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 100)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	received := string(buf[:n])
	if !strings.Contains(received, "proxied-hello") {
		t.Errorf("expected 'proxied-hello', got %q", received)
	}
}

func TestProxyDialerWithAuth(t *testing.T) {
	// Start a mock proxy server that requires authentication
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start proxy server: %v", err)
	}
	defer proxyListener.Close()

	proxyAddr := proxyListener.Addr().String()

	// Start the target server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start target server: %v", err)
	}
	defer targetListener.Close()

	targetAddr := targetListener.Addr().String()

	expectedAuth := "Basic dXNlcjpwYXNz" // user:pass in base64

	// Mock proxy handler with auth check
	go func() {
		conn, err := proxyListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read CONNECT request
		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}

		// Check authentication
		auth := req.Header.Get("Proxy-Authorization")
		if auth != expectedAuth {
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
			return
		}

		// Connect to target
		targetConn, err := net.Dial("tcp", req.URL.Host)
		if err != nil {
			return
		}
		defer targetConn.Close()

		// Send 200 OK response
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		// Simple relay
		buf := make([]byte, 4096)
		targetConn.Read(buf)
		conn.Write(buf)
	}()

	// Target server handler
	targetReady := make(chan struct{})
	go func() {
		close(targetReady)
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(10 * time.Millisecond) // Small delay to ensure proxy setup
		conn.Write([]byte("auth-success"))
	}()

	<-targetReady

	// Create proxy dialer with authentication
	proxyURL, _ := url.Parse(fmt.Sprintf("http://user:pass@%s", proxyAddr))
	pd := &ProxyDialer{
		Dialer:   &net.Dialer{Timeout: 5 * time.Second},
		ProxyURL: proxyURL,
	}

	ctx := context.Background()
	conn, err := pd.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		t.Fatalf("proxy dial with auth failed: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 100)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	received := string(buf[:n])
	if !strings.Contains(received, "auth-success") {
		t.Errorf("expected 'auth-success', got %q", received)
	}
}
