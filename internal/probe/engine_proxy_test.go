package probe

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/programmerq/tlscheck/internal/plan"
)

func TestEngineUsesProxyWhenConfigured(t *testing.T) {
	// Create a self-signed certificate for the test server
	cert, key := generateSelfSignedCert(t)
	tlsCert, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatalf("failed to load certificate: %v", err)
	}

	// Start a TLS test server
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h2"},
	}

	tlsListener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to start TLS server: %v", err)
	}
	defer tlsListener.Close()

	tlsAddr := tlsListener.Addr().String()
	_, tlsPort, _ := net.SplitHostPort(tlsAddr)

	go func() {
		for {
			conn, err := tlsListener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	// Start a mock HTTP proxy that tracks connections
	proxyConnections := make(chan string, 10)
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start proxy server: %v", err)
	}
	defer proxyListener.Close()

	proxyAddr := proxyListener.Addr().String()

	go func() {
		for {
			conn, err := proxyListener.Accept()
			if err != nil {
				return
			}

			go func(proxyConn net.Conn) {
				defer proxyConn.Close()

				reader := bufio.NewReader(proxyConn)
				req, err := http.ReadRequest(reader)
				if err != nil {
					return
				}

				if req.Method != "CONNECT" {
					proxyConn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
					return
				}

				// Log the connection through proxy
				proxyConnections <- req.URL.Host

				// Connect to the target
				targetConn, err := net.Dial("tcp", req.URL.Host)
				if err != nil {
					proxyConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer targetConn.Close()

				// Send 200 OK
				proxyConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

				// Relay data
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

	// Test with proxy
	t.Run("with_proxy", func(t *testing.T) {
		engine := NewEngine()
		engine.ProxyURL = "http://" + proxyAddr

		target := plan.ProbeTarget{
			ServiceKey:  "test",
			DisplayName: "Test",
			Address:     "127.0.0.1",
			Port:        mustAtoi(tlsPort),
			PrimarySNI:  "test.example.com",
			ALPNs:       []string{"h2"},
			Trust:       plan.TrustSystemRoots,
			UseProxy:    true,
		}

		ctx := context.Background()
		result := engine.probeOnce(ctx, target, 1)

		// Should have connected through proxy
		select {
		case connectedTo := <-proxyConnections:
			expectedTarget := "127.0.0.1:" + tlsPort
			if connectedTo != expectedTarget {
				t.Errorf("proxy connected to %s, expected %s", connectedTo, expectedTarget)
			}
		case <-time.After(2 * time.Second):
			t.Error("no connection through proxy detected")
		}

		// The connection should have been attempted (may fail due to cert verification)
		if result.Failure != nil {
			// Failure is expected due to self-signed cert
			if result.Failure.Kind != "untrusted_cert" && result.Failure.Kind != "handshake_failed" {
				t.Logf("Connection failed as expected: %s - %s", result.Failure.Kind, result.Failure.Message)
			}
		}
	})

	// Test without proxy (direct connection)
	t.Run("without_proxy", func(t *testing.T) {
		engine := NewEngine()
		engine.ProxyURL = "http://" + proxyAddr

		target := plan.ProbeTarget{
			ServiceKey:  "test",
			DisplayName: "Test",
			Address:     "127.0.0.1",
			Port:        mustAtoi(tlsPort),
			PrimarySNI:  "test.example.com",
			ALPNs:       []string{"h2"},
			Trust:       plan.TrustSystemRoots,
			UseProxy:    false, // Explicitly bypass proxy
		}

		ctx := context.Background()
		result := engine.probeOnce(ctx, target, 1)

		// Should NOT have connected through proxy
		select {
		case <-proxyConnections:
			t.Error("connection went through proxy when it should have been direct")
		case <-time.After(200 * time.Millisecond):
			// Expected - no proxy connection
		}

		// The connection should have been attempted (may fail due to cert verification)
		if result.Failure != nil {
			// Failure is expected due to self-signed cert
			if result.Failure.Kind != "untrusted_cert" && result.Failure.Kind != "handshake_failed" {
				t.Logf("Connection failed as expected: %s - %s", result.Failure.Kind, result.Failure.Message)
			}
		}
	})
}

func generateSelfSignedCert(t *testing.T) (certPEM, keyPEM string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}))

	return certPEM, keyPEM
}

func mustAtoi(s string) int {
	var n int
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}
