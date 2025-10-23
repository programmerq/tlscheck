package probe

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/programmerq/tlscheck/internal/plan"
)

func TestEngineHandshakeSuccess(t *testing.T) {
	t.Parallel()

	cert, pool := generateServerCert(t, "teleport.example.com")
	addr, cleanup := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}, nil)
	t.Cleanup(cleanup)

	host, port := splitHostPort(t, addr)
	target := plan.ProbeTarget{
		ServiceKey:      "proxy_web",
		Address:         host,
		Port:            port,
		PrimarySNI:      "teleport.example.com",
		ALPNs:           []string{"h2", "http/1.1"},
		Trust:           plan.TrustSystemRoots,
		Repeat:          1,
		UpgradeSequence: nil,
	}

	engine := NewEngine()
	engine.systemRoots = pool

	probePlan := plan.Plan{Targets: []plan.ProbeTarget{target}}
	results, err := engine.Run(context.Background(), probePlan)
	if err != nil {
		t.Fatalf("engine.Run returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	res := results[0]
	if res.Failure != nil {
		t.Fatalf("expected success, got failure: %#v", res.Failure)
	}
	if res.NegotiatedProtocol != "h2" {
		t.Fatalf("negotiated protocol = %q, want h2", res.NegotiatedProtocol)
	}
	if res.LeafFingerprint == "" || res.LeafSubject == "" {
		t.Fatalf("expected certificate details to be populated")
	}
	if res.LeafSubject != "CN=teleport.example.com" {
		t.Fatalf("LeafSubject = %q, want CN=teleport.example.com", res.LeafSubject)
	}
	if res.LeafIssuer != "CN=tlscheck test ca" {
		t.Fatalf("LeafIssuer = %q, want CN=tlscheck test ca", res.LeafIssuer)
	}
	if len(res.LeafSANs) != 1 || res.LeafSANs[0] != "teleport.example.com" {
		t.Fatalf("LeafSANs = %#v, want [teleport.example.com]", res.LeafSANs)
	}
}

func TestEngineALPNMismatch(t *testing.T) {
	t.Parallel()

	cert, pool := generateServerCert(t, "cluster.example.com")
	addr, cleanup := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}, nil)
	t.Cleanup(cleanup)

	host, port := splitHostPort(t, addr)
	target := plan.ProbeTarget{
		ServiceKey: "proxy_web",
		Address:    host,
		Port:       port,
		PrimarySNI: "cluster.example.com",
		ALPNs:      []string{"h2"},
		Trust:      plan.TrustSystemRoots,
	}

	engine := NewEngine()
	engine.systemRoots = pool

	probePlan := plan.Plan{Targets: []plan.ProbeTarget{target}}
	results, err := engine.Run(context.Background(), probePlan)
	if err != nil {
		t.Fatalf("engine.Run returned error: %v", err)
	}
	if results[0].Failure == nil || results[0].Failure.Kind != "alpn_mismatch" {
		t.Fatalf("expected alpn_mismatch failure, got %#v", results[0].Failure)
	}
}

func TestEngineHandshakeFailure(t *testing.T) {
	t.Parallel()

	addr, cleanup := startFailingServer(t)
	t.Cleanup(cleanup)

	host, port := splitHostPort(t, addr)
	target := plan.ProbeTarget{
		ServiceKey: "proxy_web",
		Address:    host,
		Port:       port,
		PrimarySNI: "cluster.example.com",
		ALPNs:      []string{"h2"},
	}

	engine := NewEngine()

	probePlan := plan.Plan{Targets: []plan.ProbeTarget{target}}
	results, err := engine.Run(context.Background(), probePlan)
	if err != nil {
		t.Fatalf("engine.Run returned error: %v", err)
	}
	if results[0].Failure == nil || results[0].Failure.Kind != "handshake_failed" {
		t.Fatalf("expected handshake_failed, got %#v", results[0].Failure)
	}
}

func TestEngineReportsUntrustedCertWithDetails(t *testing.T) {
	t.Parallel()

	cert, _ := generateServerCert(t, "untrusted.example.com")
	addr, cleanup := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}, nil)
	t.Cleanup(cleanup)

	host, port := splitHostPort(t, addr)
	target := plan.ProbeTarget{
		ServiceKey: "proxy_web",
		Address:    host,
		Port:       port,
		PrimarySNI: "untrusted.example.com",
		ALPNs:      []string{"h2"},
		Trust:      plan.TrustSystemRoots,
	}

	engine := NewEngine()
	engine.systemRoots = x509.NewCertPool() // empty so verification fails

	probePlan := plan.Plan{Targets: []plan.ProbeTarget{target}}
	results, err := engine.Run(context.Background(), probePlan)
	if err != nil {
		t.Fatalf("engine.Run returned error: %v", err)
	}
	res := results[0]
	if res.Failure == nil || res.Failure.Kind != "untrusted_cert" {
		t.Fatalf("expected untrusted_cert failure, got %#v", res.Failure)
	}
	if res.LeafFingerprint == "" || res.LeafSubject == "" {
		t.Fatalf("expected certificate metadata to be captured on failure")
	}
	if len(res.LeafSANs) == 0 || res.LeafSANs[0] != "untrusted.example.com" {
		t.Fatalf("expected SANs to include leaf DNS name, got %#v", res.LeafSANs)
	}
}

func TestEngineHonorsHostCATrust(t *testing.T) {
	t.Parallel()

	cert, hostPool := generateServerCert(t, "teleport.example.com")
	addr, cleanup := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"teleport-proxy-ssh"},
	}, nil)
	t.Cleanup(cleanup)

	host, port := splitHostPort(t, addr)
	target := plan.ProbeTarget{
		ServiceKey: "proxy_ssh",
		Address:    host,
		Port:       port,
		PrimarySNI: "teleport.example.com",
		ALPNs:      []string{"teleport-proxy-ssh"},
		Trust:      plan.TrustHostCA,
	}

	engine := NewEngine()
	engine.RootCAs = hostPool
	engine.systemRoots = x509.NewCertPool() // ensure system trust alone would fail

	probePlan := plan.Plan{Targets: []plan.ProbeTarget{target}}
	results, err := engine.Run(context.Background(), probePlan)
	if err != nil {
		t.Fatalf("engine.Run returned error: %v", err)
	}
	if results[0].Failure != nil {
		t.Fatalf("expected success, got failure %#v", results[0].Failure)
	}
}

func TestEngineRequiresHostCABundle(t *testing.T) {
	t.Parallel()

	cert, _ := generateServerCert(t, "teleport.example.com")
	addr, cleanup := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"teleport-proxy-ssh"},
	}, nil)
	t.Cleanup(cleanup)

	host, port := splitHostPort(t, addr)
	target := plan.ProbeTarget{
		ServiceKey: "proxy_ssh",
		Address:    host,
		Port:       port,
		PrimarySNI: "teleport.example.com",
		ALPNs:      []string{"teleport-proxy-ssh"},
		Trust:      plan.TrustHostCA,
	}

	engine := NewEngine()
	engine.RootCAs = nil
	engine.systemRoots = x509.NewCertPool()

	probePlan := plan.Plan{Targets: []plan.ProbeTarget{target}}
	results, err := engine.Run(context.Background(), probePlan)
	if err != nil {
		t.Fatalf("engine.Run returned error: %v", err)
	}
	res := results[0]
	if res.Failure == nil || res.Failure.Kind != "host_ca_unavailable" {
		t.Fatalf("expected host_ca_unavailable failure, got %#v", res.Failure)
	}
}

func generateServerCert(t *testing.T, host string) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tlscheck test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return cert, pool
}

func startTLSServer(t *testing.T, cfg *tls.Config, handler func(*tls.Conn)) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var once sync.Once
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		tlsConn := tls.Server(conn, cfg)
		if err := tlsConn.Handshake(); err == nil {
			if handler != nil {
				handler(tlsConn)
			}
		}
		tlsConn.Close()
		once.Do(func() { ln.Close() })
	}()

	cleanup := func() {
		once.Do(func() { ln.Close() })
		<-done
	}

	return ln.Addr().String(), cleanup
}

func startFailingServer(t *testing.T) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
		ln.Close()
	}()

	cleanup := func() {
		ln.Close()
		<-done
	}

	return ln.Addr().String(), cleanup
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", portStr, err)
	}
	return host, port
}
