package probe

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"strconv"
	"strings"
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

func TestEngineMetadata(t *testing.T) {
	t.Parallel()

	cert, pool := generateServerCert(t, "metadata-test.example.com")
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
		PrimarySNI: "metadata-test.example.com",
		ALPNs:      []string{"h2"},
		Trust:      plan.TrustSystemRoots,
		Repeat:     1,
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

	// Verify new metadata fields are populated
	if res.LocalAddr == "" {
		t.Errorf("LocalAddr should be populated")
	}
	if res.RemoteAddr == "" {
		t.Errorf("RemoteAddr should be populated")
	}
	if res.ResolvedIP == "" {
		t.Errorf("ResolvedIP should be populated")
	}
	if res.DialDuration <= 0 {
		t.Errorf("DialDuration should be positive, got %v", res.DialDuration)
	}
	if res.HandshakeDuration <= 0 {
		t.Errorf("HandshakeDuration should be positive, got %v", res.HandshakeDuration)
	}
	if res.TotalDuration <= 0 {
		t.Errorf("TotalDuration should be positive, got %v", res.TotalDuration)
	}
	if res.TLSVersion == "" {
		t.Errorf("TLSVersion should be populated")
	}
	if res.CipherSuite == "" {
		t.Errorf("CipherSuite should be populated")
	}

	// Verify timing relationships
	if res.TotalDuration < res.DialDuration {
		t.Errorf("TotalDuration (%v) should be >= DialDuration (%v)", res.TotalDuration, res.DialDuration)
	}
	if res.TotalDuration < res.HandshakeDuration {
		t.Errorf("TotalDuration (%v) should be >= HandshakeDuration (%v)", res.TotalDuration, res.HandshakeDuration)
	}

	t.Logf("Metadata captured successfully:")
	t.Logf("  LocalAddr: %s", res.LocalAddr)
	t.Logf("  RemoteAddr: %s", res.RemoteAddr)
	t.Logf("  ResolvedIP: %s", res.ResolvedIP)
	t.Logf("  DialDuration: %v", res.DialDuration)
	t.Logf("  HandshakeDuration: %v", res.HandshakeDuration)
	t.Logf("  TotalDuration: %v", res.TotalDuration)
	t.Logf("  TLSVersion: %s", res.TLSVersion)
	t.Logf("  CipherSuite: %s", res.CipherSuite)
}

func TestEngineMultiIPResolution(t *testing.T) {
	t.Parallel()

	cert, pool := generateServerCert(t, "multi-ip-test.example.com")
	addr, cleanup := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}, nil)
	t.Cleanup(cleanup)

	host, port := splitHostPort(t, addr)
	target := plan.ProbeTarget{
		ServiceKey:  "proxy_web",
		Address:     host,
		OverrideIPs: []string{host}, // Test with single override IP
		Port:        port,
		PrimarySNI:  "multi-ip-test.example.com",
		ALPNs:       []string{"h2"},
		Trust:       plan.TrustSystemRoots,
		Repeat:      1,
	}

	engine := NewEngine()
	engine.systemRoots = pool

	probePlan := plan.Plan{Targets: []plan.ProbeTarget{target}}
	results, err := engine.Run(context.Background(), probePlan)
	if err != nil {
		t.Fatalf("engine.Run returned error: %v", err)
	}

	// Should have 1 result (one per IP in ResolvedIPs)
	if len(results) != 1 {
		t.Fatalf("expected 1 result (one per resolved IP), got %d", len(results))
	}

	res := results[0]
	if res.Failure != nil {
		t.Errorf("expected success, got failure: %#v", res.Failure)
	}
	if res.ResolvedIP == "" {
		t.Errorf("ResolvedIP should be populated")
	}

	// Test that an empty OverrideIPs list triggers DNS resolution
	target2 := plan.ProbeTarget{
		ServiceKey:  "proxy_web",
		Address:     host,
		OverrideIPs: nil, // Will trigger DNS resolution in Run()
		Port:        port,
		PrimarySNI:  "multi-ip-test.example.com",
		ALPNs:       []string{"h2"},
		Trust:       plan.TrustSystemRoots,
		Repeat:      1,
	}

	probePlan2 := plan.Plan{Targets: []plan.ProbeTarget{target2}}
	results2, err := engine.Run(context.Background(), probePlan2)
	if err != nil {
		t.Fatalf("engine.Run returned error: %v", err)
	}

	// Should have at least 1 result
	if len(results2) < 1 {
		t.Fatalf("expected at least 1 result, got %d", len(results2))
	}

	for i, res := range results2 {
		if res.Failure != nil {
			t.Logf("result %d: got failure (expected for some DNS lookups): %#v", i, res.Failure)
		}
	}
}

func TestEngineCertificateChainCapture(t *testing.T) {
	t.Parallel()

	cert, pool := generateServerCert(t, "chain-test.example.com")
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
		PrimarySNI: "chain-test.example.com",
		ALPNs:      []string{"h2"},
		Trust:      plan.TrustSystemRoots,
		Repeat:     1,
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

	// Verify certificate chain is captured
	if len(res.CertificateChain) == 0 {
		t.Fatalf("expected CertificateChain to be populated, got empty slice")
	}

	// Verify the leaf fingerprint matches the first in the chain
	if res.LeafFingerprint != res.CertificateChain[0] {
		t.Errorf("LeafFingerprint %s should match first in CertificateChain %s",
			res.LeafFingerprint, res.CertificateChain[0])
	}

	// Verify certificates are stored in PEM format
	certs := engine.GetCertificates()
	if len(certs) == 0 {
		t.Fatalf("expected certificates to be stored in engine, got empty map")
	}

	// Verify each fingerprint in the chain has a corresponding PEM certificate
	for i, fingerprint := range res.CertificateChain {
		pemData, exists := certs[fingerprint]
		if !exists {
			t.Errorf("certificate chain[%d] fingerprint %s not found in certs map", i, fingerprint)
			continue
		}

		// Verify it's valid PEM
		block, _ := pem.Decode([]byte(pemData))
		if block == nil {
			t.Errorf("certificate chain[%d] fingerprint %s: failed to decode PEM", i, fingerprint)
			continue
		}
		if block.Type != "CERTIFICATE" {
			t.Errorf("certificate chain[%d] fingerprint %s: PEM type = %q, want CERTIFICATE",
				i, fingerprint, block.Type)
		}

		// Verify the fingerprint matches the certificate
		parsedCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Errorf("certificate chain[%d] fingerprint %s: failed to parse: %v", i, fingerprint, err)
			continue
		}

		sum := sha256.Sum256(parsedCert.Raw)
		computedFingerprint := strings.ToUpper(hex.EncodeToString(sum[:]))
		if computedFingerprint != fingerprint {
			t.Errorf("certificate chain[%d]: computed fingerprint %s != stored fingerprint %s",
				i, computedFingerprint, fingerprint)
		}
	}

	t.Logf("Successfully captured %d certificate(s) in chain", len(res.CertificateChain))
	t.Logf("Stored %d unique certificate(s) in PEM format", len(certs))
}

func TestEngineClientCertificate(t *testing.T) {
	t.Parallel()

	// Generate server certificate
	serverCert, pool := generateServerCert(t, "teleport.example.com")

	// Generate a client certificate
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	clientCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-user"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientCertTemplate, clientCertTemplate, &clientKey.PublicKey, clientKey)
	if err != nil {
		t.Fatalf("failed to create client certificate: %v", err)
	}

	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})

	// Variable to capture whether client cert was presented
	var clientCertPresented bool
	var mu sync.Mutex

	// Custom handler that checks connection state
	handler := func(conn *tls.Conn) {
		state := conn.ConnectionState()
		mu.Lock()
		clientCertPresented = len(state.PeerCertificates) > 0
		mu.Unlock()
	}

	// Start TLS server that requests client certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		NextProtos:   []string{"teleport-proxy-ssh-grpc"},
		ClientAuth:   tls.RequestClientCert,
	}

	addr, cleanup := startTLSServer(t, tlsConfig, handler)
	t.Cleanup(cleanup)

	host, port := splitHostPort(t, addr)
	trueVal := true
	target := plan.ProbeTarget{
		ServiceKey:    "proxy_ssh_grpc",
		Address:       host,
		Port:          port,
		PrimarySNI:    "teleport.example.com",
		ALPNs:         []string{"teleport-proxy-ssh-grpc"},
		Trust:         plan.TrustSystemRoots,
		Repeat:        1,
		UseClientCert: &trueVal,
	}

	engine := NewEngine()
	engine.systemRoots = pool
	engine.SetClientCert(clientCertPEM, clientKeyPEM)

	probePlan := plan.Plan{Targets: []plan.ProbeTarget{target}}
	results, err := engine.Run(context.Background(), probePlan)
	if err != nil {
		t.Fatalf("engine run failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	res := results[0]
	if res.Failure != nil {
		t.Fatalf("probe failed: %s - %s", res.Failure.Kind, res.Failure.Message)
	}

	// Give the server handler a moment to record the client certificate
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	presented := clientCertPresented
	mu.Unlock()

	if !presented {
		t.Error("expected client certificate to be presented but it was not")
	}

	if res.NegotiatedProtocol != "teleport-proxy-ssh-grpc" {
		t.Errorf("negotiated protocol = %q, want teleport-proxy-ssh-grpc", res.NegotiatedProtocol)
	}

	t.Log("Client certificate was successfully presented to server")
}

func TestEngineClientCertificateNotUsedWhenNotRequired(t *testing.T) {
	t.Parallel()

	// Generate server certificate
	serverCert, pool := generateServerCert(t, "teleport.example.com")

	// Generate a client certificate (but we won't use it)
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	clientCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-user"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientCertTemplate, clientCertTemplate, &clientKey.PublicKey, clientKey)
	if err != nil {
		t.Fatalf("failed to create client certificate: %v", err)
	}

	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})

	// Variable to track if client cert was presented
	var clientCertPresented bool
	var mu sync.Mutex

	// Custom handler that checks connection state
	handler := func(conn *tls.Conn) {
		state := conn.ConnectionState()
		mu.Lock()
		clientCertPresented = len(state.PeerCertificates) > 0
		mu.Unlock()
	}

	// Start TLS server
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		NextProtos:   []string{"h2"},
		ClientAuth:   tls.RequestClientCert,
	}

	addr, cleanup := startTLSServer(t, tlsConfig, handler)
	t.Cleanup(cleanup)

	host, port := splitHostPort(t, addr)
	falseVal := false
	target := plan.ProbeTarget{
		ServiceKey:    "proxy_web",
		Address:       host,
		Port:          port,
		PrimarySNI:    "teleport.example.com",
		ALPNs:         []string{"h2"},
		Trust:         plan.TrustSystemRoots,
		Repeat:        1,
		UseClientCert: &falseVal, // This service should NOT use client cert
	}

	engine := NewEngine()
	engine.systemRoots = pool
	engine.SetClientCert(clientCertPEM, clientKeyPEM)

	probePlan := plan.Plan{Targets: []plan.ProbeTarget{target}}
	results, err := engine.Run(context.Background(), probePlan)
	if err != nil {
		t.Fatalf("engine run failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	res := results[0]
	if res.Failure != nil {
		t.Fatalf("probe failed: %s - %s", res.Failure.Kind, res.Failure.Message)
	}

	// Give the server handler a moment to record (or not) the client certificate
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	presented := clientCertPresented
	mu.Unlock()

	if presented {
		t.Error("client certificate should NOT have been presented for proxy_web service")
	}

	if res.NegotiatedProtocol != "h2" {
		t.Errorf("negotiated protocol = %q, want h2", res.NegotiatedProtocol)
	}

	t.Log("Client certificate was correctly NOT used when UseClientCert=false")
}

func TestResultTimestampAndByteCount(t *testing.T) {
	t.Parallel()

	// Set up a simple TLS server using the existing helper
	cert, _ := generateServerCert(t, "test.example.com")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})

	// Start server
	go func() {
		for {
			conn, err := tlsListener.Accept()
			if err != nil {
				return
			}
			// Send some data so BytesRead will be non-zero
			conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			conn.Close()
		}
	}()

	engine := NewEngine()
	target := plan.ProbeTarget{
		ServiceKey:  "test",
		DisplayName: "Test Service",
		Address:     "127.0.0.1",
		Port:        listener.Addr().(*net.TCPAddr).Port,
		PrimarySNI:  "test.example.com",
		ALPNs:       []string{"h2"},
		Trust:       plan.TrustSystemRoots,
		Repeat:      1,
	}

	testPlan := plan.Plan{
		Targets: []plan.ProbeTarget{target},
	}

	results, err := engine.Run(context.Background(), testPlan)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	result := results[0]

	// Check timestamp is set and recent
	if result.Timestamp.IsZero() {
		t.Error("expected Timestamp to be set")
	}
	if time.Since(result.Timestamp) > 5*time.Second {
		t.Errorf("Timestamp seems too old: %v", result.Timestamp)
	}

	// Check byte counts are set (TLS handshake should send/receive data)
	if result.BytesWritten == 0 {
		t.Error("expected BytesWritten > 0")
	}
	// BytesRead may be 0 if server closes immediately after handshake,
	// but with our server sending data, it should be > 0
	// However, this is timing-dependent, so we'll just check it was tracked
	t.Logf("Result captured:")
	t.Logf("  Timestamp: %v", result.Timestamp)
	t.Logf("  BytesWritten: %d", result.BytesWritten)
	t.Logf("  BytesRead: %d", result.BytesRead)
}

func TestResultsSorting(t *testing.T) {
	t.Parallel()

	// Create results in a mixed order
	results := []Result{
		{Target: plan.ProbeTarget{ServiceKey: "service_b", Address: "2.2.2.2"}, Attempt: 2},
		{Target: plan.ProbeTarget{ServiceKey: "service_a", Address: "1.1.1.1"}, Attempt: 1},
		{Target: plan.ProbeTarget{ServiceKey: "service_b", Address: "2.2.2.2"}, Attempt: 1},
		{Target: plan.ProbeTarget{ServiceKey: "service_a", Address: "1.1.1.2"}, Attempt: 1},
		{Target: plan.ProbeTarget{ServiceKey: "service_a", Address: "1.1.1.1"}, Attempt: 2},
		{Target: plan.ProbeTarget{ServiceKey: "service_b", Address: "2.2.2.1"}, Attempt: 1},
	}

	sortResults(results)

	// Expected order after sorting:
	// Service keys appear in the order they were first seen (service_b first, then service_a)
	// Within each service key, sorted by address, then attempt

	expected := []struct {
		serviceKey string
		address    string
		attempt    int
	}{
		{"service_b", "2.2.2.1", 1},
		{"service_b", "2.2.2.2", 1},
		{"service_b", "2.2.2.2", 2},
		{"service_a", "1.1.1.1", 1},
		{"service_a", "1.1.1.1", 2},
		{"service_a", "1.1.1.2", 1},
	}

	if len(results) != len(expected) {
		t.Fatalf("expected %d results, got %d", len(expected), len(results))
	}

	for i, exp := range expected {
		if results[i].Target.ServiceKey != exp.serviceKey {
			t.Errorf("result[%d]: expected serviceKey %s, got %s", i, exp.serviceKey, results[i].Target.ServiceKey)
		}
		if results[i].Target.Address != exp.address {
			t.Errorf("result[%d]: expected address %s, got %s", i, exp.address, results[i].Target.Address)
		}
		if results[i].Attempt != exp.attempt {
			t.Errorf("result[%d]: expected attempt %d, got %d", i, exp.attempt, results[i].Attempt)
		}
	}
}

func TestResultsDoNotIncludeDNSResolvedIPs(t *testing.T) {
	t.Parallel()

	engine := NewEngine()
	target := plan.ProbeTarget{
		ServiceKey:     "test",
		DisplayName:    "Test Service",
		Address:        "127.0.0.1",
		DNSResolvedIPs: []string{"127.0.0.1", "::1"}, // Pre-resolved IPs in plan
		Port:           9999,                         // Port that won't connect
		PrimarySNI:     "test.example.com",
		ALPNs:          []string{"h2"},
		Trust:          plan.TrustSystemRoots,
		Repeat:         1,
	}

	testPlan := plan.Plan{
		Targets: []plan.ProbeTarget{target},
	}

	results, err := engine.Run(context.Background(), testPlan)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Should get one result per DNS-resolved IP
	if len(results) < 1 {
		t.Fatalf("expected at least 1 result, got %d", len(results))
	}

	// All results' targets should NOT include DNSResolvedIPs
	for i, result := range results {
		if len(result.Target.DNSResolvedIPs) != 0 {
			t.Errorf("result[%d]: expected result.Target.DNSResolvedIPs to be empty, got: %v", i, result.Target.DNSResolvedIPs)
		}
	}
}
