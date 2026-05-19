package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/programmerq/tlscheck/internal/log"
	"github.com/programmerq/tlscheck/internal/plan"
)

// Dialer defines the minimal interface required for TCP connections.
// net.Dialer satisfies this interface.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Engine executes probe targets against a Teleport proxy.
type Engine struct {
	Dialer                Dialer
	Timeout               time.Duration
	RootCAs               *x509.CertPool
	systemRoots           *x509.CertPool
	certs                 map[string]*CertInfo // fingerprint -> expanded cert info
	certsMu               sync.Mutex
	ClientCertPEM         []byte
	ClientKeyPEM          []byte
	clientCertFingerprint string
}

// GetRootCAs returns the certificate pool currently configured for the engine.
func (e *Engine) GetRootCAs() *x509.CertPool {
	if e == nil {
		return nil
	}
	return e.RootCAs
}

// SetRootCAs updates the certificate pool used for TLS handshakes.
func (e *Engine) SetRootCAs(pool *x509.CertPool) {
	if e == nil {
		return
	}
	e.RootCAs = pool
}

// SetClientCert configures the client certificate and key used for mutual TLS.
// The cert/key pair is validated up front; if they cannot form a valid TLS
// certificate the call is a no-op so clientCertFingerprint is only ever non-empty
// when the pair is actually usable.
func (e *Engine) SetClientCert(certPEM, keyPEM []byte) {
	if e == nil {
		return
	}
	// Pre-validate that the cert and key can form a valid TLS certificate pair.
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return
	}
	e.ClientCertPEM = certPEM
	e.ClientKeyPEM = keyPEM

	// Calculate and store the client cert fingerprint
	if len(certPEM) > 0 {
		block, _ := pem.Decode(certPEM)
		if block != nil && block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				sum := sha256.Sum256(cert.Raw)
				e.clientCertFingerprint = strings.ToUpper(hex.EncodeToString(sum[:]))
			}
		}
	}
}

// GetCertificates returns the map of certificates encountered during probing.
// The map keys are SHA-256 fingerprints (uppercase hex), and the values are expanded CertInfo objects.
func (e *Engine) GetCertificates() map[string]*CertInfo {
	if e == nil {
		return nil
	}
	e.certsMu.Lock()
	defer e.certsMu.Unlock()

	// Return a copy to prevent external modifications
	result := make(map[string]*CertInfo, len(e.certs))
	for k, v := range e.certs {
		// Make a copy of the CertInfo
		infoCopy := *v
		result[k] = &infoCopy
	}
	return result
}

// GetClientCertificates returns the client certificate if configured.
// The map keys are SHA-256 fingerprints (uppercase hex), and the values are expanded CertInfo objects.
func (e *Engine) GetClientCertificates() map[string]*CertInfo {
	if e == nil || len(e.ClientCertPEM) == 0 || e.clientCertFingerprint == "" {
		return nil
	}

	info, err := ParseCertFromPEM(e.ClientCertPEM)
	if err != nil || info == nil {
		return nil
	}
	info.SetSource(CertSourceClient)

	return map[string]*CertInfo{
		e.clientCertFingerprint: info,
	}
}

// Result captures the outcome of a single probe attempt.
type Result struct {
	Target                plan.ProbeTarget `json:"target" jsonschema:"description=The probe target configuration that was tested"`
	Attempt               int              `json:"attempt" jsonschema:"description=Attempt number for this target (starts at 1)"`
	Timestamp             time.Time        `json:"timestamp" jsonschema:"description=Timestamp when this probe was executed (UTC)"`
	LocalAddr             string           `json:"local_addr,omitempty" jsonschema:"description=Local socket address (IP:port) used for the connection"`
	RemoteAddr            string           `json:"remote_addr,omitempty" jsonschema:"description=Remote socket address (IP:port) that was connected to"`
	ResolvedIP            string           `json:"resolved_ip,omitempty" jsonschema:"description=IP address extracted from the remote address"`
	BytesWritten          int64            `json:"bytes_written,omitempty" jsonschema:"description=Total bytes written during the TLS handshake"`
	BytesRead             int64            `json:"bytes_read,omitempty" jsonschema:"description=Total bytes read during the TLS handshake"`
	DialDuration          time.Duration    `json:"dial_duration_ns,omitempty" jsonschema:"description=Time taken to establish TCP connection in nanoseconds"`
	HandshakeDuration     time.Duration    `json:"handshake_duration_ns,omitempty" jsonschema:"description=Time taken to complete TLS handshake in nanoseconds"`
	TotalDuration         time.Duration    `json:"total_duration_ns,omitempty" jsonschema:"description=Total time from start to finish in nanoseconds"`
	TLSVersion            string           `json:"tls_version,omitempty" jsonschema:"description=Negotiated TLS protocol version (e.g. TLS 1.3)"`
	CipherSuite           string           `json:"cipher_suite,omitempty" jsonschema:"description=Negotiated TLS cipher suite name"`
	NegotiatedProtocol    string           `json:"negotiated_protocol,omitempty" jsonschema:"description=ALPN protocol that was successfully negotiated"`
	LeafSubject           string           `json:"leaf_subject,omitempty" jsonschema:"description=Subject DN of the server's leaf certificate"`
	LeafIssuer            string           `json:"leaf_issuer,omitempty" jsonschema:"description=Issuer DN of the server's leaf certificate"`
	LeafSANs              []string         `json:"leaf_sans,omitempty" jsonschema:"description=Subject Alternative Names from the server's leaf certificate (DNS names, IPs, URIs)"`
	LeafFingerprint       string           `json:"leaf_fingerprint,omitempty" jsonschema:"description=SHA-256 fingerprint of the server's leaf certificate (uppercase hex)"`
	CertificateChain      []string         `json:"certificate_chain,omitempty" jsonschema:"description=Ordered list of certificate fingerprints in the chain (leaf first)"`
	ClientCertFingerprint string           `json:"client_cert_fingerprint,omitempty" jsonschema:"description=SHA-256 fingerprint of the client certificate used for mutual TLS (if any)"`
	Failure               *Failure         `json:"failure,omitempty" jsonschema:"description=Failure details if the probe did not succeed"`
}

// Failure describes a classified probe error.
type Failure struct {
	Kind    string `json:"kind" jsonschema:"description=Classification of the failure (e.g. timeout, alpn_mismatch, untrusted_cert, host_ca_unavailable)"`
	Message string `json:"message" jsonschema:"description=Human-readable error message describing what went wrong"`
}

// NewEngine constructs an Engine with sensible defaults.
func NewEngine() *Engine {
	eng := &Engine{
		Dialer:  &net.Dialer{Timeout: 10 * time.Second},
		Timeout: 15 * time.Second,
		certs:   make(map[string]*CertInfo),
	}

	if pool, err := x509.SystemCertPool(); err == nil {
		eng.systemRoots = pool
	}
	if eng.systemRoots == nil {
		eng.systemRoots = x509.NewCertPool()
	}

	return eng
}

var errHostCATrustUnavailable = errors.New("host CA trust not configured")

// Run executes the provided plan and returns probe results.
func (e *Engine) Run(ctx context.Context, p plan.Plan) ([]Result, error) {
	if e.Dialer == nil {
		return nil, fmt.Errorf("probe engine requires a dialer")
	}

	log.Printf("starting probe execution with %d targets", len(p.Targets))
	results := make([]Result, 0)
	for _, target := range p.Targets {
		// Determine which IPs to probe
		ips := target.OverrideIPs
		if len(ips) == 0 {
			// No override IPs, use DNS-resolved IPs from the plan
			ips = target.DNSResolvedIPs
			if len(ips) == 0 {
				// No DNS IPs (e.g., if address is already an IP or DNS failed), use the address as-is
				ips = []string{target.Address}
			}
		}

		log.Printf("probing service %s (%s) on %s:%d with %d IP(s): %v",
			target.ServiceKey, target.DisplayName, target.Address, target.Port, len(ips), ips)

		// Probe each IP
		for _, ip := range ips {
			// Create a copy of the target for this specific IP
			// Remove DNSResolvedIPs from the copy to avoid duplication in results
			ipTarget := target
			ipTarget.DNSResolvedIPs = nil
			ipTarget.Address = ip

			repeat := ipTarget.Repeat
			if repeat <= 0 {
				repeat = 1
			}
			for attempt := 1; attempt <= repeat; attempt++ {
				res := e.probeOnce(ctx, ipTarget, attempt)
				results = append(results, res)
			}
		}
	}

	// Sort results: group by service_key, then by address, then by attempt
	sortResults(results)

	log.Printf("probe execution complete: %d results", len(results))
	return results, nil
}

func (e *Engine) probeOnce(ctx context.Context, target plan.ProbeTarget, attempt int) Result {
	startTime := time.Now()
	res := Result{
		Target:    target,
		Attempt:   attempt,
		Timestamp: startTime.UTC(),
	}

	log.Printf("[%s] attempt %d: dialing %s:%d (SNI: %s, ALPN: %v, proxy: %v)",
		target.ServiceKey, attempt, target.Address, target.Port,
		target.PrimarySNI, target.ALPNs, target.UseProxy)

	// If the target is configured to use a client certificate and we have one, record the
	// fingerprint immediately so it appears in the result regardless of whether the connection
	// ultimately succeeds or fails.
	if target.UseClientCert != nil && *target.UseClientCert && e.clientCertFingerprint != "" {
		res.ClientCertFingerprint = e.clientCertFingerprint
	}

	dialCtx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()

	// Select the appropriate dialer based on whether proxy is requested
	dialer := e.Dialer
	if target.UseProxy && target.ProxyURL != "" {
		log.Printf("[%s] using proxy: %s", target.ServiceKey, log.SanitizeURL(target.ProxyURL))
		proxyDialer, err := NewProxyDialer(target.ProxyURL, e.Timeout)
		if err != nil {
			log.Printf("[%s] proxy config error: %v", target.ServiceKey, err)
			res.TotalDuration = time.Since(startTime)
			res.Failure = &Failure{Kind: "proxy_config_error", Message: fmt.Sprintf("invalid proxy configuration: %v", err)}
			return res
		}
		dialer = proxyDialer
	}

	addr := net.JoinHostPort(target.Address, fmt.Sprintf("%d", target.Port))
	dialStart := time.Now()
	log.Printf("[%s] dialing TCP connection to %s", target.ServiceKey, addr)
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	dialEnd := time.Now()
	res.DialDuration = dialEnd.Sub(dialStart)
	if err != nil {
		log.Printf("[%s] TCP dial failed after %v: %v", target.ServiceKey, res.DialDuration, err)
		res.TotalDuration = time.Since(startTime)
		res.Failure = &Failure{Kind: classifyDialError(err), Message: err.Error()}
		return res
	}
	defer conn.Close()
	log.Printf("[%s] TCP connection established in %v (local: %s, remote: %s)",
		target.ServiceKey, res.DialDuration, conn.LocalAddr(), conn.RemoteAddr())
	res.RemoteAddr = conn.RemoteAddr().String()
	res.LocalAddr = conn.LocalAddr().String()

	if host, _, err := net.SplitHostPort(res.RemoteAddr); err == nil {
		res.ResolvedIP = host
	}

	tlsCfg := &tls.Config{
		ServerName:         target.PrimarySNI,
		NextProtos:         target.ALPNs,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}

	// If the target requires a client certificate and we have one available, configure it
	if target.UseClientCert != nil && *target.UseClientCert && len(e.ClientCertPEM) > 0 && len(e.ClientKeyPEM) > 0 {
		cert, err := tls.X509KeyPair(e.ClientCertPEM, e.ClientKeyPEM)
		if err == nil {
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
	}

	// Wrap the connection to track bytes
	trackedConn := &byteCountingConn{Conn: conn}
	tlsConn := tls.Client(trackedConn, tlsCfg)
	defer tlsConn.Close()

	handshakeStart := time.Now()
	log.Printf("[%s] starting TLS handshake", target.ServiceKey)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		log.Printf("[%s] TLS handshake failed after %v: %v", target.ServiceKey, time.Since(handshakeStart), err)
		res.HandshakeDuration = time.Since(handshakeStart)
		res.TotalDuration = time.Since(startTime)
		res.BytesWritten = trackedConn.BytesWritten()
		res.BytesRead = trackedConn.BytesRead()
		state := tlsConn.ConnectionState()
		e.captureCertificateDetails(&res, state)
		e.captureTLSDetails(&res, state)
		kind := "handshake_failed"
		if strings.Contains(err.Error(), "no application protocol") {
			kind = "alpn_mismatch"
		}
		res.Failure = &Failure{Kind: kind, Message: err.Error()}
		return res
	}
	res.HandshakeDuration = time.Since(handshakeStart)
	log.Printf("[%s] TLS handshake succeeded in %v", target.ServiceKey, res.HandshakeDuration)

	state := tlsConn.ConnectionState()
	res.NegotiatedProtocol = state.NegotiatedProtocol
	log.Printf("[%s] negotiated protocol: %s, TLS version: %s, cipher: %s",
		target.ServiceKey, state.NegotiatedProtocol,
		tlsVersionString(state.Version), tls.CipherSuiteName(state.CipherSuite))

	e.captureCertificateDetails(&res, state)
	e.captureTLSDetails(&res, state)

	if len(target.ALPNs) > 0 {
		if state.NegotiatedProtocol == "" {
			res.TotalDuration = time.Since(startTime)
			res.BytesWritten = trackedConn.BytesWritten()
			res.BytesRead = trackedConn.BytesRead()
			res.Failure = &Failure{Kind: "alpn_mismatch", Message: "server did not negotiate ALPN"}
			return res
		}
		if !contains(target.ALPNs, state.NegotiatedProtocol) {
			res.TotalDuration = time.Since(startTime)
			res.BytesWritten = trackedConn.BytesWritten()
			res.BytesRead = trackedConn.BytesRead()
			res.Failure = &Failure{Kind: "alpn_mismatch", Message: fmt.Sprintf("negotiated %s", state.NegotiatedProtocol)}
			return res
		}
	}

	if err := e.verifyPeerCertificate(state, target); err != nil {
		kind := "untrusted_cert"
		if errors.Is(err, errHostCATrustUnavailable) {
			kind = "host_ca_unavailable"
		}
		log.Printf("[%s] certificate verification failed: %v", target.ServiceKey, err)
		res.TotalDuration = time.Since(startTime)
		res.BytesWritten = trackedConn.BytesWritten()
		res.BytesRead = trackedConn.BytesRead()
		res.Failure = &Failure{Kind: kind, Message: err.Error()}
		return res
	}

	res.TotalDuration = time.Since(startTime)
	res.BytesWritten = trackedConn.BytesWritten()
	res.BytesRead = trackedConn.BytesRead()
	log.Printf("[%s] probe succeeded in %v (bytes read: %d, written: %d)",
		target.ServiceKey, res.TotalDuration, res.BytesRead, res.BytesWritten)
	return res
}

func (e *Engine) captureCertificateDetails(res *Result, state tls.ConnectionState) {
	if len(state.PeerCertificates) == 0 {
		return
	}

	leaf := state.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	res.LeafFingerprint = strings.ToUpper(hex.EncodeToString(sum[:]))
	res.LeafSubject = leaf.Subject.String()
	res.LeafIssuer = leaf.Issuer.String()

	sans := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.URIs))
	sans = append(sans, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, uri := range leaf.URIs {
		sans = append(sans, uri.String())
	}
	if len(sans) > 0 {
		res.LeafSANs = sans
	}

	// Capture the full certificate chain as fingerprints and store expanded CertInfo
	chain := make([]string, 0, len(state.PeerCertificates))
	e.certsMu.Lock()
	defer e.certsMu.Unlock()

	// Build fingerprint map for issuer fingerprint lookup
	fingerprintMap := make(map[string]string) // subject key id -> fingerprint
	for _, cert := range state.PeerCertificates {
		certSum := sha256.Sum256(cert.Raw)
		fingerprint := strings.ToUpper(hex.EncodeToString(certSum[:]))
		if len(cert.SubjectKeyId) > 0 {
			fingerprintMap[formatKeyID(cert.SubjectKeyId)] = fingerprint
		}
	}

	for _, cert := range state.PeerCertificates {
		certSum := sha256.Sum256(cert.Raw)
		fingerprint := strings.ToUpper(hex.EncodeToString(certSum[:]))
		chain = append(chain, fingerprint)

		// Store expanded certificate info if we haven't seen it before
		if _, exists := e.certs[fingerprint]; !exists {
			pemBlock := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}
			pemData := string(pem.EncodeToMemory(pemBlock))
			info := ParseCertInfo(cert, pemData)
			info.SetSource(CertSourceServer)

			// Set issuer fingerprint if we have it in the chain
			if len(cert.AuthorityKeyId) > 0 {
				if issuerFP, ok := fingerprintMap[formatKeyID(cert.AuthorityKeyId)]; ok {
					info.SetIssuerFingerprint(issuerFP)
				}
			}

			// Check for MITM suspicion against reference CAs
			referenceCAs := GetReferenceCAs()
			if trustInfo := CheckMITMSuspicion(info, referenceCAs); trustInfo != nil {
				info.TrustStatus = trustInfo
			}

			e.certs[fingerprint] = info
		}
	}
	if len(chain) > 0 {
		res.CertificateChain = chain
	}
}

func (e *Engine) captureTLSDetails(res *Result, state tls.ConnectionState) {
	res.TLSVersion = tlsVersionString(state.Version)
	res.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
}

func (e *Engine) verifyPeerCertificate(state tls.ConnectionState, target plan.ProbeTarget) error {
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("server presented no certificates")
	}

	leaf := state.PeerCertificates[0]
	opts := x509.VerifyOptions{
		DNSName: target.PrimarySNI,
	}

	if len(state.PeerCertificates) > 1 {
		opts.Intermediates = x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
	}

	switch target.Trust {
	case plan.TrustHostCA:
		if e.RootCAs == nil || len(e.RootCAs.Subjects()) == 0 {
			return errHostCATrustUnavailable
		}
		opts.Roots = e.RootCAs
	default:
		if e.systemRoots != nil && len(e.systemRoots.Subjects()) > 0 {
			opts.Roots = e.systemRoots
		}
	}

	if _, err := leaf.Verify(opts); err != nil {
		return err
	}

	return nil
}

func classifyDialError(err error) string {
	if ne, ok := err.(net.Error); ok {
		if ne.Timeout() {
			return "timeout"
		}
		// net.Error.Temporary is deprecated and no longer reliable for
		// classifying errors. Prefer explicit checks for known error types
		// if we need to add more buckets in the future.
	}
	return "proxy_connect_failed"
}

func contains(values []string, needle string) bool {
	for _, v := range values {
		if v == needle {
			return true
		}
	}
	return false
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04X", version)
	}
}

// byteCountingConn wraps a net.Conn to track bytes read and written.
type byteCountingConn struct {
	net.Conn
	bytesRead    int64
	bytesWritten int64
	mu           sync.Mutex
}

func (c *byteCountingConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	c.mu.Lock()
	c.bytesRead += int64(n)
	c.mu.Unlock()
	return n, err
}

func (c *byteCountingConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	c.mu.Lock()
	c.bytesWritten += int64(n)
	c.mu.Unlock()
	return n, err
}

func (c *byteCountingConn) BytesRead() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytesRead
}

func (c *byteCountingConn) BytesWritten() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytesWritten
}

// sortResults sorts results by service_key (grouped together), then by address, then by attempt.
func sortResults(results []Result) {
	// Create a map to track the order of service keys as they appear
	serviceOrder := make(map[string]int)
	orderIndex := 0
	for _, r := range results {
		if _, exists := serviceOrder[r.Target.ServiceKey]; !exists {
			serviceOrder[r.Target.ServiceKey] = orderIndex
			orderIndex++
		}
	}

	// Sort using the built-in sort.Slice for O(n log n) performance
	sort.Slice(results, func(i, j int) bool {
		a, b := results[i], results[j]

		// First compare by service_key order (as they appear in the original list)
		aOrder, bOrder := serviceOrder[a.Target.ServiceKey], serviceOrder[b.Target.ServiceKey]
		if aOrder != bOrder {
			return aOrder < bOrder
		}

		// Service keys are the same, compare by address
		if a.Target.Address != b.Target.Address {
			return a.Target.Address < b.Target.Address
		}

		// Addresses are the same, compare by attempt
		return a.Attempt < b.Attempt
	})
}
