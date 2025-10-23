package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/programmerq/tlscheck/internal/plan"
)

// Dialer defines the minimal interface required for TCP connections.
// net.Dialer satisfies this interface.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Engine executes probe targets against a Teleport proxy.
type Engine struct {
	Dialer      Dialer
	Timeout     time.Duration
	RootCAs     *x509.CertPool
	systemRoots *x509.CertPool
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

// Result captures the outcome of a single probe attempt.
type Result struct {
	Target             plan.ProbeTarget `json:"target"`
	Attempt            int              `json:"attempt"`
	RemoteAddr         string           `json:"remote_addr,omitempty"`
	NegotiatedProtocol string           `json:"negotiated_protocol,omitempty"`
	LeafSubject        string           `json:"leaf_subject,omitempty"`
	LeafIssuer         string           `json:"leaf_issuer,omitempty"`
	LeafSANs           []string         `json:"leaf_sans,omitempty"`
	LeafFingerprint    string           `json:"leaf_fingerprint,omitempty"`
	Failure            *Failure         `json:"failure,omitempty"`
}

// Failure describes a classified probe error.
type Failure struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// NewEngine constructs an Engine with sensible defaults.
func NewEngine() *Engine {
	eng := &Engine{
		Dialer:  &net.Dialer{Timeout: 10 * time.Second},
		Timeout: 15 * time.Second,
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

	results := make([]Result, 0)
	for _, target := range p.Targets {
		repeat := target.Repeat
		if repeat <= 0 {
			repeat = 1
		}
		for attempt := 1; attempt <= repeat; attempt++ {
			res := e.probeOnce(ctx, target, attempt)
			results = append(results, res)
		}
	}
	return results, nil
}

func (e *Engine) probeOnce(ctx context.Context, target plan.ProbeTarget, attempt int) Result {
	res := Result{Target: target, Attempt: attempt}

	dialCtx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()

	addr := net.JoinHostPort(target.Address, fmt.Sprintf("%d", target.Port))
	conn, err := e.Dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		res.Failure = &Failure{Kind: classifyDialError(err), Message: err.Error()}
		return res
	}
	defer conn.Close()
	res.RemoteAddr = conn.RemoteAddr().String()

	tlsCfg := &tls.Config{
		ServerName:         target.PrimarySNI,
		NextProtos:         target.ALPNs,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}

	tlsConn := tls.Client(conn, tlsCfg)
	defer tlsConn.Close()

	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		state := tlsConn.ConnectionState()
		e.captureCertificateDetails(&res, state)
		kind := "handshake_failed"
		if strings.Contains(err.Error(), "no application protocol") {
			kind = "alpn_mismatch"
		}
		res.Failure = &Failure{Kind: kind, Message: err.Error()}
		return res
	}

	state := tlsConn.ConnectionState()
	res.NegotiatedProtocol = state.NegotiatedProtocol

	e.captureCertificateDetails(&res, state)

	if len(target.ALPNs) > 0 {
		if state.NegotiatedProtocol == "" {
			res.Failure = &Failure{Kind: "alpn_mismatch", Message: "server did not negotiate ALPN"}
			return res
		}
		if !contains(target.ALPNs, state.NegotiatedProtocol) {
			res.Failure = &Failure{Kind: "alpn_mismatch", Message: fmt.Sprintf("negotiated %s", state.NegotiatedProtocol)}
			return res
		}
	}

	if err := e.verifyPeerCertificate(state, target); err != nil {
		kind := "untrusted_cert"
		if errors.Is(err, errHostCATrustUnavailable) {
			kind = "host_ca_unavailable"
		}
		res.Failure = &Failure{Kind: kind, Message: err.Error()}
		return res
	}

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
