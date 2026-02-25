package runner

import (
	"context"
	"net"
	"testing"

	"github.com/programmerq/tlscheck/internal/config"
	"github.com/programmerq/tlscheck/internal/discovery"
	"github.com/programmerq/tlscheck/internal/plan"
	"github.com/programmerq/tlscheck/internal/probe"
)

// TestClientCertInJSONOutput verifies that when a client certificate is configured on the
// engine, it appears in the exec.Certs map AND that results for targets with
// UseClientCert=true carry the correct ClientCertFingerprint — even when the TCP
// connection itself fails (no reachable server).
//
// The test is hermetic: it uses a stub builder that emits a single target pointing
// at a closed local port so no real DNS resolution or outbound network calls are made.
func TestClientCertInJSONOutput(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM, err := discovery.GenerateTestCertificate()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	engine := probe.NewEngine()
	engine.SetClientCert(certPEM, keyPEM)

	// Verify the engine exposes the cert.
	clientCerts := engine.GetClientCertificates()
	if len(clientCerts) == 0 {
		t.Fatal("GetClientCertificates returned empty - cert not set on engine")
	}
	var clientCertFP string
	for fp := range clientCerts {
		clientCertFP = fp
	}

	// Bind then immediately close a local port so the probe will fail with
	// "connection refused" rather than hanging on a timeout.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	trueVal := true
	target := plan.ProbeTarget{
		ServiceKey:    "test_service",
		Address:       "127.0.0.1",
		Port:          port,
		PrimarySNI:    "example.com",
		ALPNs:         []string{"h2"},
		Trust:         plan.TrustSystemRoots,
		Repeat:        1,
		UseClientCert: &trueVal,
	}
	builder := &stubBuilder{plan: plan.Plan{Targets: []plan.ProbeTarget{target}}}

	opts := config.Options{
		ClientCert: &config.ClientCertInfo{Fingerprint: clientCertFP},
	}

	exec, err := Execute(context.Background(), opts, builder, engine)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// The client cert must appear in exec.Certs regardless of probe success/failure.
	if len(exec.Certs) == 0 {
		t.Fatal("client cert not in exec.Certs")
	}
	if _, ok := exec.Certs[clientCertFP]; !ok {
		t.Errorf("client cert not found in exec.Certs by fingerprint %s", clientCertFP)
	}

	// Every result whose target has UseClientCert=true must carry the fingerprint, even when
	// the underlying TCP connection failed.
	for _, r := range exec.Results {
		if r.Target.UseClientCert != nil && *r.Target.UseClientCert {
			if r.ClientCertFingerprint == "" {
				t.Errorf("result %s: UseClientCert=true but ClientCertFingerprint is empty",
					r.Target.ServiceKey)
			} else if r.ClientCertFingerprint != clientCertFP {
				t.Errorf("result %s: ClientCertFingerprint = %s, want %s",
					r.Target.ServiceKey, r.ClientCertFingerprint, clientCertFP)
			}
		}
	}
}
