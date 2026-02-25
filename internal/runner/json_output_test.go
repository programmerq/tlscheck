package runner

import (
	"context"
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

	opts := config.Options{
		PublicAddr: "test.example.com",
		Repeat:     1,
		ClientCert: &config.ClientCertInfo{Fingerprint: clientCertFP},
	}

	exec, _ := Execute(context.Background(), opts, PlanBuilderFunc(plan.Build), engine)

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
