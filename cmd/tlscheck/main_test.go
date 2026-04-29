package main

import (
	stdbytes "bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/programmerq/tlscheck/internal/config"
	"github.com/programmerq/tlscheck/internal/plan"
	"github.com/programmerq/tlscheck/internal/probe"
	"github.com/programmerq/tlscheck/internal/runner"
)

type stubEngine struct {
	received plan.Plan
	results  []probe.Result
	rootCAs  *x509.CertPool
}

func (s *stubEngine) Run(ctx context.Context, p plan.Plan) ([]probe.Result, error) {
	s.received = p
	return s.results, nil
}

func (s *stubEngine) GetRootCAs() *x509.CertPool {
	return s.rootCAs
}

func (s *stubEngine) SetRootCAs(pool *x509.CertPool) {
	s.rootCAs = pool
}

func TestRunExecutesPlanAndEmitsResults(t *testing.T) {
	t.Parallel()

	expectedPlan := plan.Plan{
		Targets: []plan.ProbeTarget{{
			ServiceKey: "proxy_web",
			Address:    "teleport.example.com",
			Port:       443,
			Repeat:     1,
		}},
	}
	expectedResults := []probe.Result{{
		Target:             expectedPlan.Targets[0],
		Attempt:            1,
		NegotiatedProtocol: "h2",
	}}

	pool := x509.NewCertPool()
	engine := &stubEngine{results: expectedResults}
	hostCAPEM := generateHostCAPEM(t)

	deps := dependencies{
		parseArgs: func(args []string, keys []string) (config.Options, bool, error) {
			return config.Options{PublicAddr: "teleport.example.com", OutputFormat: config.OutputFormatJSON}, false, nil
		},
		resolveRuntime: func(ctx context.Context, opts config.Options) (config.Options, error) {
			opts.ClusterName = "example"
			opts.TeleportVersion = "15.3.7"
			opts.Repeat = 1
			opts.WebProxyPort = 443
			opts.TLSRoutingEnabled = true
			opts.HostCAPEM = hostCAPEM
			return opts, nil
		},
		planBuilder: runner.PlanBuilderFunc(func(opts config.Options) (plan.Plan, error) {
			planCopy := expectedPlan
			planCopy.Options = opts
			return planCopy, nil
		}),
		newEngine: func() runner.Engine { return engine },
		systemCertPool: func() (*x509.CertPool, error) {
			return pool, nil
		},
	}

	var stdout stdbytes.Buffer
	var stderr stdbytes.Buffer

	exitCode := run(context.Background(), []string{"--proxy-server", "teleport.example.com"}, &stdout, &stderr, deps)
	if exitCode != 0 {
		t.Fatalf("run returned non-zero exit code: %d (stderr: %s)", exitCode, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr output: %s", stderr.String())
	}

	if engine.rootCAs == nil {
		t.Fatalf("expected engine to receive host CA pool")
	}
	if engine.rootCAs == pool {
		t.Fatalf("expected host CA pool to replace system pool")
	}
	block, _ := pem.Decode(hostCAPEM)
	if block == nil {
		t.Fatalf("failed to decode host CA PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse host CA certificate: %v", err)
	}
	found := false
	for _, subject := range engine.rootCAs.Subjects() {
		if stdbytes.Equal(subject, cert.RawSubject) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected host CA subject to be present in pool")
	}

	if len(engine.received.Targets) != len(expectedPlan.Targets) {
		t.Fatalf("engine received unexpected number of targets: %#v", engine.received.Targets)
	}

	var exec runner.Execution
	if err := json.NewDecoder(&stdout).Decode(&exec); err != nil {
		t.Fatalf("failed to decode execution output: %v", err)
	}

	if len(exec.Results) != len(expectedResults) {
		t.Fatalf("unexpected result count: got %d want %d", len(exec.Results), len(expectedResults))
	}
	if exec.Results[0].NegotiatedProtocol != expectedResults[0].NegotiatedProtocol {
		t.Fatalf("unexpected negotiated protocol: got %q want %q", exec.Results[0].NegotiatedProtocol, expectedResults[0].NegotiatedProtocol)
	}

	if exec.Plan.Targets[0].ServiceKey != expectedPlan.Targets[0].ServiceKey {
		t.Fatalf("unexpected plan output: %#v", exec.Plan.Targets)
	}
}

func generateHostCAPEM(t *testing.T) []byte {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tlscheck test host ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return pem.EncodeToMemory(block)
}

func TestRunWithHTMLOutput(t *testing.T) {
	t.Parallel()

	expectedPlan := plan.Plan{
		Targets: []plan.ProbeTarget{{
			ServiceKey: "proxy_web",
			Address:    "teleport.example.com",
			Port:       443,
			Repeat:     1,
		}},
	}
	expectedResults := []probe.Result{{
		Target:             expectedPlan.Targets[0],
		Attempt:            1,
		NegotiatedProtocol: "h2",
	}}

	engine := &stubEngine{results: expectedResults}

	deps := dependencies{
		parseArgs: func(args []string, keys []string) (config.Options, bool, error) {
			return config.Options{
				PublicAddr:   "teleport.example.com",
				OutputFormat: config.OutputFormatHTML,
			}, false, nil
		},
		resolveRuntime: func(ctx context.Context, opts config.Options) (config.Options, error) {
			opts.ClusterName = "example"
			opts.TeleportVersion = "15.3.7"
			opts.Repeat = 1
			opts.WebProxyPort = 443
			opts.TLSRoutingEnabled = true
			opts.OutputFormat = config.OutputFormatHTML
			return opts, nil
		},
		planBuilder: runner.PlanBuilderFunc(func(opts config.Options) (plan.Plan, error) {
			planCopy := expectedPlan
			planCopy.Options = opts
			return planCopy, nil
		}),
		newEngine: func() runner.Engine { return engine },
		systemCertPool: func() (*x509.CertPool, error) {
			return x509.NewCertPool(), nil
		},
	}

	var stdout stdbytes.Buffer
	var stderr stdbytes.Buffer

	exitCode := run(context.Background(), []string{"--proxy-server", "teleport.example.com", "--output-format", "html"}, &stdout, &stderr, deps)
	if exitCode != 0 {
		t.Fatalf("run returned non-zero exit code: %d (stderr: %s)", exitCode, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr output: %s", stderr.String())
	}

	html := stdout.String()
	if !stdbytes.Contains([]byte(html), []byte("<!DOCTYPE html>")) {
		t.Error("HTML output missing DOCTYPE declaration")
	}
	if !stdbytes.Contains([]byte(html), []byte("TLS Check Results")) {
		t.Error("HTML output missing title")
	}
	if !stdbytes.Contains([]byte(html), []byte("example")) {
		t.Error("HTML output missing cluster name")
	}
}
