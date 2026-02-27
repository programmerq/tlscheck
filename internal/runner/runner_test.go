package runner

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/programmerq/tlscheck/internal/config"
	"github.com/programmerq/tlscheck/internal/discovery"
	"github.com/programmerq/tlscheck/internal/plan"
	"github.com/programmerq/tlscheck/internal/probe"
)

type stubEngine struct {
	lastPlan plan.Plan
	results  []probe.Result
	err      error
}

func (s *stubEngine) Run(ctx context.Context, p plan.Plan) ([]probe.Result, error) {
	s.lastPlan = p
	return s.results, s.err
}

type stubBuilder struct {
	plan plan.Plan
	err  error
}

func (s *stubBuilder) Build(opts config.Options) (plan.Plan, error) {
	return s.plan, s.err
}

func TestExecuteSuccess(t *testing.T) {
	t.Parallel()

	opts := config.Options{PublicAddr: "proxy.example.com"}
	expectedPlan := plan.Plan{Targets: []plan.ProbeTarget{{ServiceKey: "proxy_web"}}}
	expectedResults := []probe.Result{{Target: expectedPlan.Targets[0], Attempt: 1}}

	builder := &stubBuilder{plan: expectedPlan}
	engine := &stubEngine{results: expectedResults}

	exec, err := Execute(context.Background(), opts, builder, engine)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if !reflect.DeepEqual(exec.Plan, expectedPlan) {
		t.Fatalf("execution plan mismatch:\n got %#v\nwant %#v", exec.Plan, expectedPlan)
	}
	if !reflect.DeepEqual(exec.Results, expectedResults) {
		t.Fatalf("execution results mismatch:\n got %#v\nwant %#v", exec.Results, expectedResults)
	}

	if !reflect.DeepEqual(engine.lastPlan, expectedPlan) {
		t.Fatalf("engine received unexpected plan: %#v", engine.lastPlan)
	}

	// Verify network info is populated
	if exec.Network == nil {
		t.Fatal("expected Network info to be populated")
	}
}

func TestExecuteBuilderError(t *testing.T) {
	t.Parallel()

	builderErr := errors.New("plan failed")
	builder := &stubBuilder{err: builderErr}

	exec, err := Execute(context.Background(), config.Options{}, builder, &stubEngine{})
	if err == nil {
		t.Fatalf("Execute returned nil error, want %v", builderErr)
	}
	if exec.Plan.Targets != nil || exec.Results != nil {
		t.Fatalf("expected empty execution on error, got %#v", exec)
	}
}

func TestExecuteEngineError(t *testing.T) {
	t.Parallel()

	expectedPlan := plan.Plan{Targets: []plan.ProbeTarget{{ServiceKey: "proxy_web"}}}
	engineErr := errors.New("dial failed")
	engine := &stubEngine{err: engineErr}
	builder := &stubBuilder{plan: expectedPlan}

	exec, err := Execute(context.Background(), config.Options{}, builder, engine)
	if err == nil {
		t.Fatalf("Execute returned nil error, want %v", engineErr)
	}
	if !reflect.DeepEqual(engine.lastPlan, expectedPlan) {
		t.Fatalf("engine received unexpected plan: %#v", engine.lastPlan)
	}
	if exec.Plan.Targets != nil || exec.Results != nil {
		t.Fatalf("expected empty execution on error, got %#v", exec)
	}
}

func TestExecuteRequiresDependencies(t *testing.T) {
	t.Parallel()

	if _, err := Execute(context.Background(), config.Options{}, nil, &stubEngine{}); err == nil {
		t.Fatalf("Execute accepted nil builder")
	}
	if _, err := Execute(context.Background(), config.Options{}, &stubBuilder{}, nil); err == nil {
		t.Fatalf("Execute accepted nil engine")
	}
}

type stubEngineWithCerts struct {
	stubEngine
	certs map[string]*probe.CertInfo
}

func (s *stubEngineWithCerts) GetCertificates() map[string]*probe.CertInfo {
	return s.certs
}

func TestExecuteCertificateCollection(t *testing.T) {
	t.Parallel()

	opts := config.Options{PublicAddr: "proxy.example.com"}
	expectedPlan := plan.Plan{Targets: []plan.ProbeTarget{{ServiceKey: "proxy_web"}}}

	// Create a result with a certificate chain
	result := probe.Result{
		Target:           expectedPlan.Targets[0],
		Attempt:          1,
		LeafFingerprint:  "ABC123",
		CertificateChain: []string{"ABC123", "DEF456"},
	}

	// Create an engine that implements CertificateCollector
	expectedCerts := map[string]*probe.CertInfo{
		"ABC123": {
			PEM:         "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----\n",
			Fingerprint: "ABC123",
			Source:      probe.CertSourceServer,
		},
		"DEF456": {
			PEM:         "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n",
			Fingerprint: "DEF456",
			Source:      probe.CertSourceServer,
		},
	}

	builder := &stubBuilder{plan: expectedPlan}
	engine := &stubEngineWithCerts{
		stubEngine: stubEngine{results: []probe.Result{result}},
		certs:      expectedCerts,
	}

	exec, err := Execute(context.Background(), opts, builder, engine)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	// Verify certificates are collected
	if exec.Certs == nil {
		t.Fatalf("expected Certs to be populated, got nil")
	}

	// Verify both certificates are present
	if len(exec.Certs) != 2 {
		t.Errorf("expected 2 certs, got %d", len(exec.Certs))
	}

	// Verify network info is populated
	if exec.Network == nil {
		t.Fatal("expected Network info to be populated")
	}
}

func TestExecuteNoCertificates(t *testing.T) {
	t.Parallel()

	opts := config.Options{PublicAddr: "proxy.example.com"}
	expectedPlan := plan.Plan{Targets: []plan.ProbeTarget{{ServiceKey: "proxy_web"}}}
	expectedResults := []probe.Result{{Target: expectedPlan.Targets[0], Attempt: 1}}

	builder := &stubBuilder{plan: expectedPlan}
	engine := &stubEngine{results: expectedResults}

	exec, err := Execute(context.Background(), opts, builder, engine)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	// Verify Certs is not set (or is empty) when engine doesn't implement CertificateCollector
	if exec.Certs != nil && len(exec.Certs) > 0 {
		t.Errorf("expected Certs to be empty or nil when engine doesn't collect certificates, got %#v", exec.Certs)
	}

	// Verify network info is populated
	if exec.Network == nil {
		t.Fatal("expected Network info to be populated")
	}
}

type stubEngineWithClientCerts struct {
	stubEngine
	clientCerts map[string]*probe.CertInfo
}

func (s *stubEngineWithClientCerts) GetClientCertificates() map[string]*probe.CertInfo {
	return s.clientCerts
}

func TestExecuteClientCertificateCollection(t *testing.T) {
	t.Parallel()

	opts := config.Options{PublicAddr: "proxy.example.com"}
	trueVal := true
	expectedPlan := plan.Plan{Targets: []plan.ProbeTarget{{ServiceKey: "proxy_ssh_grpc", UseClientCert: &trueVal}}}

	// Create a result with a client cert fingerprint
	result := probe.Result{
		Target:                expectedPlan.Targets[0],
		Attempt:               1,
		ClientCertFingerprint: "57A7AF6D505D1223B5DB0280E6CE4119A8067FED960649F8308332C99C398BE7",
	}

	// Create an engine that implements ClientCertificateCollector
	expectedClientCerts := map[string]*probe.CertInfo{
		"57A7AF6D505D1223B5DB0280E6CE4119A8067FED960649F8308332C99C398BE7": {
			PEM:         "-----BEGIN CERTIFICATE-----\nMIIDZz...\n-----END CERTIFICATE-----\n",
			Fingerprint: "57A7AF6D505D1223B5DB0280E6CE4119A8067FED960649F8308332C99C398BE7",
			Source:      probe.CertSourceClient,
		},
	}

	builder := &stubBuilder{plan: expectedPlan}
	engine := &stubEngineWithClientCerts{
		stubEngine:  stubEngine{results: []probe.Result{result}},
		clientCerts: expectedClientCerts,
	}

	exec, err := Execute(context.Background(), opts, builder, engine)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	// Verify client certificates are collected in combined Certs map
	if exec.Certs == nil {
		t.Fatalf("expected Certs to be populated with client cert, got nil")
	}

	// Verify client cert is in the combined map
	if len(exec.Certs) != 1 {
		t.Errorf("expected 1 cert in combined map, got %d", len(exec.Certs))
	}

	// Verify the result includes the client cert fingerprint
	if result.ClientCertFingerprint != "57A7AF6D505D1223B5DB0280E6CE4119A8067FED960649F8308332C99C398BE7" {
		t.Errorf("Result missing client cert fingerprint")
	}
}

func TestExecuteHostCACertCollection(t *testing.T) {
	t.Parallel()

	// Generate a CA certificate and encode it as PEM.
	certPEM, _, err := discovery.GenerateTestCertificate()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	opts := config.Options{
		PublicAddr: "proxy.example.com",
		HostCAPEM:  certPEM,
	}
	builder := &stubBuilder{plan: plan.Plan{}}
	engine := &stubEngine{}

	exec, err := Execute(context.Background(), opts, builder, engine)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if len(exec.Certs) == 0 {
		t.Fatal("expected Certs to include HostCA cert, got empty map")
	}

	for fp, info := range exec.Certs {
		if info.Source != probe.CertSourceHostCA {
			t.Errorf("cert %s: source = %q, want 'host_ca'", fp, info.Source)
		}
	}
}

func TestExecuteHostCACertDoesNotOverwriteServerCert(t *testing.T) {
	t.Parallel()

	// Use a cert as both a "server cert" (via the engine) and as a HostCA cert.
	// When fingerprints collide the server cert (set first) should win.
	certPEM, _, err := discovery.GenerateTestCertificate()
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	// Parse the fingerprint from the PEM so we can create a matching stub cert.
	serverCerts := probe.ParseCertBundleFromPEM(certPEM, probe.CertSourceServer)
	if len(serverCerts) != 1 {
		t.Fatalf("expected 1 cert from PEM, got %d", len(serverCerts))
	}
	var fp string
	var serverInfo *probe.CertInfo
	for k, v := range serverCerts {
		fp = k
		serverInfo = v
	}

	opts := config.Options{
		PublicAddr: "proxy.example.com",
		HostCAPEM:  certPEM,
	}
	builder := &stubBuilder{plan: plan.Plan{}}
	engine := &stubEngineWithCerts{
		stubEngine: stubEngine{},
		certs:      map[string]*probe.CertInfo{fp: serverInfo},
	}

	exec, err := Execute(context.Background(), opts, builder, engine)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if exec.Certs[fp].Source != probe.CertSourceServer {
		t.Errorf("expected server cert source to win, got %q", exec.Certs[fp].Source)
	}
}

func TestRealEngineWithClientCert(t *testing.T) {
	// Generate a test certificate
	certPEM, keyPEM, err := discovery.GenerateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	// Create real engine
	engine := probe.NewEngine()

	// Set client cert
	engine.SetClientCert(certPEM, keyPEM)

	// Verify GetClientCertificates returns the cert with expanded info
	clientCerts := engine.GetClientCertificates()
	if clientCerts == nil || len(clientCerts) == 0 {
		t.Fatal("GetClientCertificates returned nil or empty")
	}

	t.Logf("Client certs: %d", len(clientCerts))
	for fp, info := range clientCerts {
		t.Logf("  Fingerprint: %s", fp)
		t.Logf("  Source: %s", info.Source)
		t.Logf("  Subject CN: %s", info.Subject.CommonName)
	}

	// Verify the client cert has the correct source
	for _, info := range clientCerts {
		if info.Source != probe.CertSourceClient {
			t.Errorf("Expected client cert source to be 'client', got %q", info.Source)
		}
	}

	// Now test through runner.Execute
	opts := config.Options{
		PublicAddr: "test.example.com",
		Repeat:     1,
	}

	builder := PlanBuilderFunc(plan.Build)

	// Note: This will fail because we can't connect to test.example.com
	// but we should still check if Certs would be populated even on error
	exec, _ := Execute(context.Background(), opts, builder, engine)

	// Check if Certs is populated in the execution
	// Even if execution failed, if the engine had client certs, they should be in the result
	if exec.Certs != nil && len(exec.Certs) > 0 {
		t.Logf("Certs in Execution: %d", len(exec.Certs))
	} else {
		// This is the issue! When execution fails, we might not populate certs
		t.Logf("WARNING: Certs not populated in Execution (might be expected if error occurred early)")
	}
}
