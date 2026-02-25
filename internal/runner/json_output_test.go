package runner

import (
"context"
"encoding/json"
"testing"

"github.com/programmerq/tlscheck/internal/config"
"github.com/programmerq/tlscheck/internal/discovery"
"github.com/programmerq/tlscheck/internal/plan"
"github.com/programmerq/tlscheck/internal/probe"
)

func TestClientCertInJSONOutput(t *testing.T) {
certPEM, keyPEM, err := discovery.GenerateTestCertificate()
if err != nil {
t.Fatalf("failed to generate test cert: %v", err)
}

engine := probe.NewEngine()
engine.SetClientCert(certPEM, keyPEM)

// Check the cert is available
clientCerts := engine.GetClientCertificates()
if len(clientCerts) == 0 {
t.Fatal("GetClientCertificates returned empty - cert not set on engine")
}

var clientCertFP string
for fp := range clientCerts {
clientCertFP = fp
}
t.Logf("Client cert fingerprint: %s", clientCertFP)

opts := config.Options{
PublicAddr: "test.example.com",
Repeat:     1,
ClientCert: &config.ClientCertInfo{Fingerprint: clientCertFP},
}

builder := PlanBuilderFunc(plan.Build)
exec, _ := Execute(context.Background(), opts, builder, engine)

// Marshal to JSON to simulate real output
data, err := json.MarshalIndent(exec, "", "  ")
if err != nil {
t.Fatalf("failed to marshal: %v", err)
}

t.Logf("Certs map size: %d", len(exec.Certs))
if len(exec.Certs) == 0 {
t.Error("FAIL: client cert not in exec.Certs!")
t.Logf("JSON output:\n%s", string(data[:min(len(data), 2000)]))
} else {
if _, ok := exec.Certs[clientCertFP]; ok {
t.Logf("PASS: client cert found in exec.Certs with fingerprint %s", clientCertFP)
} else {
t.Errorf("client cert not found in exec.Certs by fingerprint %s", clientCertFP)
}
}

// Check if any result has ClientCertFingerprint set
var foundResultWithCert bool
for _, r := range exec.Results {
if r.ClientCertFingerprint != "" {
foundResultWithCert = true
t.Logf("Result %s has ClientCertFingerprint: %s", r.Target.ServiceKey, r.ClientCertFingerprint)
}
}
if !foundResultWithCert {
t.Log("No results had ClientCertFingerprint set (probe likely failed due to no real server)")
}
}

func min(a, b int) int {
if a < b {
return a
}
return b
}
