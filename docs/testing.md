# Testing Strategy

This project needs high confidence before running probes against production Teleport clusters.
The following layers ensure we can iterate safely while surfacing regressions quickly.

## Unit Tests

Current coverage focuses on locking in the behaviours that feed the probe engine:

* `internal/config` – table-driven coverage for argument parsing, proxy detection, service
  filtering, and runtime discovery. Tests now ensure we surface proxy metadata from `/webapi/ping`
  and fetch the Teleport Host CA bundle so probes pin to Teleport-managed trust roots.
* `internal/plan` – golden-style tests that assert the matrix of services, upgrade sequences, and
  notes for each Teleport version band. These tests pin behaviour such as the base16 cluster hint,
  the WebSocket-only transition in v18+, the auth SNI/ALPN ordering (`<base16>.teleport.cluster.local`
  with a `teleport-auth@` ALPN prefix), and ensure we reuse the web proxy port from `/webapi/ping`
  while flagging multiplex probes as informational when TLS routing is disabled.
* `internal/probe` – TLS harnesses that spin up in-memory listeners. They now confirm that asking
  for `teleport.example.com` via SNI returns a leaf certificate for the same host, record negotiated
  ALPN values, enforce the correct trust strategy (system roots vs. the downloaded host CA), capture
  subject/issuer/SAN details even on trust failures, and classify handshake, ALPN, dial, and
  certificate-verification failures without touching external networks.
* `internal/runner` – orchestration tests that assert the CLI stitches plan building and probe
  execution together correctly, returning empty results if either phase fails and surfacing errors to
  callers without additional network setup.
* `cmd/tlscheck` – end-to-end command wiring that injects stub dependencies to confirm the CLI emits
  the generated plan and probe results while seeding the probe engine with a certificate pool.

As we extend the implementation, unit tests will grow to include serialization helpers,
SNI/ALPN builders, and any future resolvers. Mocks in this layer remain simple structs so that
higher-level probe tests can inject synthetic failures without bringing up full network stacks.

## Probe Engine Tests

Once the dialer implementation lands, we will abstract network I/O behind interfaces. A probe will
receive a `Dialer` and `HTTPClient` so that tests can swap in in-memory transports. We will use the
following primitives to simulate TLS outcomes:

* `net.Pipe` with `tls.Server`/`tls.Client` wrapped around each endpoint to emulate handshake
  success, ALPN negotiation, or explicit handshake failures.
* Custom `tls.Config` hooks (`GetConfigForClient`, `VerifyPeerCertificate`) that inject specific
  certificate chains or errors to test `unexpected_cert` and `handshake_failed` paths.
* `httptest.Server` instances configured with middleware that strips or rewrites Upgrade headers so
  we can assert the `upgrade_rejected` classification and proxy metadata logging.

These tests will be table-driven and will produce JSONL outputs that we compare against fixtures,
allowing us to pin both successful probe results and nuanced failure taxonomies.

## Integration Tests

A future phase will provision ephemeral Teleport clusters (via docker-compose or Terraform) covering
version bands v15–v18. Against these clusters we will run the full CLI end-to-end, verifying that the
observed TLS handshake metadata matches expectations (cert identities, negotiated protocols, upgrade
behaviour). These tests will run behind a synthetic L7 proxy that can strip Upgrade headers to ensure
proxy reporting remains accurate.

Until the integration environment exists, we will simulate a subset locally using `minica`-issued
certificates and lightweight Go servers that implement the Teleport upgrade contract endpoints.

### Manual validation steps

Before the automated environment is online, we can still exercise the tool against a real cluster
while minimising risk:

1. Use `tsh login` to ensure a fresh profile exists under `$TELEPORT_HOME` (or `~/.tsh`). The CLI
   will pick up the `current-profile` pointer automatically.
2. Run `go run ./cmd/tlscheck --services proxy_web --repeat 1` to inspect the JSON plan and verify
   that the discovered proxy address, cluster name, Teleport version, and host CA fingerprint match
   expectations. Check that the plan’s `trust` field reads `system` for web probes and `host_ca` for
   the internal services. Only the proxy web check includes the connection upgrade sequence; other
   probes now run without upgrade tokens.
3. Capture a baseline by running the probe engine against a known-good Teleport environment while
   tailing proxy logs. Confirm that the recorded negotiated protocol, certificate subject, and ALPN
   match the server output.
4. Introduce controlled failures (for example, point DNS at an endpoint serving an invalid
   certificate) and confirm that the JSON results land in the correct failure buckets (`untrusted_cert`
   vs. `host_ca_unavailable`) while still recording the presented certificate details. These manual
   checks mirror the synthetic failures already covered in unit tests and provide confidence before
   wider rollout.

## Failure Injection Helpers

To make failure injection repeatable, we will maintain helper builders that describe a probe attempt
(e.g. desired ALPN, SNI, certificate chain) and produce mock listeners. Tests will compose these
helpers to assert that classification (`handshake_failed`, `timeout`, etc.) and logging fields are
set correctly. The helpers will track outstanding goroutines and close listeners at the end of each
test to avoid resource leaks.

## CI Hooks

`go test ./...` remains the default check. As we add integration coverage, we will gate the heavier
scenarios behind build tags (`integration`) so that contributors can run fast unit tests by default
and opt into the full suite with `go test -tags=integration ./...`.
