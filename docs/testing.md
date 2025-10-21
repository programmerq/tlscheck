# Testing Strategy

This project needs high confidence before running probes against production Teleport clusters.
The following layers ensure we can iterate safely while surfacing regressions quickly.

## Unit Tests

* `internal/config` – table-driven coverage for argument parsing, proxy detection, and service
  filtering. These tests validate defaults such as repeat counts and ensure flag changes do not
  silently break backwards compatibility.
* `internal/plan` – golden-style tests that assert the matrix of services, upgrade sequences, and
  notes for each Teleport version band. These tests pin behaviour such as the base16 cluster hint
  and the WebSocket-only transition in v18+.
* `internal/probe` – TLS harnesses that spin up in-memory listeners. They now confirm that asking
  for `teleport.example.com` via SNI returns a leaf certificate for the same host, and classify
  ALPN mismatches and handshake failures without touching external networks.

Unit tests will grow to include serialization helpers, SNI/ALPN builders, and any future resolvers.
Mocks in this layer remain simple structs so that higher-level probe tests can inject synthetic
failures without bringing up full network stacks.

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
