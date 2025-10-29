# tlscheck

Prototype harness for Teleport proxy TLS connectivity probing. See [docs/design.md](docs/design.md) for the current design and test matrix.

## CLI execution flow

The `tlscheck` CLI now builds a JSON plan and executes it immediately, returning the generated plan
together with probe results. Every `(service, port, SNI, ALPN)` combination that the harness touches
appears in the `plan` section of the output, while the `results` array records the negotiated ALPN,
leaf certificate subject/fingerprint, or a classified failure for each attempt. All probes dial the
Teleport proxy web endpoint discovered from `/webapi/ping` (specifically the
`proxy.ssh.public_addr` host and port). When a cluster advertises `tls_routing_enabled=false`, the
plan marks non-web probes with `"informational_only": true` so failures on those alternate SNIs do
not read as hard outages. Example:

```shell
go run ./cmd/tlscheck > results.json
```

The resulting JSON document contains three top-level keys (`plan`, `results`, and `certs`):

* `plan` – the resolved probe matrix, including the base16 cluster hints and the upgrade sequence we
  exercise against the proxy web endpoint to detect whether connection upgrades are required. Each
  target also records a `trust` strategy (`system` or `host_ca`) so it is obvious which authority
  bundle the probe engine will use during verification.
* `results` – an entry per probe attempt that captures negotiated protocols, peer certificate
  metadata (subject, issuer, SANs, fingerprint), connection details (local/remote addresses,
  resolved IP, TLS version, cipher suite), timing information (dial, handshake, and total
  durations), and failure classifications such as `timeout`, `alpn_mismatch`, `untrusted_cert`, or
  `host_ca_unavailable`. When a hostname resolves to multiple IPs, each IP is probed independently.
  Each result also includes a `certificate_chain` field containing an ordered list of certificate
  fingerprints (leaf first) representing the complete chain presented by the server.
* `certs` – a map of all certificates encountered during probing, indexed by their SHA-256
  fingerprint (uppercase hex). Each entry contains the certificate in PEM format. This structure
  avoids duplication when the same certificate appears in multiple probe results, and allows easy
  lookup of the full certificate data by referencing fingerprints from the `certificate_chain` field
  in results.

Flags:

* `--proxy-server` – Teleport proxy public DNS name. When omitted, the CLI reads
  `$TELEPORT_HOME/current-profile` (or `~/.tsh/current-profile`) to locate the active profile and
  derives the public address automatically.
* `--repeat` – Attempts per `(SNI, ALPN, IP)` combination. Defaults to `1` per the latest guidance.
* `--services` – Optional comma-separated allow-list of service keys (for example
  `proxy_web,proxy_ssh`). Valid service keys: `proxy_web`, `reverse_tunnel`, `proxy_ssh`,
  `proxy_ssh_grpc`, `auth_via_proxy`, `kubernetes`, `db_postgres`, `db_mysql`, `db_mongodb`,
  `db_redis`, `app_access`, `desktop_access`. Each selected service reuses the proxy web port
  reported by `/webapi/ping` so the CLI never assumes Teleport’s legacy listener layout.
* `-v, --version` – Print the tlscheck build identifier and exit.

Cluster name and Teleport version are no longer accepted as flags; the CLI always retrieves them via
`/webapi/ping` after resolving the proxy address. The response also drives the probe severity: when
`tls_routing_enabled` is `false`, the CLI still runs ALPN/SNI permutations against the web port but
flags them as informational in the emitted plan. If no active Teleport profile exists, tlscheck prints
`no active tsh profile. specify a proxy via --proxy-server` alongside the usage banner. When the probe
engine cannot complete an attempt (for example, handshake or ALPN negotiation failures), the CLI still
emits the plan and annotates each failure with a descriptive `kind` and message so the underlying
issue is obvious from the JSON.

The command respects `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` to mirror `tsh` behaviour. Proxy
settings are echoed back in the generated plan for traceability, and tlscheck automatically downloads
the Teleport Host CA bundle from `/webapi/auth/export?type=tls-host`. Probes that depend on
Teleport-issued credentials (`proxy_ssh`, `proxy_ssh_grpc`, `auth_via_proxy`, and `kubernetes`) pin to
that bundle, while all other targets continue to use the operating system trust store. If the host
bundle cannot be fetched, only the host-CA probes fail (with `host_ca_unavailable`) while still
reporting the presented certificate details. All failures now capture certificate metadata even when
verification fails so operators can inspect SANs and issuers for misconfigurations.

## Building

Build the binary for your current platform:

```shell
make build
```

For cross-platform builds and release artifacts, see the [release documentation](docs/release.md).

## Testing

Run `go test ./...` for the fast unit suite. The [testing strategy](docs/testing.md) describes how we
will expand coverage with TLS failure injection and future integration checks. Unit coverage now
includes discovery of Teleport profiles, `/webapi/ping` lookups, and TLS probe execution with
in-memory certificates so handshake, ALPN mismatch, and failure classifications stay regression-free.
The same document outlines a short manual validation loop for exercising the tool against a real
Teleport cluster before the full integration harness is in place.

## Releases

See [docs/release.md](docs/release.md) for information about the release process, including:
- Creating releases with GitHub tags
- Building cross-platform binaries
- Docker image publishing to ghcr.io
- Supported platforms and architectures
