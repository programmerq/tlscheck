# tlscheck

Prototype harness for Teleport proxy TLS connectivity probing. See [docs/design.md](docs/design.md) for the current design and test matrix.

## CLI plan scaffolding

The `tlscheck` CLI currently builds a JSON plan that enumerates every `(service, port, SNI, ALPN)` combination the harness will probe. Example:

```shell
go run ./cmd/tlscheck
```

Flags:

* `--proxy-server` – Teleport proxy public DNS name. When omitted, the CLI reads
  `$TELEPORT_HOME/current-profile` (or `~/.tsh/current-profile`) to locate the active profile and
  derives the public address automatically.
* `--repeat` – Attempts per `(SNI, ALPN, IP)` combination. Defaults to `1` per the latest guidance.
* `--services` – Optional comma-separated allow-list of service keys (for example
  `proxy_web,proxy_ssh`). Valid service keys: `proxy_web`, `reverse_tunnel`, `proxy_ssh`,
  `proxy_ssh_grpc`, `auth`, `kube`, `db_postgres`, `db_mysql`, `db_mongo`, `db_redis`, `app`,
  `desktop`.
* `-v, --version` – Print the tlscheck build identifier and exit.

Cluster name and Teleport version are no longer accepted as flags; the CLI always retrieves them via
`/webapi/ping` after resolving the proxy address. If no active Teleport profile exists, tlscheck
prints `no active tsh profile. specify a proxy via --proxy-server` alongside the usage banner.

The command respects `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` to mirror `tsh` behaviour. Proxy settings are echoed back in the generated plan for traceability.

## Testing

Run `go test ./...` for the fast unit suite. The [testing strategy](docs/testing.md) describes how we
will expand coverage with TLS failure injection and future integration checks. Unit coverage now
includes discovery of Teleport profiles, `/webapi/ping` lookups, and TLS probe execution with
in-memory certificates so handshake, ALPN mismatch, and failure classifications stay regression-free.
