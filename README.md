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

The resulting JSON document contains several top-level keys:

* `arguments` – the parsed command-line options and runtime configuration used for this execution.
* `network` – comprehensive network configuration discovery including:
  - `proxy_config` – detected proxy settings from environment variables (HTTP_PROXY, HTTPS_PROXY,
    NO_PROXY, ALL_PROXY, FTP_PROXY), OS-level system proxy settings (macOS Network Settings, Windows
    Registry), SOCKS proxy configuration, and PAC (Proxy Auto-Configuration) file detection and
    retrieval. This captures all proxy sources including those not visible via environment variables
    alone.
  - `routes` – system routing table when available, including default gateway, all route entries with
    destination, gateway, interface, and metrics. Routes are captured on Linux (via `ip route` or
    `route`), macOS (via `netstat -rn`), and Windows (via `route print`). If route capture fails due
    to permissions, the `available` field is false and an error message is provided.
  - `vpn` – VPN detection results including identified VPN network interfaces (tun, tap, utun, ppp,
    wireguard, etc.), running VPN applications (OpenVPN, WireGuard, Cisco AnyConnect, GlobalProtect,
    Tailscale, ZeroTier, etc.), and routes associated with VPN interfaces. Detection works across
    Linux, macOS, and Windows platforms.
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
* `certs` – a map of all certificates encountered during probing (including client certificates used
  for mutual TLS), indexed by their SHA-256 fingerprint (uppercase hex). Each entry contains expanded
  certificate metadata:
  - `pem` – the certificate in PEM format
  - `fingerprint` – SHA-256 fingerprint (uppercase hex)
  - `subject` – structured subject name (common_name, organization, country, etc.)
  - `issuer` – structured issuer name
  - `validity` – certificate validity period (not_before, not_after in ISO 8601 format)
  - `sans` – Subject Alternative Names (dns, ip, uri, email arrays)
  - `authority_key_id` – issuer key identifier (colon-separated hex)
  - `subject_key_id` – subject key identifier
  - `is_ca` – whether the certificate is a CA
  - `issuer_fingerprint` – fingerprint of the issuer certificate if present in the chain
  - `serial_number`, `signature_algorithm`, `public_key_algorithm`, `key_usage`, `ext_key_usage`
  - `source` – how the certificate was obtained ("server" for TLS handshake, "client" for mTLS)
  - `trust_status` – MITM detection info when issuer matches known CAs but fingerprint differs

  This structure avoids duplication when the same certificate appears in multiple probe results,
  allows easy lookup by fingerprint, and provides detailed metadata for frontend rendering without
  requiring PEM decoding.

## JSON Schema

The output format is fully documented by a JSON schema located in `schemas/execution.json`. The schema
can be used for:

* **Validation**: Programmatically verify that `tlscheck` output matches the expected structure
* **IDE Integration**: Get autocomplete and validation in editors that support JSON Schema
* **Documentation**: Serve as the canonical reference for the output format

To generate or validate the schema:

```shell
# Generate the schema from Go structs
make schema

# Verify the schema is up-to-date
make schema-check
```

See [schemas/README.md](schemas/README.md) for details on using and validating against the schema.

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

The command respects `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` to mirror `tsh` behaviour. When a
proxy is detected, tlscheck automatically runs all TLS probes **twice**: once using the configured
proxy (via HTTP CONNECT), and once with a direct connection that bypasses the proxy. This dual
execution allows operators to compare behavior in both scenarios and identify issues caused by MITM
proxies or proxy misconfigurations. Each probe result indicates whether it used the proxy via
`use_proxy` and `proxy_url` fields in the target configuration. Proxy settings are echoed back in the
generated plan for traceability, and tlscheck automatically downloads the Teleport Host CA bundle from
`/webapi/auth/export?type=tls-host`. Probes that depend on Teleport-issued credentials (`proxy_ssh`,
`proxy_ssh_grpc`, `auth_via_proxy`, and `kubernetes`) pin to that bundle, while all other targets
continue to use the operating system trust store. If the host bundle cannot be fetched, only the
host-CA probes fail (with `host_ca_unavailable`) while still reporting the presented certificate
details. All failures now capture certificate metadata even when verification fails so operators can
inspect SANs and issuers for misconfigurations.

## Network Discovery

tlscheck automatically captures comprehensive network configuration to help diagnose connectivity
issues in corporate environments:

### Proxy Detection

- **Environment Variables**: Detects `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `ALL_PROXY`, and
  `FTP_PROXY` (both uppercase and lowercase variants).
- **System-Level Proxies**: On macOS, reads proxy settings from Network Preferences via
  `networksetup`. On Windows, reads from the Registry (`HKEY_CURRENT_USER\Software\Microsoft\Windows\
  CurrentVersion\Internet Settings`).
- **SOCKS Proxies**: Detects SOCKS4/SOCKS5 proxies configured via `ALL_PROXY` environment variable.
- **PAC (Proxy Auto-Configuration)**: Detects PAC file URLs from system settings and attempts to
  download and include the PAC script content for inspection.

### Routing Table Capture

tlscheck captures the system routing table when available:

- **Linux**: Uses `ip route show` or falls back to `route -n`
- **macOS**: Uses `netstat -rn`
- **Windows**: Uses `route print -4`

Route information includes destination networks, gateways, interfaces, metrics, and flags. If route
capture fails due to insufficient permissions, the output indicates this with an error message rather
than failing the entire probe run. Network interfaces are also enumerated with their addresses, MTU,
and flags.

### VPN Detection

Automatically identifies VPN connections:

- **VPN Interfaces**: Detects network interfaces with common VPN naming patterns (tun, tap, utun, ppp,
  wireguard, ipsec, vpn, openvpn, tailscale, zerotier) and reports their status and addresses.
- **VPN Applications**: Identifies running VPN applications and services:
  - Linux: OpenVPN, WireGuard, strongSwan, Tailscale, ZeroTier, NetworkManager VPN connections
  - macOS: OpenVPN, WireGuard, Cisco AnyConnect, GlobalProtect, Tunnelblick, Viscosity, Tailscale,
    ZeroTier, IPSec/IKEv2 configurations via `scutil`
  - Windows: VPN adapters including PPTP, L2TP, and WAN Miniport interfaces
- **VPN Routes**: Extracts routing table entries associated with detected VPN interfaces to show which
  networks are routed through VPN tunnels.

All network discovery results are included in the `network` top-level key in the JSON output,
providing operators with a complete picture of the network environment alongside connectivity probe
results.

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
