# TLSCheck Probe Harness Design

## Version-Aware Connectivity Matrix

| Service | Port (Separate / Legacy) | SNI (Multiplex) | ALPN List Proposed (Multiplex) | Upgrade Path When Behind L7 (Teleport version) |
| --- | --- | --- | --- | --- |
| Proxy Web UI & HTTPS API (/webapi/ping, /webapi/find, auth flows) | 3080 (or 443 if not multiplexing) | cluster.example.com (public DNS) | h2,http/1.1 | v15.1–v17: attempt `Upgrade: websocket` and `Upgrade: alpn` (fallback `alpn-ping`) against `/webapi/connectionupgrade` with mirrored `X-Teleport-Upgrade` header. v18+: WebSocket only. |
| Reverse tunnel (client/agent testing proxy’s tunnel entry) | 3024 | Public cluster DNS (probe raw IP with identical SNI) | teleport-reversetunnel | Same upgrade behavior (WebSocket preferred ≥15.1; legacy `alpn`/`alpn-ping` acceptable only <18). |
| Proxy SSH (tsh→proxy for node SSH) | 3023 | Public cluster DNS (include base16-encoded internal SNI variant when dialing raw IP) | teleport-proxy-ssh | Same upgrade behavior as above. |
| Proxy SSH-gRPC (internal SSH over gRPC transport via proxy) | — | Public cluster DNS | teleport-proxy-ssh-grpc (negotiates h2) | Same upgrade behavior as above. |
| Auth via Proxy (tsh or agents dialing Auth through proxy) | (Auth gRPC is 3025; clients use proxy via TLS routing) | teleport-auth@<cluster-name> (then h2) | teleport-auth@<cluster-name> | Same upgrade behavior as above. |
| Kubernetes API via Proxy | 3026 | kube-teleport-proxy-alpn.<cluster-name> (special SNI prefix) | h2,http/1.1 | Same upgrade behavior; L7-compatible TLS routing introduced in 13+, relevant in 15–18. |
| Databases via Proxy (tsh upstream hop) | Split listeners: Postgres 5432, MySQL 3036, MongoDB 27017, Redis 6379 | Public cluster DNS | Upstream ALPN supplied by `tsh` | Same upgrade behavior; harness dials ALPN path explicitly. |
| App Access (HTTP apps) | Multiplexed on web | Public cluster DNS | h2,http/1.1 | Same upgrade behavior. |
| Desktop Access (RDP control plane) | Multiplexed on web | Public cluster DNS | gRPC/HTTP stack → effectively h2,http/1.1 | Same upgrade behavior. |

## Notes and Expectations

- **Internal SNI forms**: compute the base16-encoded cluster name after `/webapi/ping`. These SNIs do not resolve in DNS and are only supplied during TLS handshakes when dialing a resolved proxy IP.
- **HTTP CONNECT**: honor `HTTPS_PROXY` / `HTTP_PROXY` settings. Log the CONNECT target and any proxy response headers when a proxy is used to identify middleboxes that strip upgrade headers.
- **Runtime discovery**: when CLI flags omit cluster metadata, read the active Teleport profile via `$TELEPORT_HOME/current-profile` (or `~/.tsh/current-profile`) and query `/webapi/ping` to obtain the public address, cluster name, and Teleport version automatically.
- **Upgrade contract**: send `GET /webapi/connectionupgrade` with `Connection: Upgrade`, the relevant `Upgrade` token (`websocket`, `alpn`, `alpn-ping`), and `X-Teleport-Upgrade` mirroring the value to survive middleboxes.
- **Version gates**: WebSocket upgrade landed in the 15.x line and is mandatory in 18+. Probes for v15–v17 should attempt both WebSocket and legacy upgrades; v18+ uses WebSocket only.
- **Certificates**: leaf certificates from proxy or auth must chain to the cluster Host CA and present the expected identity. Flag mismatches.

## Probe Execution Defaults

- **Repeat count**: default to a single attempt (`N = 1`) per `(SNI, ALPN, IP)` combination. Allow opt-in configuration for higher counts when deeper sampling is required.
- **Failure taxonomy**: classify probe outcomes into `handshake_failed`, `upgrade_rejected`, `alpn_mismatch`, `unexpected_cert`, `timeout`, and `proxy_connect_failed`.
- **Logging**: capture target host, resolved IP, SNI sent, ALPN list, negotiated protocol, leaf certificate fingerprint/subject, upgrade path details, and proxy metadata when applicable.

## Implementation Roadmap

1. Implement a lightweight Go CLI (this repository) that mirrors `tsh` probe ordering (`/webapi/ping` before ALPN/upgrade attempts).
2. Build a modular probe engine capable of dialing via direct sockets or HTTP CONNECT based on environment configuration.
3. Emit structured JSONL records per attempt with the fields listed above.
4. Provide configuration knobs for Teleport version bands to adjust upgrade behavior automatically.
5. Back the probe engine with the multilayered [testing strategy](testing.md) so TLS failures can be
   injected deterministically in unit and integration environments.
