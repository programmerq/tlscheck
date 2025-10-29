# DNS Resolver Information

## Overview

This document outlines considerations for gathering and reporting DNS resolver information when using tlscheck. Currently, tlscheck performs basic DNS resolution and reports the resolved IPs. Future enhancements could capture more detailed information about the resolver configuration and behavior.

## Current Implementation

As of the current version, tlscheck:
- Performs DNS resolution using Go's `net.LookupIP()` which uses the system's resolver
- Reports DNS-resolved IPs in the `dns_resolved_ips` field
- Allows manual IP override via `--ip-addresses` flag (reported in `override_ips` field)
- Does not capture or report detailed resolver configuration

## Future Enhancements

### Platform-Specific Resolver Detection

Different operating systems configure and manage DNS resolution differently. Future versions of tlscheck could detect and report:

#### Linux (systemd-resolved)
- Detect if systemd-resolved is active (`systemctl is-active systemd-resolved`)
- Parse `/etc/resolv.conf` to identify if it's managed by systemd (symlink to `/run/systemd/resolve/stub-resolv.conf`)
- Query D-Bus interface for resolver configuration: `resolvectl status`
- Report:
  - Active resolver daemon (systemd-resolved, dnsmasq, etc.)
  - Per-interface DNS servers
  - Search domains
  - DNSSEC status
  - DNS-over-TLS configuration

#### macOS
- Query system preferences via `scutil --dns`
- Parse resolver configuration from System Configuration framework
- Report:
  - DNS servers per network interface
  - Search domains
  - Resolver behavior (multicast DNS, LLMNR)
  - Private DNS zones

#### Windows
- Query DNS client configuration via PowerShell: `Get-DnsClientServerAddress`
- Detect DNS zones/partitions: `Get-DnsClientNrptPolicy`
- Report:
  - Primary and secondary DNS servers per adapter
  - DNS suffix search list
  - NRPT (Name Resolution Policy Table) rules
  - Split-brain DNS configurations

### General Resolver Information

Platform-independent information that could be captured:

1. **Resolver Performance**
   - DNS query latency
   - TTL values returned
   - Number of queries required (following CNAME chains)

2. **DNSSEC Validation**
   - Whether DNSSEC is enabled
   - Validation results for queried domains

3. **DNS Query Details**
   - Query type (A, AAAA, both)
   - Number of IPs returned for each type
   - Response codes

4. **Resolver Behavior**
   - Does resolver return IPv4 and/or IPv6?
   - Order of returned addresses
   - Round-robin behavior detection

## Implementation Considerations

### MVP Approach

For a minimum viable product, focus on:
1. Capturing and reporting the basic resolver configuration file (`/etc/resolv.conf` on Unix-like systems)
2. Detecting the most common resolver implementations (systemd-resolved, dnsmasq)
3. Recording DNS query metadata (TTL, number of results, query time)

### Cross-Platform Challenges

- Different platforms use different APIs and configuration formats
- Root/admin privileges may be required for some resolver information
- Some resolver implementations (like systemd-resolved) cache results, making it hard to get "clean" lookups

### Output Format

Resolver information could be added to the output structure as a top-level field:

```json
{
  "arguments": {...},
  "resolver_info": {
    "detected_resolver": "systemd-resolved",
    "nameservers": ["8.8.8.8", "8.8.4.4"],
    "search_domains": ["example.com"],
    "platform": "linux",
    "dnssec_enabled": true,
    "query_time_ms": 45
  },
  "plan": {...},
  "results": [...]
}
```

## Related Work

- `resolvectl` (systemd-resolved management)
- `dig` and `nslookup` (DNS query tools)
- Go's `net` package documentation: https://pkg.go.dev/net
- RFC 6762 (Multicast DNS)
- RFC 8484 (DNS-over-HTTPS)

## Contributing

If you're interested in implementing resolver information gathering, consider:
1. Starting with one platform (preferably the one you use)
2. Creating a pluggable interface for platform-specific implementations
3. Ensuring the feature is optional and doesn't break existing functionality
4. Adding appropriate tests for the resolver detection logic

## TODO

- [ ] Implement basic resolver detection for Linux (systemd-resolved)
- [ ] Add macOS DNS configuration parsing
- [ ] Add Windows DNS configuration support
- [ ] Create abstraction layer for platform-specific implementations
- [ ] Add configuration option to enable/disable resolver info gathering
- [ ] Document privacy considerations when reporting resolver configuration
