---
name: Enhance Profile Credential Security and Transparency
about: Improve visibility and control over automatic tsh profile credential usage
title: 'Enhancement: Add --use-profile-credentials flag and warning output for credential usage'
labels: enhancement, security
assignees: ''
---

## Background

Currently, `tlscheck` automatically discovers and uses credentials from the user's `.tsh` profile directory when `--proxy-server` is not specified. While this mimics `tsh` behavior and provides convenience, it raises security considerations around implicit credential usage and transparency.

## Proposed Changes

### 1. Add `--use-profile-credentials` Flag (Default: true)

Add a new CLI flag to provide explicit control over credential usage:

```bash
--use-profile-credentials    Enable/disable automatic loading of client certificates from tsh profiles (default: true)
```

**Behavior:**
- When `true` (default): Current behavior - automatically load and use client certs from profile
- When `false`: Skip client certificate loading even if profile is discovered
- Users can opt-out with `--use-profile-credentials=false` for read-only profile discovery

**Implementation:**
- Add boolean field to `Options` struct in `internal/config/options.go`
- Update CLI flag parsing in `ParseArgs()`
- Modify `ResolveRuntime()` in `internal/config/runtime.go` to respect the flag
- Skip `LoadClientCert()` call when flag is false

### 2. Add Warning Output for Profile Usage

Display clear warnings when credentials are loaded to increase transparency:

**Output format:**
```
[INFO] Using Teleport profile: /Users/username/.tsh/example.com.yaml
[INFO] Using client certificate from profile: username@example.com (expires: 2025-12-15T10:30:00Z)
```

**Implementation:**
- Add logging statements before loading profile (show full path)
- Add logging after successful client cert load (show username, cluster, expiration)
- Display warnings to stderr (not just --verbose mode)
- Include certificate expiration time from `NotAfter` field

### 3. Add Bogus Client Certificate Testing

Implement a fallback mechanism to test with a self-signed/bogus client certificate when no valid tsh credentials are available:

**Purpose:**
- Detect load balancers terminating TLS before Teleport
- Provide diagnostic value even without valid credentials
- Differentiate between:
  - Server accepts connection (LB terminating TLS)
  - Server rejects with cert verification error (expected)
  - No difference from no-cert connection (LB stripping client certs)

**Implementation:**
- Generate ephemeral self-signed client certificate in-memory
- Use for mTLS probes when `--use-profile-credentials=false` or when no profile exists
- Flag results as "bogus_cert_test" in probe output
- Document expected behaviors in output notes

**Behavior matrix:**
```
Has Profile Cert | --use-profile-credentials | Behavior
----------------|---------------------------|----------
Yes             | true (default)            | Use profile cert
Yes             | false                     | Use bogus cert
No              | true                      | Use bogus cert
No              | false                     | Use bogus cert
```

## Benefits

1. **Security:** Explicit control over credential usage
2. **Transparency:** Users know when their credentials are being used
3. **Diagnostics:** Bogus cert testing provides value regardless of profile availability
4. **Backwards Compatible:** Default behavior unchanged (default true)
5. **Load Balancer Detection:** Identifies TLS termination issues

## Testing Considerations

- Test with valid profile credentials
- Test with `--use-profile-credentials=false`
- Test without any profile (fallback to bogus cert)
- Test with expired profile credentials
- Verify warning messages appear correctly
- Test bogus cert against real Teleport cluster (should reject)
- Test bogus cert behavior vs no-cert behavior

## Documentation Updates

- Update README.md to document `--use-profile-credentials` flag
- Add section explaining credential usage and transparency
- Document bogus certificate testing behavior
- Update CLI help text

## Related Files

- `internal/config/options.go` - Add flag
- `internal/config/runtime.go` - Implement credential loading logic
- `internal/discovery/profile.go` - May need certificate generation utilities
- `cmd/tlscheck/main.go` - CLI flag parsing
- `README.md` - Documentation

## Security Considerations

This enhancement improves security posture by:
- Making credential usage explicit and controllable
- Providing clear visibility into which credentials are used
- Allowing security-conscious users to disable automatic credential loading
- Maintaining backwards compatibility with existing workflows

## Priority

Medium - Enhancement that improves security transparency and diagnostic capabilities without breaking existing functionality.
