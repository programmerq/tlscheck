# TLS Check JSON Schema

This directory contains the JSON Schema definition for the `tlscheck` output format.

## Overview

The schema defines the complete structure of the JSON output produced by the `tlscheck` CLI tool. This includes:

- **arguments**: Runtime configuration and CLI options
- **network**: Network discovery information (proxy configuration, routing table, VPN detection)
- **plan**: The generated probe execution plan
- **results**: Individual probe results with connection details, certificate info, and failures
- **certs**: Certificate metadata indexed by SHA-256 fingerprint

## Schema File

- `execution.json` - Complete schema for the Execution output structure

### Schema URL

The schema is identified by: `https://github.com/programmerq/tlscheck/schemas/execution.json`

This URL is embedded in the schema's `$id` field and can be used by validators and IDEs.

## Using the Schema

### IDE Integration

Many modern IDEs and editors support JSON Schema validation. You can reference the schema in your JSON files:

```json
{
  "$schema": "https://github.com/programmerq/tlscheck/schemas/execution.json",
  "arguments": { ... }
}
```

### Validation

The schema can be used to validate `tlscheck` output programmatically. See `internal/schema/validate_test.go` for examples.

### Command Line Validation

You can use the provided validation script:

```bash
# Run tlscheck and save output
./tlscheck > output.json

# Validate the output against the schema
./scripts/validate-output.sh output.json
```

Or use third-party tools like `ajv-cli`:

```bash
# Install ajv-cli
npm install -g ajv-cli

# Validate tlscheck output
tlscheck | tee output.json
ajv validate -s schemas/execution.json -d output.json
```

## Generating the Schema

The schema is automatically generated from the Go struct definitions using the `cmd/schema-gen` tool.

```bash
# Generate the schema
make schema

# Verify schema is up-to-date (fails if schema needs regeneration)
make schema-check
```

The schema generation is integrated into the development workflow:

1. **During development**: Run `make schema` after modifying output structures
2. **In CI**: Run `make schema-check` to ensure the schema stays synchronized

## Schema Versioning

The schema follows the same versioning as the tlscheck tool. Breaking changes to the output
format will result in a major version bump.

## Compatibility Notes

- The schema is compatible with JSON Schema Draft 2020-12
- Array fields may be `null` or `[]` (empty array) due to Go's JSON marshaling behavior
- The `omitempty` tag is used extensively, so many fields may be absent from the output
- Duration fields (e.g., `dial_duration_ms`, `handshake_duration_ms`) are encoded as integers representing nanoseconds, despite the `_ms` suffix in the field name

## Documentation

The schema serves as the canonical documentation for the `tlscheck` output format. For
human-readable documentation, see:

- [README.md](../README.md) - General overview of output structure
- [docs/design.md](../docs/design.md) - Design decisions and probe matrix

## Contributing

When adding new fields or modifying the output structure:

1. Update the relevant Go structs in `internal/`
2. Run `make schema` to regenerate the schema
3. Run `make test` to ensure validation tests pass
4. Update documentation if the changes affect user-visible behavior
5. Commit both the code changes and the updated schema
