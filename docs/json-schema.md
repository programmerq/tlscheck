# JSON Schema Implementation

This document describes the JSON schema implementation for the tlscheck project.

## Overview

The JSON schema provides machine-readable documentation for the tlscheck output format. It enables:

1. **Validation**: Programmatic verification that output matches the expected structure
2. **IDE Support**: Autocomplete and inline documentation in modern editors
3. **Documentation**: Canonical reference for the output format
4. **CI Integration**: Automated checks to ensure schema stays synchronized with code

## Architecture

### Schema Generation (`cmd/schema-gen`)

The schema is generated automatically from Go struct definitions using the `invopop/jsonschema` library. This ensures the schema always reflects the actual code structure.

**Key files:**
- `cmd/schema-gen/main.go`: Generator tool that reflects on Go structs and produces JSON Schema
- `schemas/execution.json`: Generated schema file (1062 lines)

**How it works:**
1. Uses Go reflection to analyze the `runner.Execution` struct
2. Recursively traverses all nested structs (Plan, Result, CertInfo, etc.)
3. Generates JSON Schema Draft 2020-12 compatible output
4. Adds metadata ($id, $schema, title, description)

### Schema Validation (`internal/schema`)

**Key files:**
- `internal/schema/validate_test.go`: Test suite that validates generated output against schema

**Test coverage:**
- `TestExecutionOutputMatchesSchema`: Validates that realistic execution results conform to the schema
- `TestSchemaExists`: Ensures schema file is present
- `TestSchemaIsValidJSON`: Verifies schema is well-formed JSON
- `TestSchemaHasMetadata`: Checks for required metadata fields

**Handling Go's JSON marshaling:**
The validation tests include a `normalizeNullArrays()` function that handles Go's behavior of encoding nil slices as `null` instead of `[]`. This is a known Go limitation and the normalization ensures validation succeeds.

### Build Integration (Makefile)

**New targets:**
- `make schema`: Regenerates the schema from Go structs
- `make schema-check`: Verifies schema is up-to-date (fails if regeneration needed)

**Usage in development:**
```bash
# After modifying output structures:
make schema

# Before committing:
make schema-check
make test
```

### CI Integration (`.github/workflows/pr-checks.yml`)

The PR checks workflow now includes `make schema-check` to ensure:
1. Schema is never out of sync with code
2. Developers remember to regenerate after struct changes
3. Schema changes are reviewed alongside code changes

## Schema Structure

The schema defines these top-level properties:

```json
{
  "arguments": { ... },    // Runtime configuration
  "network": { ... },      // Network discovery data
  "plan": { ... },         // Probe execution plan
  "results": [ ... ],      // Probe results
  "certs": { ... }         // Certificate metadata
}
```

### Key Features

1. **Strict validation**: `additionalProperties: false` prevents unexpected fields
2. **Required fields**: Core fields marked as required
3. **Type safety**: All fields have explicit types
4. **No references**: Schema is fully expanded for easier consumption

## Validation Tools

### Built-in Script (`scripts/validate-output.sh`)

```bash
./tlscheck > output.json
./scripts/validate-output.sh output.json
```

Uses the same validation library as the tests (`santhosh-tekuri/jsonschema/v6`).

### Third-party Tools

The schema is compatible with standard JSON Schema validators:
- `ajv-cli` (Node.js)
- `jsonschema` (Python)
- IDE plugins (VS Code, IntelliJ, etc.)

## Dependencies

**New dependencies added:**
- `github.com/invopop/jsonschema` - Schema generation
- `github.com/santhosh-tekuri/jsonschema/v6` - Schema validation

Both are mature, well-maintained libraries with good compatibility.

## Maintenance

### When to Regenerate

Regenerate the schema whenever you:
- Add/remove fields from output structs
- Change field types
- Modify JSON tags
- Add new output structures

### Versioning

The schema follows tlscheck's versioning. Breaking schema changes should trigger a major version bump.

### Guidelines (AGENTS.md)

Updated to include:
- Requirement to run `make schema` after modifying output structures
- CI enforcement via `make schema-check`
- Schema as part of the definition of done

## Future Enhancements

Potential improvements:
1. **Multiple schema versions**: Support for different output format versions
2. **Examples**: Embed example output in the schema
3. **Descriptions**: Add field-level descriptions via struct tags
4. **Publication**: Host schema at the URL specified in `$id`
5. **Validation in CLI**: Optional `--validate` flag to self-validate output

## References

- [JSON Schema Specification](https://json-schema.org/)
- [invopop/jsonschema](https://github.com/invopop/jsonschema)
- [santhosh-tekuri/jsonschema](https://github.com/santhosh-tekuri/jsonschema)
