#!/bin/bash
# validate-output.sh
# Usage: ./validate-output.sh <output-file>
#
# Validates a tlscheck JSON output file against the JSON schema.
# Requires: go

set -e

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <output-file>"
    exit 1
fi

OUTPUT_FILE="$1"

if [ ! -f "$OUTPUT_FILE" ]; then
    echo "Error: File '$OUTPUT_FILE' not found"
    exit 1
fi

# Create a temporary test file that validates the output
cat > /tmp/validate_output_test.go <<'EOF'
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <output-file>\n", os.Args[0])
		os.Exit(1)
	}

	// Load the schema
	schemaPath := "schemas/execution.json"
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read schema: %v\n", err)
		os.Exit(1)
	}

	// Compile schema
	compiler := jsonschema.NewCompiler()
	var schemaObj interface{}
	if err := json.Unmarshal(schemaData, &schemaObj); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse schema: %v\n", err)
		os.Exit(1)
	}

	schemaURL := "https://github.com/programmerq/tlscheck/schemas/execution.json"
	if err := compiler.AddResource(schemaURL, schemaObj); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to add schema: %v\n", err)
		os.Exit(1)
	}

	schema, err := compiler.Compile(schemaURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to compile schema: %v\n", err)
		os.Exit(1)
	}

	// Load and validate output
	outputPath := os.Args[1]
	outputData, err := os.ReadFile(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read output: %v\n", err)
		os.Exit(1)
	}

	var output interface{}
	if err := json.Unmarshal(outputData, &output); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse output JSON: %v\n", err)
		os.Exit(1)
	}

	if err := schema.Validate(output); err != nil {
		fmt.Fprintf(os.Stderr, "Validation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ %s validates against schema\n", filepath.Base(outputPath))
}
EOF

# Run the validator
cd "$(dirname "$0")/.."
go run /tmp/validate_output_test.go "$OUTPUT_FILE"

# Clean up
rm /tmp/validate_output_test.go
