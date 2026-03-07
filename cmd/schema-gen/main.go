package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/invopop/jsonschema"
	"github.com/programmerq/tlscheck/internal/runner"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <output-dir>\n", os.Args[0])
		os.Exit(1)
	}

	outputDir := os.Args[1]

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	// Generate schema for the Execution struct (top-level output)
	// TODO: Setting DoNotReference to false would produce a more compact schema
	// using $defs/$ref for shared types (e.g. ProbeTarget appears in both Plan.Targets
	// and Result.Target). Evaluate whether downstream schema consumers handle $ref
	// reliably before making that change.
	reflector := &jsonschema.Reflector{
		AllowAdditionalProperties: false,
		DoNotReference:            true,
		ExpandedStruct:            true,
	}

	schema := reflector.Reflect(&runner.Execution{})

	// Add metadata
	schema.ID = jsonschema.ID("https://github.com/programmerq/tlscheck/schemas/execution.json")
	schema.Version = "https://json-schema.org/draft/2020-12/schema"
	schema.Title = "TLS Check Execution Result"
	schema.Description = "The complete output from a tlscheck execution, including arguments, network discovery, probe plan, results, and certificate details."

	// Marshal to JSON with indentation
	schemaJSON, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal schema: %v\n", err)
		os.Exit(1)
	}

	// Write schema to file
	schemaPath := filepath.Join(outputDir, "execution.json")
	if err := os.WriteFile(schemaPath, schemaJSON, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write schema file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully generated schema: %s\n", schemaPath)
}
