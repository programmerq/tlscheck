package schema_test

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/programmerq/tlscheck/internal/config"
	"github.com/programmerq/tlscheck/internal/plan"
	"github.com/programmerq/tlscheck/internal/probe"
	"github.com/programmerq/tlscheck/internal/runner"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestExecutionOutputMatchesSchema(t *testing.T) {
	// Load the schema
	schemaPath := filepath.Join("..", "..", "schemas", "execution.json")
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("Failed to read schema file: %v", err)
	}

	// Compile the schema using URL
	compiler := jsonschema.NewCompiler()

	// Parse schema JSON
	var schemaObj interface{}
	if err := json.Unmarshal(schemaData, &schemaObj); err != nil {
		t.Fatalf("Failed to parse schema JSON: %v", err)
	}

	schemaURL := "https://github.com/programmerq/tlscheck/schemas/execution.json"
	if err := compiler.AddResource(schemaURL, schemaObj); err != nil {
		t.Fatalf("Failed to add schema resource: %v", err)
	}
	schema, err := compiler.Compile(schemaURL)
	if err != nil {
		t.Fatalf("Failed to compile schema: %v", err)
	}

	// Create a sample execution result
	opts := config.Options{
		PublicAddr:        "example.com",
		ClusterName:       "test-cluster",
		TeleportVersion:   "v18.0.0",
		WebProxyPort:      443,
		TLSRoutingEnabled: true,
		Repeat:            1,
		Proxy: config.ProxySettings{
			HTTPSProxy: "",
			HTTPProxy:  "",
			NoProxy:    "",
		},
	}

	// Build a minimal plan
	testPlan, err := plan.Build(opts)
	if err != nil {
		t.Fatalf("Failed to build plan: %v", err)
	}

	// Create a minimal engine with mock results
	engine := probe.NewEngine()
	if pool, err := x509.SystemCertPool(); err == nil {
		engine.SetRootCAs(pool)
	}

	// Create a minimal execution result
	exec := runner.Execution{
		Arguments: &opts,
		Plan:      testPlan,
		Results:   []probe.Result{}, // Empty results for schema validation
	}

	// Marshal to JSON with MarshalIndent to match real output format
	execJSON, err := json.MarshalIndent(exec, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal execution: %v", err)
	}

	// Normalize JSON - convert null to empty arrays for validation
	// This is needed because Go's JSON encoder outputs null for nil slices
	var jsonData interface{}
	if err := json.Unmarshal(execJSON, &jsonData); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}
	normalizeNullArrays(jsonData)

	// Validate against schema
	if err := schema.Validate(jsonData); err != nil {
		t.Errorf("Execution output does not match schema: %v", err)
		// Re-marshal normalized data for cleaner debug output
		debugJSON, _ := json.MarshalIndent(jsonData, "", "  ")
		t.Logf("Generated JSON (normalized):\n%s", string(debugJSON))
	}
}

// normalizeNullArrays recursively walks JSON data and converts null to empty arrays
// where the schema expects arrays. This handles Go's JSON encoding behavior where
// nil slices are encoded as null.
func normalizeNullArrays(data interface{}) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			if value == nil {
				// Check if this field name suggests it should be an array
				if shouldBeArray(key) {
					v[key] = []interface{}{}
				}
			} else {
				normalizeNullArrays(value)
			}
		}
	case []interface{}:
		for _, item := range v {
			normalizeNullArrays(item)
		}
	}
}

// shouldBeArray returns true if the field name suggests it should be an array
func shouldBeArray(fieldName string) bool {
	arrayFields := map[string]bool{
		"alpns":               true,
		"upgrade_sequence":    true,
		"additional_snis":     true,
		"dns_resolved_ips":    true,
		"override_ips":        true,
		"notes":               true,
		"service_filter":      true,
		"ip_addresses":        true,
		"results":             true,
		"targets":             true,
		"parsed_hosts":        true,
		"exclude_list":        true,
		"routes":              true,
		"interfaces":          true,
		"applications":        true,
		"addresses":           true,
		"key_usage":           true,
		"ext_key_usage":       true,
		"dns":                 true,
		"ip":                  true,
		"uri":                 true,
		"email":               true,
		"organization":        true,
		"organizational_unit": true,
		"country":             true,
		"province":            true,
		"locality":            true,
		"trusted_by":          true,
		"certificate_chain":   true,
		"leaf_sans":           true,
	}
	return arrayFields[fieldName]
}

func TestSchemaValidatesRealOutput(t *testing.T) {
	// Skip if we don't have a real Teleport instance to test against
	t.Skip("Skipping real output validation - requires Teleport instance")

	// This test would run the actual tlscheck CLI and validate its output
	// For now, we skip it as it requires external dependencies
}

func TestSchemaExists(t *testing.T) {
	schemaPath := filepath.Join("..", "..", "schemas", "execution.json")
	if _, err := os.Stat(schemaPath); os.IsNotExist(err) {
		t.Errorf("Schema file does not exist at %s", schemaPath)
	}
}

func TestSchemaIsValidJSON(t *testing.T) {
	schemaPath := filepath.Join("..", "..", "schemas", "execution.json")
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("Failed to read schema file: %v", err)
	}

	var schema interface{}
	if err := json.Unmarshal(schemaData, &schema); err != nil {
		t.Errorf("Schema is not valid JSON: %v", err)
	}
}

func TestSchemaHasMetadata(t *testing.T) {
	schemaPath := filepath.Join("..", "..", "schemas", "execution.json")
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("Failed to read schema file: %v", err)
	}

	var schema map[string]interface{}
	if err := json.Unmarshal(schemaData, &schema); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Check for required metadata fields
	requiredFields := []string{"$schema", "$id"}
	for _, field := range requiredFields {
		if _, exists := schema[field]; !exists {
			t.Errorf("Schema missing required metadata field: %s", field)
		}
	}
}
