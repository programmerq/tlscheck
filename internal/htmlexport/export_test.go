package htmlexport

import (
	"bytes"
	"strings"
	"testing"

	"github.com/programmerq/tlscheck/internal/config"
	"github.com/programmerq/tlscheck/internal/plan"
	"github.com/programmerq/tlscheck/internal/probe"
	"github.com/programmerq/tlscheck/internal/runner"
)

func TestWriteGeneratesValidHTML(t *testing.T) {
	exec := runner.Execution{
		Arguments: &config.Options{
			PublicAddr:        "teleport.example.com",
			ClusterName:       "test-cluster",
			TeleportVersion:   "15.0.0",
			TLSRoutingEnabled: true,
			Repeat:            1,
		},
		Plan: plan.Plan{
			Targets: []plan.ProbeTarget{
				{
					ServiceKey: "proxy_web",
					Address:    "teleport.example.com",
					Port:       443,
					PrimarySNI: "teleport.example.com",
					ALPNs:      []string{"h2"},
					Repeat:     1,
				},
			},
		},
		Results: []probe.Result{
			{
				Target: plan.ProbeTarget{
					ServiceKey: "proxy_web",
					Address:    "teleport.example.com",
					Port:       443,
					PrimarySNI: "teleport.example.com",
					ALPNs:      []string{"h2"},
				},
				Attempt:            1,
				NegotiatedProtocol: "h2",
				TLSVersion:         "TLS 1.3",
			},
		},
	}

	var buf bytes.Buffer
	err := Write(&buf, exec)
	if err != nil {
		t.Fatalf("Write() returned error: %v", err)
	}

	html := buf.String()

	// Check for essential HTML elements
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("HTML output missing DOCTYPE declaration")
	}
	if !strings.Contains(html, "<html") {
		t.Error("HTML output missing html tag")
	}
	if !strings.Contains(html, "<head>") {
		t.Error("HTML output missing head tag")
	}
	if !strings.Contains(html, "<body>") {
		t.Error("HTML output missing body tag")
	}
	if !strings.Contains(html, "TLS Check Results") {
		t.Error("HTML output missing title")
	}

	// Check for embedded JSON data
	if !strings.Contains(html, "const tlsCheckData") {
		t.Error("HTML output missing embedded JSON data")
	}
	if !strings.Contains(html, "test-cluster") {
		t.Error("HTML output missing cluster name from data")
	}
	if !strings.Contains(html, "teleport.example.com") {
		t.Error("HTML output missing proxy address from data")
	}

	// Check for CSS
	if !strings.Contains(html, "<style>") {
		t.Error("HTML output missing CSS")
	}

	// Check for JavaScript
	if !strings.Contains(html, "<script>") {
		t.Error("HTML output missing JavaScript")
	}
}

func TestWriteHandlesEmptyResults(t *testing.T) {
	exec := runner.Execution{
		Arguments: &config.Options{
			PublicAddr:  "teleport.example.com",
			ClusterName: "test-cluster",
		},
		Plan:    plan.Plan{},
		Results: []probe.Result{},
	}

	var buf bytes.Buffer
	err := Write(&buf, exec)
	if err != nil {
		t.Fatalf("Write() returned error for empty results: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("HTML output for empty results missing DOCTYPE declaration")
	}
}

func TestWriteHandlesFailures(t *testing.T) {
	exec := runner.Execution{
		Arguments: &config.Options{
			PublicAddr:  "teleport.example.com",
			ClusterName: "test-cluster",
		},
		Results: []probe.Result{
			{
				Target: plan.ProbeTarget{
					ServiceKey: "proxy_web",
					Address:    "teleport.example.com",
					Port:       443,
				},
				Attempt: 1,
				Failure: &probe.Failure{
					Kind:    "timeout",
					Message: "connection timed out",
				},
			},
		},
	}

	var buf bytes.Buffer
	err := Write(&buf, exec)
	if err != nil {
		t.Fatalf("Write() returned error for failed results: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "timeout") {
		t.Error("HTML output missing failure kind")
	}
	if !strings.Contains(html, "connection timed out") {
		t.Error("HTML output missing failure message")
	}
}

func TestWriteSelfContained(t *testing.T) {
	exec := runner.Execution{
		Arguments: &config.Options{
			PublicAddr: "teleport.example.com",
		},
		Results: []probe.Result{},
	}

	var buf bytes.Buffer
	err := Write(&buf, exec)
	if err != nil {
		t.Fatalf("Write() returned error: %v", err)
	}

	html := buf.String()

	// Check that there are no external dependencies
	if strings.Contains(html, "http://") || strings.Contains(html, "https://") {
		// Allow only schema URLs which are not loaded
		lines := strings.Split(html, "\n")
		for _, line := range lines {
			if (strings.Contains(line, "http://") || strings.Contains(line, "https://")) &&
				!strings.Contains(line, "schema") && !strings.Contains(line, "github.com") {
				t.Errorf("HTML contains external URL that may not be self-contained: %s", line)
			}
		}
	}

	// Ensure CSS is embedded
	if !strings.Contains(html, "<style>") {
		t.Error("HTML does not contain embedded CSS")
	}

	// Ensure JavaScript is embedded
	if !strings.Contains(html, "<script>") {
		t.Error("HTML does not contain embedded JavaScript")
	}
}
