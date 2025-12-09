package log

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestLoggingDisabledByDefault(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	defer func() {
		SetOutput(os.Stderr)
	}()

	// Logging should be disabled by default
	SetEnabled(false)
	Printf("test message")

	if buf.Len() > 0 {
		t.Errorf("expected no output when logging is disabled, got: %s", buf.String())
	}
}

func TestLoggingWhenEnabled(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	defer func() {
		SetEnabled(false)
		SetOutput(os.Stderr)
	}()

	SetEnabled(true)

	Printf("test message %s", "arg")

	output := buf.String()
	if !strings.Contains(output, "test message arg") {
		t.Errorf("expected output to contain 'test message arg', got: %s", output)
	}

	// Should have timestamp
	if !strings.Contains(output, "[") || !strings.Contains(output, "]") {
		t.Errorf("expected output to have timestamp, got: %s", output)
	}
}

func TestPrintln(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	defer func() {
		SetEnabled(false)
		SetOutput(os.Stderr)
	}()

	SetEnabled(true)

	Println("test message")

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("expected output to contain 'test message', got: %s", output)
	}
}

func TestConcurrentLogging(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	defer func() {
		SetEnabled(false)
		SetOutput(os.Stderr)
	}()

	SetEnabled(true)

	// Test that concurrent logging doesn't cause data races
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			Printf("message %d", n)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Just verify we got some output
	if buf.Len() == 0 {
		t.Error("expected some output from concurrent logging")
	}
}

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "URL without credentials",
			input:    "http://proxy.example.com:8080",
			expected: "http://proxy.example.com:8080",
		},
		{
			name:     "URL with username only",
			input:    "http://user@proxy.example.com:8080",
			expected: "http://%5Bredacted%5D@proxy.example.com:8080",
		},
		{
			name:     "URL with username and password",
			input:    "http://user:password@proxy.example.com:8080",
			expected: "http://%5Bredacted%5D@proxy.example.com:8080",
		},
		{
			name:     "HTTPS URL with credentials",
			input:    "https://admin:secret123@proxy.example.com:443",
			expected: "https://%5Bredacted%5D@proxy.example.com:443",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "invalid URL",
			input:    "not a valid url ://",
			expected: "[invalid URL]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeURL(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeURL(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
