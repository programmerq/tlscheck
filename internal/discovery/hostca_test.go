package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const sampleHostCAPEM = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUGzJrped1IovnHgwlHGhEq+y3OCkwCgYIKoZIzj0EAwIw\nFDESMBAGA1UEAwwJdGVzdC5jYS5pbyAwHhcNMjQwMTAxMDAwMDAwWhcNMzQwMTAx\nMDAwMDAwWjAUMRIwEAYDVQQDDAl0ZXN0LmNhLmlvMFkwEwYHKoZIzj0CAQYIKoZI\nzj0DAQcDQgAE6yOD87o5iV/mQJu1WDVYj1WFJsbgx5caX5/C/PObbIVdQydb9h9t\nW7x1YgnSUZXoqBYwygJyI072QtdgQXMMB6NTMFEwHQYDVR0OBBYEFNyEJD7BqXc9\n4HIX66D+QP9enZ5hMB8GA1UdIwQYMBaAFNyEJD7BqXc94HIX66D+QP9enZ5hMA8G\nA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgCZ3swaP42gnikIze8ihc\nYtL6vhfVqlhK/SXxPxq8npACIQDB0Gooy2cuglRez2oJ6TP2PzefDs2fzGEylh4G\nWXNoWA==\n-----END CERTIFICATE-----\n"

func TestFetchHostCAs(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/webapi/auth/export":
			if got := r.URL.Query().Get("type"); got != "tls-host" {
				t.Fatalf("unexpected type query: %q", got)
			}
			if _, err := w.Write([]byte(sampleHostCAPEM)); err != nil {
				t.Fatalf("write host CA: %v", err)
			}
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	bundle, err := FetchHostCAs(context.Background(), srv.URL, ProxySettings{})
	if err != nil {
		t.Fatalf("FetchHostCAs returned error: %v", err)
	}

	if string(bundle) != sampleHostCAPEM {
		t.Fatalf("unexpected bundle contents: %q", string(bundle))
	}
}

func TestFetchHostCAsRejectsEmptyBody(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/webapi/auth/export":
			// return OK with empty body
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	if _, err := FetchHostCAs(context.Background(), srv.URL, ProxySettings{}); err == nil {
		t.Fatal("expected error when host CA body empty")
	}
}

func TestFetchHostCAsFallsBackOnCertError(t *testing.T) {
	t.Parallel()

	// Use a TLS server with self-signed certificate - this would fail
	// certificate verification, so the function should fall back to insecure mode
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/webapi/auth/export":
			if got := r.URL.Query().Get("type"); got != "tls-host" {
				t.Fatalf("unexpected type query: %q", got)
			}
			if _, err := w.Write([]byte(sampleHostCAPEM)); err != nil {
				t.Fatalf("write host CA: %v", err)
			}
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	// This request will first fail with "x509: certificate signed by unknown authority"
	// then retry with InsecureSkipVerify and succeed
	bundle, err := FetchHostCAs(context.Background(), srv.URL, ProxySettings{})
	if err != nil {
		t.Fatalf("FetchHostCAs returned error (expected to fall back to insecure): %v", err)
	}

	if string(bundle) != sampleHostCAPEM {
		t.Fatalf("unexpected bundle contents: %q", string(bundle))
	}
}

func TestFetchHostCAsWithStatusCapturesCertError(t *testing.T) {
	t.Parallel()

	// Use a TLS server with self-signed certificate
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/webapi/auth/export":
			if _, err := w.Write([]byte(sampleHostCAPEM)); err != nil {
				t.Fatalf("write host CA: %v", err)
			}
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	result, err := FetchHostCAsWithStatus(context.Background(), srv.URL, ProxySettings{})
	if err != nil {
		t.Fatalf("FetchHostCAsWithStatus returned error: %v", err)
	}

	if string(result.Bundle) != sampleHostCAPEM {
		t.Fatalf("unexpected bundle contents: %q", string(result.Bundle))
	}

	// Verify that we detected the verification failure and fell back
	if !result.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify to be true")
	}
	if result.TLSVerificationSucceeded {
		t.Fatal("expected TLSVerificationSucceeded to be false")
	}
	if result.TLSVerificationError == "" {
		t.Fatal("expected TLSVerificationError to capture the original error")
	}
	t.Logf("Captured TLS verification error: %s", result.TLSVerificationError)
}
