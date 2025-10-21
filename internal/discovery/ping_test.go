package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchClusterInfo(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webapi/ping" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		payload := map[string]string{
			"cluster_name":   "root.example.com",
			"server_version": "v17.3.2",
		}
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			t.Fatalf("failed to encode payload: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	info, err := FetchClusterInfo(context.Background(), srv.URL, ProxySettings{})
	if err != nil {
		t.Fatalf("FetchClusterInfo returned error: %v", err)
	}

	if info.ClusterName != "root.example.com" {
		t.Fatalf("ClusterName = %q, want root.example.com", info.ClusterName)
	}
	if info.ServerVersion != "v17.3.2" {
		t.Fatalf("ServerVersion = %q, want v17.3.2", info.ServerVersion)
	}
}
