package config

import "testing"

func TestSplitCSV(t *testing.T) {
	t.Parallel()

	got := splitCSV(" proxy_web ,proxy_ssh , ,")
	want := []string{"proxy_web", "proxy_ssh"}
	if len(got) != len(want) {
		t.Fatalf("unexpected length: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("element %d = %q want %q", i, got[i], want[i])
		}
	}
}

func TestOptionsWantsService(t *testing.T) {
	t.Parallel()

	opts := Options{ServiceFilter: []string{"proxy_web", "db_postgres"}}

	cases := []struct {
		key  string
		want bool
	}{
		{"proxy_web", true},
		{"PROXY_WEB", true},
		{"db_mysql", false},
	}

	for _, tc := range cases {
		if got := opts.WantsService(tc.key); got != tc.want {
			t.Fatalf("WantsService(%q) = %v want %v", tc.key, got, tc.want)
		}
	}
}
