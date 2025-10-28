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

func TestParseArgsWithIPAddresses(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "single IP",
			args: []string{"--proxy-server", "example.com", "--ip-addresses", "192.168.1.1"},
			want: []string{"192.168.1.1"},
		},
		{
			name: "multiple IPs",
			args: []string{"--proxy-server", "example.com", "--ip-addresses", "192.168.1.1,10.0.0.1,172.16.0.1"},
			want: []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"},
		},
		{
			name: "IPs with spaces",
			args: []string{"--proxy-server", "example.com", "--ip-addresses", " 192.168.1.1 , 10.0.0.1 , 172.16.0.1 "},
			want: []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"},
		},
		{
			name: "no IP addresses",
			args: []string{"--proxy-server", "example.com"},
			want: nil,
		},
		{
			name: "empty IP addresses string",
			args: []string{"--proxy-server", "example.com", "--ip-addresses", ""},
			want: nil,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Note: Not parallel because ParseArgs sets a global usage variable
			opts, _, err := ParseArgs(tc.args, []string{"proxy_web"})
			if err != nil {
				t.Fatalf("ParseArgs() error = %v", err)
			}
			if len(opts.IPAddresses) != len(tc.want) {
				t.Fatalf("IPAddresses length = %d, want %d", len(opts.IPAddresses), len(tc.want))
			}
			for i, ip := range tc.want {
				if opts.IPAddresses[i] != ip {
					t.Fatalf("IPAddresses[%d] = %q, want %q", i, opts.IPAddresses[i], ip)
				}
			}
		})
	}
}
