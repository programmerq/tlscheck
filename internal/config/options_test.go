package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

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
			name: "IPv6 addresses",
			args: []string{"--proxy-server", "example.com", "--ip-addresses", "2001:0db8:85a3:0000:0000:8a2e:0370:7334,::1,fe80::1"},
			want: []string{"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "::1", "fe80::1"},
		},
		{
			name: "mixed IPv4 and IPv6",
			args: []string{"--proxy-server", "example.com", "--ip-addresses", "192.168.1.1,2001:db8::1,10.0.0.1"},
			want: []string{"192.168.1.1", "2001:db8::1", "10.0.0.1"},
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

func TestParseArgsHeaderFlag(t *testing.T) {
	// Not parallel because ParseArgs sets a global usage variable.

	cases := []struct {
		name    string
		args    []string
		want    map[string]string
		wantErr bool
	}{
		{
			name: "single -H flag",
			args: []string{"--proxy-server", "example.com", "-H", "Authorization: Bearer token123"},
			want: map[string]string{"Authorization": "Bearer token123"},
		},
		{
			name: "single --header flag",
			args: []string{"--proxy-server", "example.com", "--header", "Authorization: Bearer token123"},
			want: map[string]string{"Authorization": "Bearer token123"},
		},
		{
			name: "multiple -H flags",
			args: []string{
				"--proxy-server", "example.com",
				"-H", "Authorization: Bearer abc",
				"-H", "X-Custom: val",
			},
			want: map[string]string{"Authorization": "Bearer abc", "X-Custom": "val"},
		},
		{
			name: "mixed -H and --header flags",
			args: []string{
				"--proxy-server", "example.com",
				"-H", "Authorization: Bearer abc",
				"--header", "X-Custom: val",
			},
			want: map[string]string{"Authorization": "Bearer abc", "X-Custom": "val"},
		},
		{
			name: "no header flags",
			args: []string{"--proxy-server", "example.com"},
			want: nil,
		},
		{
			name:    "missing colon",
			args:    []string{"--proxy-server", "example.com", "-H", "Authorization"},
			wantErr: true,
		},
		{
			name:    "empty header name",
			args:    []string{"--proxy-server", "example.com", "-H", ": value"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			opts, _, err := ParseArgs(tc.args, []string{"proxy_web"})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseArgs() error = %v", err)
			}
			if !reflect.DeepEqual(opts.ExtraHeaders, tc.want) {
				t.Fatalf("ExtraHeaders = %v, want %v", opts.ExtraHeaders, tc.want)
			}
		})
	}
}

func TestParseArgsHeaderFromFile(t *testing.T) {
	// Not parallel because ParseArgs sets a global usage variable.

	dir := t.TempDir()
	headerFile := filepath.Join(dir, "headers.txt")
	content := "# comment line\nAuthorization: Bearer fromfile\nX-Custom: custom-value\n"
	if err := os.WriteFile(headerFile, []byte(content), 0600); err != nil {
		t.Fatalf("writing header file: %v", err)
	}

	args := []string{"--proxy-server", "example.com", "-H", "@" + headerFile}
	opts, _, err := ParseArgs(args, []string{"proxy_web"})
	if err != nil {
		t.Fatalf("ParseArgs() error = %v", err)
	}
	want := map[string]string{
		"Authorization": "Bearer fromfile",
		"X-Custom":      "custom-value",
	}
	if !reflect.DeepEqual(opts.ExtraHeaders, want) {
		t.Fatalf("ExtraHeaders = %v, want %v", opts.ExtraHeaders, want)
	}
}

func TestHeaderFlagSet(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		inputs  []string
		want    map[string]string
		wantErr bool
	}{
		{
			name:   "single header",
			inputs: []string{"Authorization: Bearer token"},
			want:   map[string]string{"Authorization": "Bearer token"},
		},
		{
			name:   "multiple headers via repeated Set",
			inputs: []string{"Authorization: Bearer token", "X-Custom: value"},
			want:   map[string]string{"Authorization": "Bearer token", "X-Custom": "value"},
		},
		{
			name:   "whitespace trimmed",
			inputs: []string{"  Foo : bar  "},
			want:   map[string]string{"Foo": "bar"},
		},
		{
			name:   "later set overrides earlier for same key",
			inputs: []string{"X-Foo: first", "X-Foo: second"},
			want:   map[string]string{"X-Foo": "second"},
		},
		{
			name:    "missing colon",
			inputs:  []string{"Authorization"},
			wantErr: true,
		},
		{
			name:    "empty header name",
			inputs:  []string{": value"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var h headerFlag
			var lastErr error
			for _, input := range tc.inputs {
				if err := h.Set(input); err != nil {
					lastErr = err
					break
				}
			}
			if tc.wantErr {
				if lastErr == nil {
					t.Fatal("expected error but got nil")
				}
				return
			}
			if lastErr != nil {
				t.Fatalf("unexpected error: %v", lastErr)
			}
			if !reflect.DeepEqual(h.headers, tc.want) {
				t.Fatalf("headers = %v, want %v", h.headers, tc.want)
			}
		})
	}
}
