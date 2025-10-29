package discovery

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestDetectEnvironmentProxies(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		expected EnvironmentProxies
	}{
		{
			name: "all proxies set",
			env: map[string]string{
				"HTTPS_PROXY": "https://proxy.example.com:8443",
				"HTTP_PROXY":  "http://proxy.example.com:8080",
				"NO_PROXY":    "localhost,127.0.0.1",
				"ALL_PROXY":   "socks5://socks.example.com:1080",
				"FTP_PROXY":   "ftp://ftp.example.com:21",
			},
			expected: EnvironmentProxies{
				HTTPSProxy: "https://proxy.example.com:8443",
				HTTPProxy:  "http://proxy.example.com:8080",
				NoProxy:    "localhost,127.0.0.1",
				AllProxy:   "socks5://socks.example.com:1080",
				FTPProxy:   "ftp://ftp.example.com:21",
				Parsed:     []string{"proxy.example.com:8443", "proxy.example.com:8080", "socks.example.com:1080"},
			},
		},
		{
			name: "lowercase variants",
			env: map[string]string{
				"https_proxy": "https://proxy.local:8443",
				"http_proxy":  "http://proxy.local:8080",
			},
			expected: EnvironmentProxies{
				HTTPSProxy: "https://proxy.local:8443",
				HTTPProxy:  "http://proxy.local:8080",
				Parsed:     []string{"proxy.local:8443", "proxy.local:8080"},
			},
		},
		{
			name: "uppercase takes precedence",
			env: map[string]string{
				"HTTPS_PROXY": "https://upper.example.com:8443",
				"https_proxy": "https://lower.example.com:8443",
			},
			expected: EnvironmentProxies{
				HTTPSProxy: "https://upper.example.com:8443",
				Parsed:     []string{"upper.example.com:8443"},
			},
		},
		{
			name:     "no proxies set",
			env:      map[string]string{},
			expected: EnvironmentProxies{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
				"NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy", "FTP_PROXY", "ftp_proxy"} {
				os.Unsetenv(key)
			}

			// Set test environment
			for k, v := range tt.env {
				os.Setenv(k, v)
			}

			// Run test
			result := detectEnvironmentProxies()

			// Verify results
			if result.HTTPSProxy != tt.expected.HTTPSProxy {
				t.Errorf("HTTPSProxy: got %q, want %q", result.HTTPSProxy, tt.expected.HTTPSProxy)
			}
			if result.HTTPProxy != tt.expected.HTTPProxy {
				t.Errorf("HTTPProxy: got %q, want %q", result.HTTPProxy, tt.expected.HTTPProxy)
			}
			if result.NoProxy != tt.expected.NoProxy {
				t.Errorf("NoProxy: got %q, want %q", result.NoProxy, tt.expected.NoProxy)
			}
			if result.AllProxy != tt.expected.AllProxy {
				t.Errorf("AllProxy: got %q, want %q", result.AllProxy, tt.expected.AllProxy)
			}
			if result.FTPProxy != tt.expected.FTPProxy {
				t.Errorf("FTPProxy: got %q, want %q", result.FTPProxy, tt.expected.FTPProxy)
			}

			// Check parsed hosts
			if len(result.Parsed) != len(tt.expected.Parsed) {
				t.Errorf("Parsed hosts length: got %d, want %d", len(result.Parsed), len(tt.expected.Parsed))
			} else {
				parsedMap := make(map[string]bool)
				for _, p := range result.Parsed {
					parsedMap[p] = true
				}
				for _, expected := range tt.expected.Parsed {
					if !parsedMap[expected] {
						t.Errorf("Expected parsed host %q not found", expected)
					}
				}
			}

			// Clean up
			for k := range tt.env {
				os.Unsetenv(k)
			}
		})
	}
}

func TestDetectSOCKSProxy(t *testing.T) {
	tests := []struct {
		name     string
		allProxy string
		expected *SOCKSProxyInfo
	}{
		{
			name:     "SOCKS5 proxy",
			allProxy: "socks5://socks.example.com:1080",
			expected: &SOCKSProxyInfo{
				Version: "SOCKS5",
				Address: "socks.example.com",
				Port:    1080,
				Source:  "ALL_PROXY environment variable",
			},
		},
		{
			name:     "SOCKS4 proxy",
			allProxy: "socks4://socks.example.com:1080",
			expected: &SOCKSProxyInfo{
				Version: "SOCKS4",
				Address: "socks.example.com",
				Port:    1080,
				Source:  "ALL_PROXY environment variable",
			},
		},
		{
			name:     "SOCKS proxy without version",
			allProxy: "socks://socks.example.com:1080",
			expected: &SOCKSProxyInfo{
				Version: "SOCKS5",
				Address: "socks.example.com",
				Port:    1080,
				Source:  "ALL_PROXY environment variable",
			},
		},
		{
			name:     "non-SOCKS proxy",
			allProxy: "http://proxy.example.com:8080",
			expected: nil,
		},
		{
			name:     "empty",
			allProxy: "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv("ALL_PROXY")
			os.Unsetenv("all_proxy")

			if tt.allProxy != "" {
				os.Setenv("ALL_PROXY", tt.allProxy)
			}

			result := detectSOCKSProxy()

			if tt.expected == nil {
				if result != nil {
					t.Errorf("Expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatalf("Expected non-nil result, got nil")
			}

			if result.Version != tt.expected.Version {
				t.Errorf("Version: got %q, want %q", result.Version, tt.expected.Version)
			}
			if result.Address != tt.expected.Address {
				t.Errorf("Address: got %q, want %q", result.Address, tt.expected.Address)
			}
			if result.Port != tt.expected.Port {
				t.Errorf("Port: got %d, want %d", result.Port, tt.expected.Port)
			}

			os.Unsetenv("ALL_PROXY")
		})
	}
}

func TestParseLinuxRoutes(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		expected []Route
	}{
		{
			name: "typical ip route output",
			output: `default via 192.168.1.1 dev eth0
10.0.0.0/8 via 10.0.0.1 dev tun0
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100`,
			expected: []Route{
				{
					Destination: "default",
					Gateway:     "192.168.1.1",
					Interface:   "eth0",
				},
				{
					Destination: "10.0.0.0/8",
					Gateway:     "10.0.0.1",
					Interface:   "tun0",
				},
				{
					Destination: "192.168.1.0/24",
					Interface:   "eth0",
				},
			},
		},
		{
			name:     "empty output",
			output:   "",
			expected: []Route{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseLinuxRoutes(tt.output)

			if len(result) != len(tt.expected) {
				t.Fatalf("Expected %d routes, got %d", len(tt.expected), len(result))
			}

			for i, r := range result {
				if r.Destination != tt.expected[i].Destination {
					t.Errorf("Route %d: Destination: got %q, want %q", i, r.Destination, tt.expected[i].Destination)
				}
				if r.Gateway != tt.expected[i].Gateway {
					t.Errorf("Route %d: Gateway: got %q, want %q", i, r.Gateway, tt.expected[i].Gateway)
				}
				if r.Interface != tt.expected[i].Interface {
					t.Errorf("Route %d: Interface: got %q, want %q", i, r.Interface, tt.expected[i].Interface)
				}
			}
		})
	}
}

func TestParseDarwinRoutes(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		expected []Route
	}{
		{
			name: "typical netstat output",
			output: `Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGScg          en0
10.0.0/24          10.0.0.1           UGSc          utun0
127.0.0.1          127.0.0.1          UH            lo0
192.168.1/24       link#4             UCS           en0`,
			expected: []Route{
				{
					Destination: "default",
					Gateway:     "192.168.1.1",
					Flags:       "UGScg",
					Interface:   "en0",
				},
				{
					Destination: "10.0.0/24",
					Gateway:     "10.0.0.1",
					Flags:       "UGSc",
					Interface:   "utun0",
				},
				{
					Destination: "127.0.0.1",
					Gateway:     "127.0.0.1",
					Flags:       "UH",
					Interface:   "lo0",
				},
				{
					Destination: "192.168.1/24",
					Gateway:     "link#4",
					Flags:       "UCS",
					Interface:   "en0",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDarwinRoutes(tt.output)

			if len(result) != len(tt.expected) {
				t.Fatalf("Expected %d routes, got %d", len(tt.expected), len(result))
			}

			for i, r := range result {
				if r.Destination != tt.expected[i].Destination {
					t.Errorf("Route %d: Destination: got %q, want %q", i, r.Destination, tt.expected[i].Destination)
				}
				if r.Gateway != tt.expected[i].Gateway {
					t.Errorf("Route %d: Gateway: got %q, want %q", i, r.Gateway, tt.expected[i].Gateway)
				}
				if r.Flags != tt.expected[i].Flags {
					t.Errorf("Route %d: Flags: got %q, want %q", i, r.Flags, tt.expected[i].Flags)
				}
				if r.Interface != tt.expected[i].Interface {
					t.Errorf("Route %d: Interface: got %q, want %q", i, r.Interface, tt.expected[i].Interface)
				}
			}
		})
	}
}

func TestParseWindowsRoutes(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		expected []Route
	}{
		{
			name: "typical route print output",
			output: `
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
      192.168.1.0    255.255.255.0         On-link     192.168.1.100    281
===========================================================================
Persistent Routes:
  None
`,
			expected: []Route{
				{
					Destination: "0.0.0.0",
					Netmask:     "0.0.0.0",
					Gateway:     "192.168.1.1",
					Interface:   "192.168.1.100",
					Metric:      25,
				},
				{
					Destination: "127.0.0.0",
					Netmask:     "255.0.0.0",
					Gateway:     "On-link",
					Interface:   "127.0.0.1",
					Metric:      331,
				},
				{
					Destination: "192.168.1.0",
					Netmask:     "255.255.255.0",
					Gateway:     "On-link",
					Interface:   "192.168.1.100",
					Metric:      281,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseWindowsRoutes(tt.output)

			if len(result) != len(tt.expected) {
				t.Fatalf("Expected %d routes, got %d", len(tt.expected), len(result))
			}

			for i, r := range result {
				if r.Destination != tt.expected[i].Destination {
					t.Errorf("Route %d: Destination: got %q, want %q", i, r.Destination, tt.expected[i].Destination)
				}
				if r.Netmask != tt.expected[i].Netmask {
					t.Errorf("Route %d: Netmask: got %q, want %q", i, r.Netmask, tt.expected[i].Netmask)
				}
				if r.Gateway != tt.expected[i].Gateway {
					t.Errorf("Route %d: Gateway: got %q, want %q", i, r.Gateway, tt.expected[i].Gateway)
				}
				if r.Interface != tt.expected[i].Interface {
					t.Errorf("Route %d: Interface: got %q, want %q", i, r.Interface, tt.expected[i].Interface)
				}
				if r.Metric != tt.expected[i].Metric {
					t.Errorf("Route %d: Metric: got %d, want %d", i, r.Metric, tt.expected[i].Metric)
				}
			}
		})
	}
}

func TestDetectVPNInterfaces(t *testing.T) {
	// This test verifies the logic without requiring actual VPN interfaces
	// We can't create fake network interfaces, so we'll just ensure the function runs
	result := detectVPNInterfaces()

	// Result can be empty or contain VPN interfaces
	// Just verify it returns a valid slice
	if result == nil {
		result = []VPNInterface{}
	}

	// Log what we found for debugging
	t.Logf("Found %d VPN interfaces", len(result))
	for _, iface := range result {
		t.Logf("  - %s (type: %s, status: %s)", iface.Name, iface.Type, iface.Status)
	}
}

func TestDiscoverNetwork(t *testing.T) {
	ctx := context.Background()

	// Set up test environment
	os.Setenv("HTTPS_PROXY", "https://proxy.test.com:8443")
	defer os.Unsetenv("HTTPS_PROXY")

	result := DiscoverNetwork(ctx)

	// Verify proxy config was discovered
	if result.ProxyConfig.Environment.HTTPSProxy != "https://proxy.test.com:8443" {
		t.Errorf("Expected HTTPS_PROXY to be discovered, got %q", result.ProxyConfig.Environment.HTTPSProxy)
	}

	// Verify detection time is set
	if result.ProxyConfig.DetectionTime.IsZero() {
		t.Error("Expected detection time to be set")
	}

	// Verify VPN detection time is set
	if result.VPN.DetectionTime.IsZero() {
		t.Error("Expected VPN detection time to be set")
	}

	// Routes should have been attempted
	// (may fail on some platforms, but should have tried)
	t.Logf("Routes available: %v", result.Routes.Available)
	if result.Routes.Error != "" {
		t.Logf("Route detection error (expected on some platforms): %s", result.Routes.Error)
	}
}

func TestDiscoverInterfaces(t *testing.T) {
	result := discoverInterfaces()

	// Should find at least the loopback interface
	if len(result) == 0 {
		t.Error("Expected to find at least one network interface")
	}

	// Verify structure
	for _, iface := range result {
		if iface.Name == "" {
			t.Error("Expected interface to have a name")
		}
		t.Logf("Interface: %s (MTU: %d, Flags: %s)", iface.Name, iface.MTU, iface.Flags)
	}
}

func TestFilterVPNRoutes(t *testing.T) {
	routes := []Route{
		{Destination: "10.0.0.0/8", Gateway: "10.0.0.1", Interface: "tun0"},
		{Destination: "192.168.1.0/24", Gateway: "192.168.1.1", Interface: "eth0"},
		{Destination: "172.16.0.0/16", Gateway: "172.16.0.1", Interface: "utun0"},
		{Destination: "default", Gateway: "192.168.1.1", Interface: "eth0"},
	}

	vpnIfaces := []VPNInterface{
		{Name: "tun0", Type: "tun"},
		{Name: "utun0", Type: "utun"},
	}

	result := filterVPNRoutes(routes, vpnIfaces)

	// Should only return routes for tun0 and utun0
	if len(result) != 2 {
		t.Errorf("Expected 2 VPN routes, got %d", len(result))
	}

	for _, route := range result {
		if route.Interface != "tun0" && route.Interface != "utun0" {
			t.Errorf("Unexpected interface in VPN routes: %s", route.Interface)
		}
	}
}

func TestUniqueStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "with duplicates",
			input:    []string{"a", "b", "a", "c", "b"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "no duplicates",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "empty",
			input:    []string{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := uniqueStrings(tt.input)

			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d unique strings, got %d", len(tt.expected), len(result))
			}

			// Check that all expected strings are present
			resultMap := make(map[string]bool)
			for _, s := range result {
				resultMap[s] = true
			}

			for _, expected := range tt.expected {
				if !resultMap[expected] {
					t.Errorf("Expected string %q not found in result", expected)
				}
			}
		})
	}
}

func TestNetworkJSONStructure(t *testing.T) {
	ctx := context.Background()

	// Set some test environment variables
	os.Setenv("HTTPS_PROXY", "https://proxy.example.com:8443")
	os.Setenv("HTTP_PROXY", "http://proxy.example.com:8080")
	os.Setenv("NO_PROXY", "localhost,127.0.0.1,.internal")
	defer os.Unsetenv("HTTPS_PROXY")
	defer os.Unsetenv("HTTP_PROXY")
	defer os.Unsetenv("NO_PROXY")

	// Discover network information
	networkInfo := DiscoverNetwork(ctx)

	// Verify JSON can be marshaled
	data, err := json.Marshal(networkInfo)
	if err != nil {
		t.Fatalf("Failed to marshal network info to JSON: %v", err)
	}

	// Verify we got some data
	if len(data) < 100 {
		t.Errorf("JSON output seems too small: %d bytes", len(data))
	}

	// Unmarshal to verify structure
	var decoded NetworkInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal network info: %v", err)
	}

	// Verify proxy config
	if decoded.ProxyConfig.Environment.HTTPSProxy != "https://proxy.example.com:8443" {
		t.Errorf("HTTPS_PROXY not captured correctly after JSON round-trip")
	}

	t.Logf("Successfully marshaled and unmarshaled NetworkInfo with %d bytes", len(data))
}
