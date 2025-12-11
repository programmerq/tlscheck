package discovery

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// NetworkInfo captures network configuration including proxy, routing, and VPN details.
type NetworkInfo struct {
	System      SystemInfo  `json:"system" jsonschema:"description=System information including hostname, OS, and architecture"`
	ProxyConfig ProxyConfig `json:"proxy_config" jsonschema:"description=Detected proxy configuration from environment variables, system settings, and PAC files"`
	Routes      RouteInfo   `json:"routes" jsonschema:"description=System routing table and network interface information"`
	VPN         VPNInfo     `json:"vpn" jsonschema:"description=VPN detection results including interfaces, applications, and routes"`
}

// SystemInfo captures basic system information.
type SystemInfo struct {
	Hostname     string    `json:"hostname" jsonschema:"description=System hostname"`
	OS           string    `json:"os" jsonschema:"description=Operating system (e.g. linux, darwin, windows)"`
	Architecture string    `json:"architecture" jsonschema:"description=CPU architecture (e.g. amd64, arm64)"`
	CapturedAt   time.Time `json:"captured_at" jsonschema:"description=Timestamp when system information was captured (UTC)"`
}

// ProxyConfig captures all proxy-related configuration.
type ProxyConfig struct {
	Environment   EnvironmentProxies `json:"environment" jsonschema:"description=Proxy settings from environment variables (HTTP_PROXY, HTTPS_PROXY, etc.)"`
	SystemProxy   *SystemProxy       `json:"system_proxy,omitempty" jsonschema:"description=OS-level proxy settings from macOS Network Settings or Windows Registry"`
	PACFile       *PACFileInfo       `json:"pac_file,omitempty" jsonschema:"description=Proxy Auto-Configuration (PAC) file URL and content"`
	SOCKSProxy    *SOCKSProxyInfo    `json:"socks_proxy,omitempty" jsonschema:"description=SOCKS proxy configuration detected from environment"`
	DetectionTime time.Time          `json:"detection_time" jsonschema:"description=Timestamp when proxy detection was performed (UTC)"`
}

// EnvironmentProxies captures proxy settings from environment variables.
type EnvironmentProxies struct {
	HTTPSProxy string   `json:"https_proxy,omitempty" jsonschema:"description=HTTPS proxy URL from HTTPS_PROXY or https_proxy environment variable"`
	HTTPProxy  string   `json:"http_proxy,omitempty" jsonschema:"description=HTTP proxy URL from HTTP_PROXY or http_proxy environment variable"`
	NoProxy    string   `json:"no_proxy,omitempty" jsonschema:"description=Comma-separated list of hosts to bypass proxy from NO_PROXY or no_proxy"`
	AllProxy   string   `json:"all_proxy,omitempty" jsonschema:"description=Fallback proxy URL from ALL_PROXY or all_proxy (often used for SOCKS)"`
	FTPProxy   string   `json:"ftp_proxy,omitempty" jsonschema:"description=FTP proxy URL from FTP_PROXY or ftp_proxy environment variable"`
	Parsed     []string `json:"parsed_hosts,omitempty" jsonschema:"description=Parsed proxy host addresses extracted from proxy URLs"`
}

// SystemProxy captures OS-level proxy settings (primarily macOS/Windows).
type SystemProxy struct {
	Enabled     bool     `json:"enabled" jsonschema:"description=Whether system-level proxy is enabled"`
	HTTPProxy   string   `json:"http_proxy,omitempty" jsonschema:"description=HTTP proxy address from system settings"`
	HTTPSProxy  string   `json:"https_proxy,omitempty" jsonschema:"description=HTTPS proxy address from system settings"`
	SOCKSProxy  string   `json:"socks_proxy,omitempty" jsonschema:"description=SOCKS proxy address from system settings"`
	FTPProxy    string   `json:"ftp_proxy,omitempty" jsonschema:"description=FTP proxy address from system settings"`
	ExcludeList []string `json:"exclude_list,omitempty" jsonschema:"description=List of domains or addresses to bypass proxy"`
	PACEnabled  bool     `json:"pac_enabled" jsonschema:"description=Whether Proxy Auto-Configuration is enabled"`
	PACURL      string   `json:"pac_url,omitempty" jsonschema:"description=URL of the PAC file if PAC is enabled"`
	Source      string   `json:"source" jsonschema:"description=Source of the system proxy settings (e.g. macOS Network Settings, Windows Registry)"` // "macOS Network Settings", "Windows Registry", etc.
}

// PACFileInfo captures Proxy Auto-Configuration file details.
type PACFileInfo struct {
	URL       string `json:"url,omitempty" jsonschema:"description=URL where the PAC file was retrieved from"`
	Content   string `json:"content,omitempty" jsonschema:"description=Full content of the PAC file (JavaScript)"`
	Error     string `json:"error,omitempty" jsonschema:"description=Error message if PAC file could not be retrieved"`
	Retrieved bool   `json:"retrieved" jsonschema:"description=Whether the PAC file was successfully retrieved"`
}

// SOCKSProxyInfo captures SOCKS proxy configuration.
type SOCKSProxyInfo struct {
	Version string `json:"version" jsonschema:"description=SOCKS protocol version (SOCKS4 or SOCKS5)"` // "SOCKS4", "SOCKS5"
	Address string `json:"address" jsonschema:"description=SOCKS proxy server address (hostname or IP)"`
	Port    int    `json:"port" jsonschema:"description=SOCKS proxy server port number"`
	Source  string `json:"source" jsonschema:"description=Where this SOCKS proxy configuration was found (e.g. ALL_PROXY environment variable)"`
}

// RouteInfo captures routing table information.
type RouteInfo struct {
	Available  bool           `json:"available" jsonschema:"description=Whether routing table information was successfully captured"`
	Error      string         `json:"error,omitempty" jsonschema:"description=Error message if route capture failed"`
	DefaultGW  string         `json:"default_gateway,omitempty" jsonschema:"description=Default gateway IP address from the routing table"`
	Routes     []Route        `json:"routes,omitempty" jsonschema:"description=List of routing table entries"`
	Interfaces []NetInterface `json:"interfaces,omitempty" jsonschema:"description=List of network interfaces with their addresses"`
	CapturedAt time.Time      `json:"captured_at,omitempty" jsonschema:"description=Timestamp when routing information was captured (UTC)"`
}

// Route represents a single routing table entry.
type Route struct {
	Destination string `json:"destination" jsonschema:"description=Destination network in CIDR notation or 'default' for default route"`
	Gateway     string `json:"gateway,omitempty" jsonschema:"description=Gateway IP address for this route"`
	Netmask     string `json:"netmask,omitempty" jsonschema:"description=Network mask for the destination (on platforms that use netmask instead of CIDR)"`
	Interface   string `json:"interface" jsonschema:"description=Network interface name for this route (e.g. eth0, en0)"`
	Metric      int    `json:"metric,omitempty" jsonschema:"description=Route metric (lower is preferred)"`
	Flags       string `json:"flags,omitempty" jsonschema:"description=Route flags indicating properties like Up, Gateway, Host"`
}

// NetInterface represents a network interface.
type NetInterface struct {
	Name         string   `json:"name" jsonschema:"description=Network interface name (e.g. eth0, en0, wlan0)"`
	HardwareAddr string   `json:"hardware_addr,omitempty" jsonschema:"description=MAC address of the interface"`
	Addresses    []string `json:"addresses,omitempty" jsonschema:"description=IP addresses assigned to this interface in CIDR notation"`
	Flags        string   `json:"flags,omitempty" jsonschema:"description=Interface flags (e.g. up, broadcast, multicast)"`
	MTU          int      `json:"mtu,omitempty" jsonschema:"description=Maximum Transmission Unit size in bytes"`
}

// VPNInfo captures VPN-related configuration and state.
type VPNInfo struct {
	Detected      bool           `json:"detected" jsonschema:"description=Whether any VPN connections were detected"`
	Interfaces    []VPNInterface `json:"interfaces,omitempty" jsonschema:"description=VPN network interfaces found on the system"`
	Applications  []VPNApp       `json:"applications,omitempty" jsonschema:"description=VPN applications and services detected as running"`
	Routes        []Route        `json:"routes,omitempty" jsonschema:"description=Routing table entries associated with VPN interfaces"`
	DetectionTime time.Time      `json:"detection_time" jsonschema:"description=Timestamp when VPN detection was performed (UTC)"`
}

// VPNInterface represents a detected VPN network interface.
type VPNInterface struct {
	Name      string   `json:"name" jsonschema:"description=Interface name (e.g. tun0, utun1, ppp0)"`
	Type      string   `json:"type" jsonschema:"description=VPN interface type (e.g. tun, tap, ppp, utun, wireguard)"` // "tun", "tap", "ppp", "utun", etc.
	Addresses []string `json:"addresses,omitempty" jsonschema:"description=IP addresses assigned to this VPN interface"`
	Status    string   `json:"status" jsonschema:"description=Interface status (e.g. up, down)"`
}

// VPNApp represents a detected VPN application or service.
type VPNApp struct {
	Name    string `json:"name" jsonschema:"description=Name of the VPN application or service"`
	Type    string `json:"type" jsonschema:"description=Type of VPN (e.g. OpenVPN, WireGuard, Cisco AnyConnect, GlobalProtect)"` // "OpenVPN", "WireGuard", "Cisco AnyConnect", etc.
	Status  string `json:"status" jsonschema:"description=Application status (e.g. running, configured)"`
	Details string `json:"details,omitempty" jsonschema:"description=Additional details about the VPN connection"`
}

// DiscoverNetwork gathers comprehensive network configuration information.
func DiscoverNetwork(ctx context.Context) NetworkInfo {
	info := NetworkInfo{
		System:      discoverSystemInfo(),
		ProxyConfig: discoverProxyConfig(ctx),
		Routes:      discoverRoutes(ctx),
		VPN:         discoverVPN(ctx),
	}
	return info
}

// discoverSystemInfo collects basic system information.
func discoverSystemInfo() SystemInfo {
	hostname, _ := os.Hostname()
	// If hostname cannot be determined, use "unknown"
	if hostname == "" {
		hostname = "unknown"
	}

	return SystemInfo{
		Hostname:     hostname,
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		CapturedAt:   time.Now().UTC(),
	}
}

// discoverProxyConfig detects all proxy configuration sources.
func discoverProxyConfig(ctx context.Context) ProxyConfig {
	config := ProxyConfig{
		Environment:   detectEnvironmentProxies(),
		DetectionTime: time.Now().UTC(),
	}

	// Detect system-level proxy settings
	if sysProxy := detectSystemProxy(ctx); sysProxy != nil {
		config.SystemProxy = sysProxy

		// If PAC is enabled, try to fetch the PAC file
		if sysProxy.PACEnabled && sysProxy.PACURL != "" {
			config.PACFile = fetchPACFile(ctx, sysProxy.PACURL)
		}
	}

	// Detect SOCKS proxy
	if socksProxy := detectSOCKSProxy(); socksProxy != nil {
		config.SOCKSProxy = socksProxy
	}

	return config
}

// detectEnvironmentProxies reads proxy settings from environment variables.
func detectEnvironmentProxies() EnvironmentProxies {
	proxies := EnvironmentProxies{
		HTTPSProxy: firstNonEmpty(os.Getenv("HTTPS_PROXY"), os.Getenv("https_proxy")),
		HTTPProxy:  firstNonEmpty(os.Getenv("HTTP_PROXY"), os.Getenv("http_proxy")),
		NoProxy:    firstNonEmpty(os.Getenv("NO_PROXY"), os.Getenv("no_proxy")),
		AllProxy:   firstNonEmpty(os.Getenv("ALL_PROXY"), os.Getenv("all_proxy")),
		FTPProxy:   firstNonEmpty(os.Getenv("FTP_PROXY"), os.Getenv("ftp_proxy")),
	}

	// Parse proxy hosts for easier inspection
	var hosts []string
	for _, proxy := range []string{proxies.HTTPSProxy, proxies.HTTPProxy, proxies.AllProxy} {
		if proxy != "" {
			if parsed, err := url.Parse(proxy); err == nil && parsed.Host != "" {
				hosts = append(hosts, parsed.Host)
			}
		}
	}
	if len(hosts) > 0 {
		proxies.Parsed = uniqueStrings(hosts)
	}

	return proxies
}

// detectSystemProxy attempts to discover OS-level proxy configuration.
func detectSystemProxy(ctx context.Context) *SystemProxy {
	switch runtime.GOOS {
	case "darwin":
		return detectMacOSProxy(ctx)
	case "windows":
		return detectWindowsProxy(ctx)
	default:
		// Linux and other Unix systems typically use environment variables
		return nil
	}
}

// detectMacOSProxy reads proxy settings from macOS Network Settings.
func detectMacOSProxy(ctx context.Context) *SystemProxy {
	// Use networksetup command to read proxy settings
	cmd := exec.CommandContext(ctx, "networksetup", "-getwebproxy", "Wi-Fi")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try Ethernet if Wi-Fi fails
		cmd = exec.CommandContext(ctx, "networksetup", "-getwebproxy", "Ethernet")
		output, err = cmd.CombinedOutput()
		if err != nil {
			return nil
		}
	}

	proxy := &SystemProxy{
		Source: "macOS Network Settings",
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Enabled:") {
			proxy.Enabled = strings.Contains(line, "Yes")
		} else if strings.HasPrefix(line, "Server:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				proxy.HTTPProxy = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "Port:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 && proxy.HTTPProxy != "" {
				port := strings.TrimSpace(parts[1])
				if port != "" && port != "0" {
					proxy.HTTPProxy = proxy.HTTPProxy + ":" + port
				}
			}
		}
	}

	// Check HTTPS proxy
	cmd = exec.CommandContext(ctx, "networksetup", "-getsecurewebproxy", "Wi-Fi")
	output, err = cmd.CombinedOutput()
	if err == nil {
		lines = strings.Split(string(output), "\n")
		var httpsHost, httpsPort string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Server:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					httpsHost = strings.TrimSpace(parts[1])
				}
			} else if strings.HasPrefix(line, "Port:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					httpsPort = strings.TrimSpace(parts[1])
				}
			}
		}
		if httpsHost != "" {
			if httpsPort != "" && httpsPort != "0" {
				proxy.HTTPSProxy = httpsHost + ":" + httpsPort
			} else {
				proxy.HTTPSProxy = httpsHost
			}
		}
	}

	// Check SOCKS proxy
	cmd = exec.CommandContext(ctx, "networksetup", "-getsocksfirewallproxy", "Wi-Fi")
	output, err = cmd.CombinedOutput()
	if err == nil {
		lines = strings.Split(string(output), "\n")
		var socksHost, socksPort string
		var socksEnabled bool
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Enabled:") {
				socksEnabled = strings.Contains(line, "Yes")
			} else if strings.HasPrefix(line, "Server:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					socksHost = strings.TrimSpace(parts[1])
				}
			} else if strings.HasPrefix(line, "Port:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					socksPort = strings.TrimSpace(parts[1])
				}
			}
		}
		if socksEnabled && socksHost != "" {
			if socksPort != "" && socksPort != "0" {
				proxy.SOCKSProxy = socksHost + ":" + socksPort
			} else {
				proxy.SOCKSProxy = socksHost
			}
		}
	}

	// Check PAC settings
	cmd = exec.CommandContext(ctx, "networksetup", "-getautoproxyurl", "Wi-Fi")
	output, err = cmd.CombinedOutput()
	if err == nil {
		lines = strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Enabled:") {
				proxy.PACEnabled = strings.Contains(line, "Yes")
			} else if strings.HasPrefix(line, "URL:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					proxy.PACURL = strings.TrimSpace(parts[1])
					// URL might be like "http://..." so rejoin
					if strings.HasPrefix(strings.TrimSpace(parts[1]), "//") {
						proxy.PACURL = "http:" + strings.TrimSpace(parts[1])
					} else {
						remaining := strings.SplitN(line, "URL:", 2)
						if len(remaining) == 2 {
							proxy.PACURL = strings.TrimSpace(remaining[1])
						}
					}
				}
			}
		}
	}

	// Check bypass domains
	cmd = exec.CommandContext(ctx, "networksetup", "-getproxybypassdomains", "Wi-Fi")
	output, err = cmd.CombinedOutput()
	if err == nil {
		lines = strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "There") {
				proxy.ExcludeList = append(proxy.ExcludeList, line)
			}
		}
	}

	return proxy
}

// detectWindowsProxy reads proxy settings from Windows Registry.
func detectWindowsProxy(ctx context.Context) *SystemProxy {
	// Query Windows registry for proxy settings
	cmd := exec.CommandContext(ctx, "reg", "query",
		`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyEnable")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}

	proxy := &SystemProxy{
		Source: "Windows Registry",
	}

	// Parse ProxyEnable
	if strings.Contains(string(output), "0x1") {
		proxy.Enabled = true
	}

	// Query ProxyServer
	cmd = exec.CommandContext(ctx, "reg", "query",
		`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyServer")
	output, err = cmd.CombinedOutput()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "ProxyServer") && strings.Contains(line, "REG_SZ") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					proxyStr := parts[len(parts)-1]
					// Parse proxy string which can be "http=proxy:port;https=proxy:port"
					if strings.Contains(proxyStr, "=") {
						proxies := strings.Split(proxyStr, ";")
						for _, p := range proxies {
							kv := strings.SplitN(p, "=", 2)
							if len(kv) == 2 {
								switch strings.ToLower(kv[0]) {
								case "http":
									proxy.HTTPProxy = kv[1]
								case "https":
									proxy.HTTPSProxy = kv[1]
								case "ftp":
									proxy.FTPProxy = kv[1]
								case "socks":
									proxy.SOCKSProxy = kv[1]
								}
							}
						}
					} else {
						// Single proxy for all protocols
						proxy.HTTPProxy = proxyStr
						proxy.HTTPSProxy = proxyStr
					}
				}
			}
		}
	}

	// Query ProxyOverride (bypass list)
	cmd = exec.CommandContext(ctx, "reg", "query",
		`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyOverride")
	output, err = cmd.CombinedOutput()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "ProxyOverride") && strings.Contains(line, "REG_SZ") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					bypassStr := parts[len(parts)-1]
					proxy.ExcludeList = strings.Split(bypassStr, ";")
				}
			}
		}
	}

	// Query AutoConfigURL (PAC)
	cmd = exec.CommandContext(ctx, "reg", "query",
		`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "AutoConfigURL")
	output, err = cmd.CombinedOutput()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "AutoConfigURL") && strings.Contains(line, "REG_SZ") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					proxy.PACEnabled = true
					proxy.PACURL = parts[len(parts)-1]
				}
			}
		}
	}

	return proxy
}

// detectSOCKSProxy detects SOCKS proxy from environment variables.
func detectSOCKSProxy() *SOCKSProxyInfo {
	allProxy := firstNonEmpty(os.Getenv("ALL_PROXY"), os.Getenv("all_proxy"))
	if allProxy == "" {
		return nil
	}

	parsed, err := url.Parse(allProxy)
	if err != nil || parsed.Host == "" {
		return nil
	}

	// Check if it's a SOCKS proxy
	scheme := strings.ToLower(parsed.Scheme)
	if !strings.HasPrefix(scheme, "socks") {
		return nil
	}

	info := &SOCKSProxyInfo{
		Address: parsed.Hostname(),
		Source:  "ALL_PROXY environment variable",
	}

	if parsed.Port() != "" {
		fmt.Sscanf(parsed.Port(), "%d", &info.Port)
	}

	switch scheme {
	case "socks4":
		info.Version = "SOCKS4"
	case "socks5", "socks5h", "socks":
		info.Version = "SOCKS5"
	default:
		info.Version = scheme
	}

	return info
}

// fetchPACFile attempts to download and read a PAC file.
func fetchPACFile(ctx context.Context, pacURL string) *PACFileInfo {
	info := &PACFileInfo{
		URL: pacURL,
	}

	if pacURL == "" {
		info.Error = "PAC URL is empty"
		return info
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pacURL, nil)
	if err != nil {
		info.Error = fmt.Sprintf("failed to create request: %v", err)
		return info
	}

	resp, err := client.Do(req)
	if err != nil {
		info.Error = fmt.Sprintf("failed to fetch: %v", err)
		return info
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		info.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return info
	}

	// Read up to 64KB of PAC file content
	buf := make([]byte, 64*1024)
	n, _ := resp.Body.Read(buf)
	info.Content = string(buf[:n])
	info.Retrieved = true

	return info
}

// discoverRoutes captures the routing table and network interfaces.
func discoverRoutes(ctx context.Context) RouteInfo {
	info := RouteInfo{
		CapturedAt: time.Now().UTC(),
	}

	// Discover network interfaces first
	info.Interfaces = discoverInterfaces()

	// Capture routing table
	switch runtime.GOOS {
	case "linux":
		info = discoverLinuxRoutes(ctx, info)
	case "darwin":
		info = discoverDarwinRoutes(ctx, info)
	case "windows":
		info = discoverWindowsRoutes(ctx, info)
	default:
		info.Available = false
		info.Error = fmt.Sprintf("routing table capture not implemented for %s", runtime.GOOS)
	}

	return info
}

// discoverInterfaces discovers network interfaces using the net package.
func discoverInterfaces() []NetInterface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var result []NetInterface
	for _, iface := range ifaces {
		ni := NetInterface{
			Name:         iface.Name,
			HardwareAddr: iface.HardwareAddr.String(),
			Flags:        iface.Flags.String(),
			MTU:          iface.MTU,
		}

		// Get addresses
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				ni.Addresses = append(ni.Addresses, addr.String())
			}
		}

		result = append(result, ni)
	}

	return result
}

// discoverLinuxRoutes reads the Linux routing table.
func discoverLinuxRoutes(ctx context.Context, info RouteInfo) RouteInfo {
	cmd := exec.CommandContext(ctx, "ip", "route", "show")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Fallback to route command
		cmd = exec.CommandContext(ctx, "route", "-n")
		output, err = cmd.CombinedOutput()
		if err != nil {
			info.Available = false
			info.Error = fmt.Sprintf("failed to capture routes: %v", err)
			return info
		}
	}

	info.Available = true
	info.Routes = parseLinuxRoutes(string(output))

	// Extract default gateway
	for _, route := range info.Routes {
		if route.Destination == "default" || route.Destination == "0.0.0.0" {
			info.DefaultGW = route.Gateway
			break
		}
	}

	return info
}

// parseLinuxRoutes parses output from ip route show command.
func parseLinuxRoutes(output string) []Route {
	var routes []Route
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse "ip route show" format
		// Examples:
		// default via 192.168.1.1 dev eth0
		// 192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		route := Route{}

		if fields[0] == "default" {
			route.Destination = "default"
		} else {
			route.Destination = fields[0]
		}

		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "via":
				if i+1 < len(fields) {
					route.Gateway = fields[i+1]
					i++
				}
			case "dev":
				if i+1 < len(fields) {
					route.Interface = fields[i+1]
					i++
				}
			case "metric":
				if i+1 < len(fields) {
					fmt.Sscanf(fields[i+1], "%d", &route.Metric)
					i++
				}
			}
		}

		routes = append(routes, route)
	}

	return routes
}

// discoverDarwinRoutes reads the macOS routing table.
func discoverDarwinRoutes(ctx context.Context, info RouteInfo) RouteInfo {
	cmd := exec.CommandContext(ctx, "netstat", "-rn")
	output, err := cmd.CombinedOutput()
	if err != nil {
		info.Available = false
		info.Error = fmt.Sprintf("failed to capture routes: %v", err)
		return info
	}

	info.Available = true
	info.Routes = parseDarwinRoutes(string(output))

	// Extract default gateway
	for _, route := range info.Routes {
		if route.Destination == "default" {
			info.DefaultGW = route.Gateway
			break
		}
	}

	return info
}

// parseDarwinRoutes parses output from netstat -rn on macOS.
func parseDarwinRoutes(output string) []Route {
	var routes []Route
	lines := strings.Split(output, "\n")
	inIPv4Section := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Look for IPv4 routing table section
		if strings.Contains(line, "Internet:") {
			inIPv4Section = true
			continue
		}

		if strings.Contains(line, "Internet6:") {
			inIPv4Section = false
			continue
		}

		// Skip header lines
		if strings.HasPrefix(line, "Destination") {
			continue
		}

		if !inIPv4Section {
			continue
		}

		// Parse route line
		// Format: Destination Gateway Flags Netif Expire
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		route := Route{
			Destination: fields[0],
			Gateway:     fields[1],
			Flags:       fields[2],
		}

		if len(fields) >= 4 {
			route.Interface = fields[3]
		}

		routes = append(routes, route)
	}

	return routes
}

// discoverWindowsRoutes reads the Windows routing table.
func discoverWindowsRoutes(ctx context.Context, info RouteInfo) RouteInfo {
	cmd := exec.CommandContext(ctx, "route", "print", "-4")
	output, err := cmd.CombinedOutput()
	if err != nil {
		info.Available = false
		info.Error = fmt.Sprintf("failed to capture routes: %v", err)
		return info
	}

	info.Available = true
	info.Routes = parseWindowsRoutes(string(output))

	// Extract default gateway
	for _, route := range info.Routes {
		if route.Destination == "0.0.0.0" {
			info.DefaultGW = route.Gateway
			break
		}
	}

	return info
}

// parseWindowsRoutes parses output from route print command on Windows.
func parseWindowsRoutes(output string) []Route {
	var routes []Route
	lines := strings.Split(output, "\n")
	inRouteTable := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Look for active routes section
		if strings.Contains(line, "Active Routes:") {
			inRouteTable = true
			continue
		}

		// Skip until we're in the route table
		if !inRouteTable {
			continue
		}

		// Skip header and separator lines
		if strings.Contains(line, "Network Destination") ||
			strings.Contains(line, "=====") {
			continue
		}

		// Parse route line
		// Format: Network Destination  Netmask  Gateway  Interface  Metric
		fields := strings.Fields(line)
		if len(fields) < 4 {
			// End of route table
			if strings.Contains(line, "Persistent Routes:") {
				break
			}
			continue
		}

		route := Route{
			Destination: fields[0],
			Netmask:     fields[1],
			Gateway:     fields[2],
			Interface:   fields[3],
		}

		if len(fields) >= 5 {
			fmt.Sscanf(fields[4], "%d", &route.Metric)
		}

		routes = append(routes, route)
	}

	return routes
}

// discoverVPN detects VPN connections and related information.
func discoverVPN(ctx context.Context) VPNInfo {
	info := VPNInfo{
		DetectionTime: time.Now().UTC(),
	}

	// Detect VPN interfaces
	info.Interfaces = detectVPNInterfaces()
	if len(info.Interfaces) > 0 {
		info.Detected = true
	}

	// Detect VPN applications
	info.Applications = detectVPNApplications(ctx)
	if len(info.Applications) > 0 {
		info.Detected = true
	}

	// Extract VPN-related routes
	routeInfo := discoverRoutes(ctx)
	if routeInfo.Available {
		info.Routes = filterVPNRoutes(routeInfo.Routes, info.Interfaces)
	}

	return info
}

// detectVPNInterfaces identifies network interfaces that are likely VPN connections.
func detectVPNInterfaces() []VPNInterface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var vpnIfaces []VPNInterface

	// Common VPN interface name patterns
	vpnPatterns := []string{
		"tun", "tap", "ppp", "utun", "ipsec", "wg", "vpn",
		"wireguard", "openvpn", "tailscale", "zerotier",
	}

	for _, iface := range ifaces {
		nameLower := strings.ToLower(iface.Name)
		isVPN := false
		vpnType := "unknown"

		for _, pattern := range vpnPatterns {
			if strings.Contains(nameLower, pattern) {
				isVPN = true
				vpnType = pattern
				break
			}
		}

		if !isVPN {
			continue
		}

		vpnIface := VPNInterface{
			Name:   iface.Name,
			Type:   vpnType,
			Status: "unknown",
		}

		// Check if interface is up
		if iface.Flags&net.FlagUp != 0 {
			vpnIface.Status = "up"
		} else {
			vpnIface.Status = "down"
		}

		// Get addresses
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				vpnIface.Addresses = append(vpnIface.Addresses, addr.String())
			}
		}

		vpnIfaces = append(vpnIfaces, vpnIface)
	}

	return vpnIfaces
}

// detectVPNApplications attempts to detect running VPN applications.
func detectVPNApplications(ctx context.Context) []VPNApp {
	switch runtime.GOOS {
	case "darwin":
		return detectMacOSVPNApps(ctx)
	case "linux":
		return detectLinuxVPNApps(ctx)
	case "windows":
		return detectWindowsVPNApps(ctx)
	default:
		return nil
	}
}

// detectMacOSVPNApps detects VPN applications on macOS.
func detectMacOSVPNApps(ctx context.Context) []VPNApp {
	var apps []VPNApp

	// Check for common VPN applications via process list
	vpnProcesses := map[string]string{
		"openvpn":          "OpenVPN",
		"wireguard":        "WireGuard",
		"Cisco AnyConnect": "Cisco AnyConnect",
		"GlobalProtect":    "Palo Alto GlobalProtect",
		"Tunnelblick":      "Tunnelblick",
		"Viscosity":        "Viscosity",
		"tailscaled":       "Tailscale",
		"zerotier-one":     "ZeroTier",
	}

	cmd := exec.CommandContext(ctx, "ps", "aux")
	output, err := cmd.CombinedOutput()
	if err == nil {
		outputStr := strings.ToLower(string(output))
		for process, appName := range vpnProcesses {
			if strings.Contains(outputStr, strings.ToLower(process)) {
				apps = append(apps, VPNApp{
					Name:   appName,
					Type:   appName,
					Status: "running",
				})
			}
		}
	}

	// Check scutil for VPN services
	cmd = exec.CommandContext(ctx, "scutil", "--nc", "list")
	output, err = cmd.CombinedOutput()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "IPSec") || strings.Contains(line, "IKEv2") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					name := strings.Trim(fields[2], `"`)
					apps = append(apps, VPNApp{
						Name:    name,
						Type:    "IPSec/IKEv2",
						Status:  "configured",
						Details: line,
					})
				}
			}
		}
	}

	return apps
}

// detectLinuxVPNApps detects VPN applications on Linux.
func detectLinuxVPNApps(ctx context.Context) []VPNApp {
	var apps []VPNApp

	vpnProcesses := map[string]string{
		"openvpn":      "OpenVPN",
		"wireguard":    "WireGuard",
		"wg-quick":     "WireGuard",
		"strongswan":   "strongSwan",
		"tailscaled":   "Tailscale",
		"zerotier-one": "ZeroTier",
	}

	cmd := exec.CommandContext(ctx, "ps", "aux")
	output, err := cmd.CombinedOutput()
	if err == nil {
		outputStr := strings.ToLower(string(output))
		for process, appName := range vpnProcesses {
			if strings.Contains(outputStr, process) {
				apps = append(apps, VPNApp{
					Name:   appName,
					Type:   appName,
					Status: "running",
				})
			}
		}
	}

	// Check for NetworkManager VPN connections
	cmd = exec.CommandContext(ctx, "nmcli", "-t", "-f", "TYPE,NAME,STATE", "connection", "show")
	output, err = cmd.CombinedOutput()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "vpn") {
				fields := strings.Split(line, ":")
				if len(fields) >= 3 {
					apps = append(apps, VPNApp{
						Name:    fields[1],
						Type:    "NetworkManager VPN",
						Status:  fields[2],
						Details: line,
					})
				}
			}
		}
	}

	return apps
}

// detectWindowsVPNApps detects VPN applications on Windows.
func detectWindowsVPNApps(ctx context.Context) []VPNApp {
	var apps []VPNApp

	// Check for VPN adapters
	cmd := exec.CommandContext(ctx, "netsh", "interface", "show", "interface")
	output, err := cmd.CombinedOutput()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			lineLower := strings.ToLower(line)
			if strings.Contains(lineLower, "vpn") ||
				strings.Contains(lineLower, "wan miniport") ||
				strings.Contains(lineLower, "pptp") ||
				strings.Contains(lineLower, "l2tp") {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					apps = append(apps, VPNApp{
						Name:    strings.Join(fields[3:], " "),
						Type:    "Windows VPN Adapter",
						Status:  fields[1],
						Details: line,
					})
				}
			}
		}
	}

	return apps
}

// filterVPNRoutes extracts routes that are associated with VPN interfaces.
func filterVPNRoutes(routes []Route, vpnIfaces []VPNInterface) []Route {
	if len(vpnIfaces) == 0 {
		return nil
	}

	// Build a map of VPN interface names
	vpnIfaceMap := make(map[string]bool)
	for _, iface := range vpnIfaces {
		vpnIfaceMap[iface.Name] = true
	}

	var vpnRoutes []Route
	for _, route := range routes {
		if vpnIfaceMap[route.Interface] {
			vpnRoutes = append(vpnRoutes, route)
		}
	}

	return vpnRoutes
}

// uniqueStrings returns a deduplicated slice of strings.
func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
