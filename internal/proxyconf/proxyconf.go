package proxyconf

// Settings captures HTTP/HTTPS proxy configuration.
type Settings struct {
	HTTPSProxy string `json:"https_proxy,omitempty" jsonschema:"description=HTTPS proxy URL from HTTPS_PROXY environment variable"`
	HTTPProxy  string `json:"http_proxy,omitempty" jsonschema:"description=HTTP proxy URL from HTTP_PROXY environment variable"`
	NoProxy    string `json:"no_proxy,omitempty" jsonschema:"description=Comma-separated list of hosts to bypass proxy from NO_PROXY environment variable"`
}
