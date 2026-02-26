package runner

import (
	"context"
	"fmt"

	"github.com/programmerq/tlscheck/internal/config"
	"github.com/programmerq/tlscheck/internal/discovery"
	"github.com/programmerq/tlscheck/internal/plan"
	"github.com/programmerq/tlscheck/internal/probe"
)

// PlanBuilder wraps plan construction so callers can inject alternatives during tests.
type PlanBuilder interface {
	Build(config.Options) (plan.Plan, error)
}

// PlanBuilderFunc adapts a plain function to the PlanBuilder interface.
type PlanBuilderFunc func(config.Options) (plan.Plan, error)

// Build satisfies the PlanBuilder interface.
func (f PlanBuilderFunc) Build(opts config.Options) (plan.Plan, error) {
	return f(opts)
}

// Engine defines the subset of the probe engine behaviour required for execution.
type Engine interface {
	Run(context.Context, plan.Plan) ([]probe.Result, error)
}

// CertificateCollector is an optional interface that probe engines may implement
// to provide access to collected certificates with expanded metadata.
type CertificateCollector interface {
	GetCertificates() map[string]*probe.CertInfo
}

// ClientCertificateCollector is an optional interface that probe engines may implement
// to provide access to configured client certificates with expanded metadata.
type ClientCertificateCollector interface {
	GetClientCertificates() map[string]*probe.CertInfo
}

// Execution captures the combination of the generated plan and the resulting probe outcomes.
type Execution struct {
	Arguments *config.Options            `json:"arguments,omitempty" jsonschema:"description=Parsed command-line arguments and runtime configuration used for this execution"`
	Network   *discovery.NetworkInfo     `json:"network,omitempty" jsonschema:"description=Network configuration discovery results including proxy settings, routing table, and VPN detection"`
	Plan      plan.Plan                  `json:"plan" jsonschema:"description=Generated probe execution plan with all target combinations to be tested"`
	Results   []probe.Result             `json:"results" jsonschema:"description=Individual probe results for each target, containing connection details, certificates, and any failures"`
	Certs     map[string]*probe.CertInfo `json:"certs,omitempty" jsonschema:"description=Map of all certificates encountered during probing, indexed by SHA-256 fingerprint (uppercase hex)"`
}

// Execute builds a probe plan using the supplied builder and executes it with the engine.
func Execute(ctx context.Context, opts config.Options, builder PlanBuilder, engine Engine) (Execution, error) {
	if builder == nil {
		return Execution{}, fmt.Errorf("plan builder is required")
	}
	if engine == nil {
		return Execution{}, fmt.Errorf("probe engine is required")
	}

	// Discover network configuration including proxy, routes, and VPN
	networkInfo := discovery.DiscoverNetwork(ctx)

	probePlan, err := builder.Build(opts)
	if err != nil {
		return Execution{}, err
	}

	results, err := engine.Run(ctx, probePlan)
	if err != nil {
		return Execution{}, err
	}

	exec := Execution{
		Arguments: &opts,
		Network:   &networkInfo,
		Plan:      probePlan,
		Results:   results,
	}

	// Combine all certificates (server and client) into a single map
	allCerts := make(map[string]*probe.CertInfo)

	// If the engine supports certificate collection, retrieve the certificates
	if collector, ok := engine.(CertificateCollector); ok {
		certs := collector.GetCertificates()
		for fp, info := range certs {
			allCerts[fp] = info
		}
	}

	// If the engine supports client certificate collection, retrieve the client certificates
	if clientCollector, ok := engine.(ClientCertificateCollector); ok {
		clientCerts := clientCollector.GetClientCertificates()
		for fp, info := range clientCerts {
			allCerts[fp] = info
		}
	}

	// Parse the HostCA PEM bundle and add any discovered CA certificates
	if len(opts.HostCAPEM) > 0 {
		hostCACerts := probe.ParseCertBundleFromPEM(opts.HostCAPEM, probe.CertSourceHostCA)
		for fp, info := range hostCACerts {
			if _, exists := allCerts[fp]; !exists {
				allCerts[fp] = info
			}
		}
	}

	if len(allCerts) > 0 {
		exec.Certs = allCerts
	}

	return exec, nil
}
