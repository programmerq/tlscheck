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
// to provide access to collected certificates.
type CertificateCollector interface {
	GetCertificates() map[string]string
}

// ClientCertificateCollector is an optional interface that probe engines may implement
// to provide access to configured client certificates.
type ClientCertificateCollector interface {
	GetClientCertificates() map[string]string
}

// Execution captures the combination of the generated plan and the resulting probe outcomes.
type Execution struct {
	Arguments   *config.Options        `json:"arguments,omitempty"`
	Network     *discovery.NetworkInfo `json:"network,omitempty"`
	Plan        plan.Plan              `json:"plan"`
	Results     []probe.Result         `json:"results"`
	Certs       map[string]string      `json:"certs,omitempty"`
	ClientCerts map[string]string      `json:"client_certs,omitempty"`
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

	// If the engine supports certificate collection, retrieve the certificates
	if collector, ok := engine.(CertificateCollector); ok {
		certs := collector.GetCertificates()
		if len(certs) > 0 {
			exec.Certs = certs
		}
	}

	// If the engine supports client certificate collection, retrieve the client certificates
	if clientCollector, ok := engine.(ClientCertificateCollector); ok {
		clientCerts := clientCollector.GetClientCertificates()
		if len(clientCerts) > 0 {
			exec.ClientCerts = clientCerts
		}
	}

	return exec, nil
}
