package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/programmerq/tlscheck/internal/config"
	"github.com/programmerq/tlscheck/internal/plan"
	"github.com/programmerq/tlscheck/internal/probe"
	"github.com/programmerq/tlscheck/internal/runner"
	"github.com/programmerq/tlscheck/internal/version"
)

func main() {
	ctx := context.Background()
	exitCode := run(ctx, os.Args[1:], os.Stdout, os.Stderr, defaultDeps())
	os.Exit(exitCode)
}

type dependencies struct {
	parseArgs      func([]string, []string) (config.Options, bool, error)
	resolveRuntime func(context.Context, config.Options) (config.Options, error)
	planBuilder    runner.PlanBuilder
	newEngine      func() runner.Engine
	systemCertPool func() (*x509.CertPool, error)
}

func defaultDeps() dependencies {
	return dependencies{
		parseArgs:      config.ParseArgs,
		resolveRuntime: config.ResolveRuntime,
		planBuilder:    runner.PlanBuilderFunc(plan.Build),
		newEngine: func() runner.Engine {
			return probe.NewEngine()
		},
		systemCertPool: x509.SystemCertPool,
	}
}

type rootCAAccessor interface {
	GetRootCAs() *x509.CertPool
	SetRootCAs(*x509.CertPool)
}

type clientCertAccessor interface {
	SetClientCert(certPEM, keyPEM []byte)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, deps dependencies) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}

	opts, showVersion, err := deps.parseArgs(args, plan.ServiceKeys())
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "failed to parse arguments: %v\n", err)
		return 2
	}

	if showVersion {
		fmt.Fprintln(stdout, version.Version)
		return 0
	}

	resolved, err := deps.resolveRuntime(ctx, opts)
	if err != nil {
		if errors.Is(err, config.ErrProxyServerRequired) {
			teleportHome := os.Getenv("TELEPORT_HOME")
			if teleportHome != "" {
				fmt.Fprintf(stderr, "no active tsh profile found in TELEPORT_HOME=%s. specify a proxy via --proxy-server\n", teleportHome)
			} else {
				fmt.Fprintln(stderr, "no active tsh profile. specify a proxy via --proxy-server")
			}
			config.Usage()
			return 2
		}
		fmt.Fprintf(stderr, "failed to resolve runtime defaults: %v\n", err)
		return 1
	}

	builder := deps.planBuilder
	engine := deps.newEngine()

	if engine != nil {
		if accessor, ok := engine.(rootCAAccessor); ok {
			if len(resolved.HostCAPEM) > 0 {
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(resolved.HostCAPEM) {
					fmt.Fprintln(stderr, "failed to parse Teleport Host CA bundle")
					return 1
				}
				accessor.SetRootCAs(pool)
			}
		}

		// Configure client certificate if available
		if accessor, ok := engine.(clientCertAccessor); ok {
			if len(resolved.ClientCertPEM) > 0 && len(resolved.ClientKeyPEM) > 0 {
				accessor.SetClientCert(resolved.ClientCertPEM, resolved.ClientKeyPEM)
			}
		}
	}

	exec, err := runner.Execute(ctx, resolved, builder, engine)
	if err != nil {
		fmt.Fprintf(stderr, "failed to execute probe plan: %v\n", err)
		return 1
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(exec); err != nil {
		fmt.Fprintf(stderr, "failed to render results: %v\n", err)
		return 1
	}

	return 0
}
