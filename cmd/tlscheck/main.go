package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/programmerq/tlscheck/internal/config"
	"github.com/programmerq/tlscheck/internal/plan"
	"github.com/programmerq/tlscheck/internal/version"
)

func main() {
	opts, showVersion, err := config.ParseArgs(os.Args[1:], plan.ServiceKeys())
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "failed to parse arguments: %v\n", err)
		os.Exit(2)
	}

	if showVersion {
		fmt.Fprintln(os.Stdout, version.Version)
		return
	}

	ctx := context.Background()
	resolved, err := config.ResolveRuntime(ctx, opts)
	if err != nil {
		if errors.Is(err, config.ErrProxyServerRequired) {
			fmt.Fprintln(os.Stderr, "no active tsh profile. specify a proxy via --proxy-server")
			config.Usage()
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "failed to resolve runtime defaults: %v\n", err)
		os.Exit(1)
	}

	probePlan, err := plan.Build(resolved)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build probe plan: %v\n", err)
		os.Exit(1)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(probePlan); err != nil {
		fmt.Fprintf(os.Stderr, "failed to render plan: %v\n", err)
		os.Exit(1)
	}
}
