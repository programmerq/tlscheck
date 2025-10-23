package runner

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/programmerq/tlscheck/internal/config"
	"github.com/programmerq/tlscheck/internal/plan"
	"github.com/programmerq/tlscheck/internal/probe"
)

type stubEngine struct {
	lastPlan plan.Plan
	results  []probe.Result
	err      error
}

func (s *stubEngine) Run(ctx context.Context, p plan.Plan) ([]probe.Result, error) {
	s.lastPlan = p
	return s.results, s.err
}

type stubBuilder struct {
	plan plan.Plan
	err  error
}

func (s *stubBuilder) Build(opts config.Options) (plan.Plan, error) {
	return s.plan, s.err
}

func TestExecuteSuccess(t *testing.T) {
	t.Parallel()

	opts := config.Options{PublicAddr: "proxy.example.com"}
	expectedPlan := plan.Plan{Targets: []plan.ProbeTarget{{ServiceKey: "proxy_web"}}}
	expectedResults := []probe.Result{{Target: expectedPlan.Targets[0], Attempt: 1}}

	builder := &stubBuilder{plan: expectedPlan}
	engine := &stubEngine{results: expectedResults}

	exec, err := Execute(context.Background(), opts, builder, engine)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if !reflect.DeepEqual(exec.Plan, expectedPlan) {
		t.Fatalf("execution plan mismatch:\n got %#v\nwant %#v", exec.Plan, expectedPlan)
	}
	if !reflect.DeepEqual(exec.Results, expectedResults) {
		t.Fatalf("execution results mismatch:\n got %#v\nwant %#v", exec.Results, expectedResults)
	}

	if !reflect.DeepEqual(engine.lastPlan, expectedPlan) {
		t.Fatalf("engine received unexpected plan: %#v", engine.lastPlan)
	}
}

func TestExecuteBuilderError(t *testing.T) {
	t.Parallel()

	builderErr := errors.New("plan failed")
	builder := &stubBuilder{err: builderErr}

	exec, err := Execute(context.Background(), config.Options{}, builder, &stubEngine{})
	if err == nil {
		t.Fatalf("Execute returned nil error, want %v", builderErr)
	}
	if exec.Plan.Targets != nil || exec.Results != nil {
		t.Fatalf("expected empty execution on error, got %#v", exec)
	}
}

func TestExecuteEngineError(t *testing.T) {
	t.Parallel()

	expectedPlan := plan.Plan{Targets: []plan.ProbeTarget{{ServiceKey: "proxy_web"}}}
	engineErr := errors.New("dial failed")
	engine := &stubEngine{err: engineErr}
	builder := &stubBuilder{plan: expectedPlan}

	exec, err := Execute(context.Background(), config.Options{}, builder, engine)
	if err == nil {
		t.Fatalf("Execute returned nil error, want %v", engineErr)
	}
	if !reflect.DeepEqual(engine.lastPlan, expectedPlan) {
		t.Fatalf("engine received unexpected plan: %#v", engine.lastPlan)
	}
	if exec.Plan.Targets != nil || exec.Results != nil {
		t.Fatalf("expected empty execution on error, got %#v", exec)
	}
}

func TestExecuteRequiresDependencies(t *testing.T) {
	t.Parallel()

	if _, err := Execute(context.Background(), config.Options{}, nil, &stubEngine{}); err == nil {
		t.Fatalf("Execute accepted nil builder")
	}
	if _, err := Execute(context.Background(), config.Options{}, &stubBuilder{}, nil); err == nil {
		t.Fatalf("Execute accepted nil engine")
	}
}
