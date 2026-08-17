package job

import (
	"context"
	"fmt"

	"github.com/Coku2015/agentbridge/internal/pg"
	"github.com/Coku2015/agentbridge/internal/vbr"
)

// TransitionFunc is a sink for validated host transitions (persist + SSE,
// FR-038). It receives the pgID discovered so far (may be empty before create).
type TransitionFunc func(from, to HostState, pgID string) error

// EnrollerConfig configures an Enroller.
type EnrollerConfig struct {
	Client     pg.Client
	Poll       pg.PollOptions
	OnChange   TransitionFunc // optional: persist + emit per transition
	StartState HostState      // default HostLocalInstallSucceeded
	PgID       string         // set when resuming/retrying discovery
}

// Enroller drives the enrollment phase for one already-installed host (US5). It
// validates every state transition against the legal table (state.go) and honors
// the registration-only / rescan-only retry edges (FR-031/032): a retry NEVER
// reinstalls and NEVER auto-uninstalls (red line 7).
type Enroller struct {
	client   pg.Client
	poll     pg.PollOptions
	onChange TransitionFunc
	pgID     string
	state    HostState
}

// NewEnroller builds an Enroller from cfg.
func NewEnroller(cfg EnrollerConfig) *Enroller {
	s := cfg.StartState
	if s == "" {
		s = HostLocalInstallSucceeded
	}
	return &Enroller{client: cfg.Client, poll: cfg.Poll, onChange: cfg.OnChange, state: s, pgID: cfg.PgID}
}

// State is the current host state.
func (e *Enroller) State() HostState { return e.state }

// PgID is the discovered Protection Group id (set after a successful create).
func (e *Enroller) PgID() string { return e.pgID }

// to validates + applies a transition, then notifies the sink. An illegal move is
// an error — the runner never silently skips a state-machine check.
func (e *Enroller) to(next HostState) error {
	if !e.state.CanTransitionTo(next) {
		return fmt.Errorf("job: illegal enrollment transition %s -> %s", e.state, next)
	}
	prev := e.state
	e.state = next
	if e.onChange != nil {
		if err := e.onChange(prev, next, e.pgID); err != nil {
			return err
		}
	}
	return nil
}

// Enroll runs full enrollment from LocalInstallSucceeded to Completed. A create
// failure lands the host in InstalledRegistrationFailed; a discovery failure in
// DiscoveryFailed. Both are recoverable via the dedicated retry methods.
func (e *Enroller) Enroll(ctx context.Context, spec vbr.ProtectionGroupSpec) error {
	if err := e.register(ctx, spec); err != nil {
		return err
	}
	return e.discover(ctx)
}

// register moves to CreatingRegistration and idempotently creates the PG. On
// failure the host ends in InstalledRegistrationFailed (registration-only retry).
func (e *Enroller) register(ctx context.Context, spec vbr.ProtectionGroupSpec) error {
	if err := e.to(HostCreatingRegistration); err != nil {
		return err
	}
	id, _, err := pg.Create(ctx, e.client, spec, e.poll)
	if err != nil {
		_ = e.to(HostInstalledRegistrationFailed)
		return fmt.Errorf("enroll: register: %w", err)
	}
	e.pgID = id
	return nil
}

// discover moves to Rescanning, rescans + reads discovered entities, and on success
// advances Discovered -> Completed. On failure the host ends in DiscoveryFailed
// (rescan-only retry). Empty discovery is NOT a failure (Principle IV).
func (e *Enroller) discover(ctx context.Context) error {
	if e.pgID == "" {
		return fmt.Errorf("enroll: discover: no PG id")
	}
	if err := e.to(HostRescanning); err != nil {
		return err
	}
	if _, err := pg.Discover(ctx, e.client, e.pgID, e.poll); err != nil {
		_ = e.to(HostDiscoveryFailed)
		return fmt.Errorf("enroll: discover: %w", err)
	}
	if err := e.to(HostDiscovered); err != nil {
		return err
	}
	return e.to(HostCompleted)
}

// RetryRegistration re-runs ONLY registration from InstalledRegistrationFailed
// (FR-031): no reinstall, no auto-uninstall. On success it continues to discovery.
func (e *Enroller) RetryRegistration(ctx context.Context, spec vbr.ProtectionGroupSpec) error {
	if e.state != HostInstalledRegistrationFailed {
		return fmt.Errorf("job: RetryRegistration only valid from InstalledRegistrationFailed (now %s)", e.state)
	}
	if err := e.register(ctx, spec); err != nil {
		return err
	}
	return e.discover(ctx)
}

// RetryDiscovery re-runs ONLY the rescan from DiscoveryFailed (FR-032): no
// recreation, no reinstall.
func (e *Enroller) RetryDiscovery(ctx context.Context) error {
	if e.state != HostDiscoveryFailed {
		return fmt.Errorf("job: RetryDiscovery only valid from DiscoveryFailed (now %s)", e.state)
	}
	return e.discover(ctx)
}
