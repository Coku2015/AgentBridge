package job

import (
	"context"
	"fmt"
	"sync"

	"github.com/Coku2015/agentbridge/internal/security"
)

// DefaultConcurrency is the batch concurrency cap (AB-NFR-003).
const DefaultConcurrency = 10

// HostSink reports a validated host state transition + progress message for one
// host. The batch validates every transition against the legal table (state.go)
// before recording it — an Action can never place a host in an illegal state.
type HostSink func(from, to HostState, msg string)

// HostAction is the per-host work (probe→install→enroll, or a sub-phase on
// retry). It is abstract so the batch engine is transport-agnostic and unit-
// testable without SSH/VBR (SOLID-D, frozen contract). It owns the per-host
// state machine and reports progress through sink.
type HostAction func(ctx context.Context, hostID string, sink HostSink) error

// HostTask is one host in a batch. It carries ONLY non-secret config (FR-014,
// red line 1): no password, key, token or passphrase is ever present here.
type HostTask struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

// HostSnapshot is the non-secret, persistable/resumable per-host view (FR-039).
// It is safe to journal and SSE-broadcast.
type HostSnapshot struct {
	ID    string    `json:"id"`
	Host  string    `json:"host"`
	State HostState `json:"state"`
	Error string    `json:"error,omitempty"` // redacted
}

// BatchEvent is the job-native progress event. The HTTP layer adapts it to its
// SSE Event (job must not import httpserver — no cycle).
type BatchEvent struct {
	Type       string // "host" | "batch"
	BatchID    string
	HostID     string
	State      HostState
	BatchState BatchState
	Message    string
}

// BatchConfig configures a batch run.
type BatchConfig struct {
	ID          string
	Concurrency int // default DefaultConcurrency (AB-NFR-003)
	Hosts       []HostTask
	Action      HostAction
	Publish     func(BatchEvent)   // optional: SSE + journal sink
	Scrubber    *security.Scrubber // optional: redacts error messages (red line 1)
	// InitialState seeds every host's starting state (default HostPending). An
	// enrollment batch sets this to HostLocalInstallSucceeded (hosts are assumed
	// already installed); an install batch leaves it Pending.
	InitialState HostState
}

// Batch runs a set of hosts with bounded concurrency and single-host failure
// isolation (AB-NFR-004): one host's error or panic never aborts the others. All
// per-host state changes are validated and observable via Snapshot()/Publish.
type Batch struct {
	mu     sync.Mutex
	cfg    BatchConfig
	order  []string // stable host ID order
	tasks  map[string]HostTask
	states map[string]HostState
	errs   map[string]string
	state  BatchState
	run    bool
}

// NewBatch builds a batch from cfg (all hosts start Pending).
func NewBatch(cfg BatchConfig) *Batch {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	initState := cfg.InitialState
	if initState == "" {
		initState = HostPending
	}
	b := &Batch{
		cfg:    cfg,
		tasks:  make(map[string]HostTask, len(cfg.Hosts)),
		states: make(map[string]HostState, len(cfg.Hosts)),
		errs:   make(map[string]string, len(cfg.Hosts)),
		state:  BatchCreated,
	}
	for _, h := range cfg.Hosts {
		if h.ID == "" {
			h.ID = h.Host
		}
		b.order = append(b.order, h.ID)
		b.tasks[h.ID] = h
		b.states[h.ID] = initState
	}
	return b
}

// State returns the current batch-level state.
func (b *Batch) State() BatchState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// Snapshot returns the non-secret per-host view in stable order (FR-038/039).
func (b *Batch) Snapshot() []HostSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]HostSnapshot, 0, len(b.order))
	for _, id := range b.order {
		out = append(out, HostSnapshot{ID: id, Host: b.tasks[id].Host, State: b.states[id], Error: b.errs[id]})
	}
	return out
}

// ResumeFrom seeds per-host state from a previous snapshot (FR-039 restart-
// resume). Only non-terminal hosts are re-run by a subsequent Run.
func (b *Batch) ResumeFrom(snaps []HostSnapshot) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range snaps {
		if _, ok := b.states[s.ID]; ok {
			b.states[s.ID] = s.State
			b.errs[s.ID] = s.Error
		}
	}
}

// transition validates + records a host transition and publishes it. Illegal
// transitions are ignored (defensive: the Action cannot lie a host into a bad
// state). The `from` argument is informational; the actual current state is the
// source of truth.
func (b *Batch) transition(hostID string, from, to HostState, msg string) {
	b.mu.Lock()
	cur := b.states[hostID]
	if !cur.CanTransitionTo(to) {
		b.mu.Unlock()
		return
	}
	b.states[hostID] = to
	b.mu.Unlock()
	b.publish(BatchEvent{Type: "host", BatchID: b.cfg.ID, HostID: hostID, State: to, Message: b.scrub(msg)})
}

// fail records a redacted error against a host without forcing a specific
// failure state (the Action is expected to have landed it already; this is the
// backstop for an Action that returned an error mid-flight).
func (b *Batch) fail(hostID, msg string) {
	b.mu.Lock()
	b.errs[hostID] = b.scrub(msg)
	st := b.states[hostID]
	b.mu.Unlock()
	b.publish(BatchEvent{Type: "host", BatchID: b.cfg.ID, HostID: hostID, State: st, Message: b.errs[hostID]})
}

func (b *Batch) scrub(s string) string {
	if b.cfg.Scrubber == nil {
		return s
	}
	return b.cfg.Scrubber.Scrub(s)
}

func (b *Batch) publish(e BatchEvent) {
	if b.cfg.Publish != nil {
		b.cfg.Publish(e)
	}
}

// Run executes every non-terminal host with bounded concurrency. A single host
// failure (error or panic) is isolated: it never cancels or blocks the others
// (AB-NFR-004). Run is idempotent — a second call is a no-op.
func (b *Batch) Run(ctx context.Context) {
	b.mu.Lock()
	if b.run {
		b.mu.Unlock()
		return
	}
	b.run = true
	b.state = BatchExecuting
	hosts := make([]HostTask, 0, len(b.order))
	for _, id := range b.order {
		if !b.states[id].IsTerminal() {
			hosts = append(hosts, b.tasks[id])
		}
	}
	b.mu.Unlock()
	b.publish(BatchEvent{Type: "batch", BatchID: b.cfg.ID, BatchState: BatchExecuting})

	sem := make(chan struct{}, b.cfg.Concurrency)
	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Add(1)
		go func(h HostTask) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			defer func() {
				if r := recover(); r != nil {
					b.fail(h.ID, fmt.Sprintf("host action panic: %v", r))
				}
			}()
			err := b.cfg.Action(ctx, h.ID, func(from, to HostState, msg string) {
				b.transition(h.ID, from, to, msg)
			})
			if err != nil {
				b.fail(h.ID, err.Error())
			}
		}(h)
	}
	wg.Wait()
	b.finalize()
}

// finalize derives the batch outcome from per-host states (FR-037).
func (b *Batch) finalize() {
	b.mu.Lock()
	completed, failed := 0, 0
	for _, id := range b.order {
		st := b.states[id]
		switch {
		case st == HostCompleted:
			completed++
		case st.IsFailure() || b.errs[id] != "":
			failed++
		}
	}
	switch {
	case failed == 0:
		b.state = BatchCompleted
	case completed > 0:
		b.state = BatchPartiallyCompleted
	default:
		b.state = BatchFailed
	}
	final := b.state
	b.mu.Unlock()
	b.publish(BatchEvent{Type: "batch", BatchID: b.cfg.ID, BatchState: final})
}

// Retry re-runs ONE host's failed phase (FR-031/032 idempotent retry). The host
// must be in a terminal/failure state; Run semantics apply for just that host.
func (b *Batch) Retry(ctx context.Context, hostID string) error {
	b.mu.Lock()
	h, ok := b.tasks[hostID]
	cur := b.states[hostID]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("batch: unknown host %s", hostID)
	}
	if !cur.IsTerminal() {
		return fmt.Errorf("batch: host %s not terminal (state %s)", hostID, cur)
	}
	err := b.cfg.Action(ctx, h.ID, func(from, to HostState, msg string) {
		b.transition(h.ID, from, to, msg)
	})
	if err != nil {
		b.fail(h.ID, err.Error())
	}
	return nil
}
