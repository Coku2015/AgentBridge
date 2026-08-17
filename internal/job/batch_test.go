package job

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Coku2015/agentbridge/internal/security"
)

// happyPath is the full legal chain Pending → Completed (state.go).
var happyPath = []HostState{
	HostConnecting, HostProbing, HostProbed, HostAwaitingPackageSelection,
	HostPrivilegeChecking, HostPreparingBundle, HostUploading, HostInstallingAgent,
	HostVerifyingLocal, HostLocalInstallSucceeded, HostCreatingRegistration,
	HostRescanning, HostDiscovered, HostCompleted,
}

func happyAction(_ context.Context, _ string, sink HostSink) error {
	for _, s := range happyPath {
		sink(HostPending, s, "")
	}
	return nil
}

// failAtConnect reaches Connecting then the legal failure SSHConnectionFailed.
func failAtConnect(_ context.Context, _ string, sink HostSink) error {
	sink(HostPending, HostConnecting, "")
	sink(HostConnecting, HostSSHConnectionFailed, "host unreachable")
	return nil
}

func mkHosts(n int) []HostTask {
	out := make([]HostTask, n)
	for i := range out {
		out[i] = HostTask{ID: string(rune('a' + i)), Host: string(rune('a' + i))}
	}
	return out
}

func stateOf(b *Batch, id string) HostState {
	for _, s := range b.Snapshot() {
		if s.ID == id {
			return s.State
		}
	}
	return ""
}

// TestFailureIsolation proves a single failing host never blocks or aborts the
// others (AB-NFR-004, FR-037), and the batch ends PartiallyCompleted.
func TestFailureIsolation(t *testing.T) {
	hosts := []HostTask{
		{ID: "a", Host: "a"}, {ID: "b", Host: "b"}, {ID: "c", Host: "c"},
	}
	b := NewBatch(BatchConfig{
		ID: "b1", Concurrency: 3, Hosts: hosts,
		Action: func(ctx context.Context, id string, sink HostSink) error {
			if id == "b" {
				return failAtConnect(ctx, id, sink)
			}
			return happyAction(ctx, id, sink)
		},
	})
	b.Run(context.Background())

	if b.State() != BatchPartiallyCompleted {
		t.Fatalf("batch state = %s, want PartiallyCompleted", b.State())
	}
	if stateOf(b, "a") != HostCompleted || stateOf(b, "c") != HostCompleted {
		t.Fatalf("healthy hosts must complete: a=%s c=%s", stateOf(b, "a"), stateOf(b, "c"))
	}
	if stateOf(b, "b") != HostSSHConnectionFailed {
		t.Fatalf("failing host state = %s, want SSHConnectionFailed", stateOf(b, "b"))
	}
}

// TestConcurrencyCap asserts at most Concurrency hosts run at once (AB-NFR-003).
func TestConcurrencyCap(t *testing.T) {
	const c = 2
	var inFlight, maxObs int32
	hosts := mkHosts(6)
	b := NewBatch(BatchConfig{
		ID: "b2", Concurrency: c, Hosts: hosts,
		Action: func(ctx context.Context, id string, sink HostSink) error {
			cur := atomic.AddInt32(&inFlight, 1)
			for {
				m := atomic.LoadInt32(&maxObs)
				if cur <= m || atomic.CompareAndSwapInt32(&maxObs, m, cur) {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
			atomic.AddInt32(&inFlight, -1)
			return happyAction(ctx, id, sink)
		},
	})
	b.Run(context.Background())
	if maxObs > c {
		t.Fatalf("concurrency exceeded cap: observed %d > %d", maxObs, c)
	}
	if b.State() != BatchCompleted {
		t.Fatalf("batch state = %s, want Completed", b.State())
	}
}

// TestRefreshSafeResume proves Snapshot + ResumeFrom lets a fresh batch skip
// already-terminal hosts on restart (FR-039).
func TestRefreshSafeResume(t *testing.T) {
	hosts := mkHosts(3)
	var ran sync.Map
	first := NewBatch(BatchConfig{ID: "b3", Concurrency: 3, Hosts: hosts, Action: happyAction})
	first.Run(context.Background())
	if first.State() != BatchCompleted {
		t.Fatalf("first run state = %s", first.State())
	}
	snap := first.Snapshot()

	// Second batch: mark all as Completed via resume; the action must NOT run.
	second := NewBatch(BatchConfig{
		ID: "b3b", Concurrency: 3, Hosts: hosts,
		Action: func(ctx context.Context, id string, sink HostSink) error {
			ran.Store(id, true)
			return happyAction(ctx, id, sink)
		},
	})
	second.ResumeFrom(snap)
	second.Run(context.Background())

	anyRan := false
	ran.Range(func(_, v any) bool { anyRan = true; return false })
	if anyRan {
		t.Fatal("resumed (terminal) hosts must not re-run")
	}
}

// TestRedaction proves a registered secret is scrubbed from a host error before
// it is recorded/broadcast (red line 1).
func TestRedaction(t *testing.T) {
	scrub := security.NewScrubber()
	scrub.Add("SUPERSECRET-TOKEN")
	var mu sync.Mutex
	var msgs []string
	b := NewBatch(BatchConfig{
		ID: "b4", Concurrency: 1, Hosts: mkHosts(1), Scrubber: scrub,
		Action: func(_ context.Context, _ string, sink HostSink) error {
			sink(HostPending, HostConnecting, "")
			sink(HostConnecting, HostSSHConnectionFailed, "auth failed for SUPERSECRET-TOKEN")
			return nil
		},
		Publish: func(e BatchEvent) {
			if e.Type == "host" && e.Message != "" {
				mu.Lock()
				msgs = append(msgs, e.Message)
				mu.Unlock()
			}
		},
	})
	b.Run(context.Background())
	mu.Lock()
	defer mu.Unlock()
	for _, m := range msgs {
		if strings.Contains(m, "SUPERSECRET-TOKEN") {
			t.Fatalf("secret leaked in event message: %q", m)
		}
	}
	redacted := false
	for _, m := range msgs {
		if strings.Contains(m, security.Redacted) {
			redacted = true
		}
	}
	if !redacted {
		t.Fatalf("expected redaction in host messages, got %v", msgs)
	}
}

// TestEventsPublished asserts progress events flow through Publish (FR-038).
func TestEventsPublished(t *testing.T) {
	var n int32
	b := NewBatch(BatchConfig{
		ID: "b5", Concurrency: 1, Hosts: mkHosts(2), Action: happyAction,
		Publish: func(BatchEvent) { atomic.AddInt32(&n, 1) },
	})
	b.Run(context.Background())
	if atomic.LoadInt32(&n) < 2 {
		t.Fatalf("expected multiple events, got %d", n)
	}
}
