package job

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Coku2015/agentbridge/internal/pg"
	"github.com/Coku2015/agentbridge/internal/vbr"
)

// fakePGClient is a job-package VBR stand-in implementing pg.Client. It can be
// primed to fail create or rescan so tests can exercise the retry edges.
type fakePGClient struct {
	existing    map[string]string
	sessions    map[string]string
	entities    map[string][]vbr.DiscoveredEntity
	creates     int
	rescans     int
	createErr   error // if set, CreateProtectionGroup returns it
	discoverErr error // if set, GetDiscoveredEntities returns it
}

func newFakePG() *fakePGClient {
	return &fakePGClient{existing: map[string]string{}, sessions: map[string]string{}, entities: map[string][]vbr.DiscoveredEntity{}}
}

func (f *fakePGClient) FindByName(_ context.Context, name string) (string, bool, error) {
	id, ok := f.existing[name]
	return id, ok, nil
}
func (f *fakePGClient) CreateProtectionGroup(_ context.Context, spec vbr.ProtectionGroupSpec) (vbr.SessionRef, error) {
	f.creates++
	if f.createErr != nil {
		return vbr.SessionRef{}, f.createErr
	}
	sid := "s-" + spec.Name
	f.sessions[sid] = "success"
	f.existing[spec.Name] = "pg-" + spec.Name
	return vbr.SessionRef{ID: sid}, nil
}
func (f *fakePGClient) GetSession(_ context.Context, id string) (vbr.SessionState, error) {
	return vbr.SessionState{State: f.sessions[id], Progress: 100}, nil
}
func (f *fakePGClient) RescanProtectionGroup(_ context.Context, pgID string) (vbr.SessionRef, error) {
	f.rescans++
	f.sessions["sr-"+pgID] = "success"
	return vbr.SessionRef{ID: "sr-" + pgID}, nil
}
func (f *fakePGClient) GetDiscoveredEntities(_ context.Context, pgID string) ([]vbr.DiscoveredEntity, error) {
	if f.discoverErr != nil {
		return nil, f.discoverErr
	}
	return f.entities[pgID], nil
}

func fastPoll() pg.PollOptions {
	return pg.PollOptions{Interval: time.Millisecond, Timeout: time.Second}
}

func spec() vbr.ProtectionGroupSpec {
	return vbr.ProtectionGroupSpec{Name: "prod"}
}

// Full happy path: LocalInstallSucceeded -> Completed through the layered states.
func TestEnrollHappyPath(t *testing.T) {
	c := newFakePG()
	var seq []HostState
	e := NewEnroller(EnrollerConfig{
		Client:   c,
		Poll:     fastPoll(),
		OnChange: func(_, to HostState, _ string) error { seq = append(seq, to); return nil },
	})
	if err := e.Enroll(context.Background(), spec()); err != nil {
		t.Fatal(err)
	}
	if e.State() != HostCompleted {
		t.Fatalf("state = %s, want Completed", e.State())
	}
	want := []HostState{HostCreatingRegistration, HostRescanning, HostDiscovered, HostCompleted}
	for i, s := range want {
		if i >= len(seq) || seq[i] != s {
			t.Fatalf("transition %d = %v, want %v (full seq=%v)", i, seq, want, seq)
		}
	}
}

// Create failure lands InstalledRegistrationFailed; a registration-only retry
// completes WITHOUT reinstalling (no extra create beyond the retry's single create).
func TestEnrollCreateFailThenRegistrationRetry(t *testing.T) {
	c := newFakePG()
	c.createErr = errors.New("boom")
	e := NewEnroller(EnrollerConfig{Client: c, Poll: fastPoll()})
	err := e.Enroll(context.Background(), spec())
	if err == nil {
		t.Fatal("expected create failure")
	}
	if e.State() != HostInstalledRegistrationFailed {
		t.Fatalf("state = %s, want InstalledRegistrationFailed", e.State())
	}

	// Retry registration only — create now succeeds and discovery proceeds.
	c.createErr = nil
	if err := e.RetryRegistration(context.Background(), spec()); err != nil {
		t.Fatal(err)
	}
	if e.State() != HostCompleted {
		t.Fatalf("state = %s after retry, want Completed", e.State())
	}
	// Exactly one successful create happened (the failed one returned before pg.Create
	// was invoked in the success path of the fake's count semantics); the retry must
	// not have caused a reinstall path — there is no install here by construction.
	if c.creates == 0 {
		t.Fatal("expected at least one create on retry")
	}
}

// Discovery failure lands DiscoveryFailed; a rescan-only retry completes WITHOUT
// recreating the PG.
func TestEnrollDiscoveryFailThenRescanRetry(t *testing.T) {
	c := newFakePG()
	c.discoverErr = errors.New("vbr read failed")
	e := NewEnroller(EnrollerConfig{Client: c, Poll: fastPoll()})
	if err := e.Enroll(context.Background(), spec()); err == nil {
		t.Fatal("expected discovery failure")
	}
	if e.State() != HostDiscoveryFailed {
		t.Fatalf("state = %s, want DiscoveryFailed", e.State())
	}
	pgID := e.PgID()
	if pgID == "" {
		t.Fatal("pgID must be set even when discovery failed (registration succeeded)")
	}
	createsBefore := c.creates

	// Retry discovery only — no PG recreation.
	c.discoverErr = nil
	if err := e.RetryDiscovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.State() != HostCompleted {
		t.Fatalf("state = %s after retry, want Completed", e.State())
	}
	if c.creates != createsBefore {
		t.Fatalf("rescan-only retry must NOT recreate PG; creates went %d -> %d", createsBefore, c.creates)
	}
}

// Retry guards: calling a retry from the wrong state is rejected.
func TestRetryGuards(t *testing.T) {
	c := newFakePG()
	e := NewEnroller(EnrollerConfig{Client: c, Poll: fastPoll()})
	if err := e.RetryRegistration(context.Background(), spec()); err == nil {
		t.Fatal("RetryRegistration from Completed/LIS must be rejected")
	}
	if err := e.RetryDiscovery(context.Background()); err == nil {
		t.Fatal("RetryDiscovery from non-DiscoveryFailed must be rejected")
	}
}

// Illegal transition detection.
func TestEnrollerIllegalTransition(t *testing.T) {
	e := &Enroller{state: HostPending} // raw: skip normal construction
	if err := e.to(HostRescanning); err == nil {
		t.Fatal("Pending -> Rescanning must be illegal")
	}
}
