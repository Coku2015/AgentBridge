package pg

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Coku2015/agentbridge/internal/vbr"
)

// fakeClient is an in-memory VBR stand-in for enrollment unit tests. It records
// every call so tests can assert idempotency (no duplicate create) and retry shape.
type fakeClient struct {
	existing       map[string]string // name -> pgID (the pre-query answer)
	creates        int
	rescans        int
	sessions       map[string]string
	sessionDetails map[string]vbr.SessionState
	entities       map[string][]vbr.DiscoveredEntity
}

func newFakeClient() *fakeClient {
	return &fakeClient{
		existing:       map[string]string{},
		sessions:       map[string]string{},
		sessionDetails: map[string]vbr.SessionState{},
		entities:       map[string][]vbr.DiscoveredEntity{},
	}
}

func (f *fakeClient) FindByName(_ context.Context, name string) (string, bool, error) {
	id, ok := f.existing[name]
	return id, ok, nil
}
func (f *fakeClient) CreateProtectionGroup(_ context.Context, spec vbr.ProtectionGroupSpec) (vbr.SessionRef, error) {
	f.creates++
	sid := "sess-create-" + spec.Name
	f.sessions[sid] = "success"
	f.existing[spec.Name] = "pg-" + spec.Name // visible to a subsequent FindByName
	return vbr.SessionRef{ID: sid}, nil
}
func (f *fakeClient) GetSession(_ context.Context, id string) (vbr.SessionState, error) {
	if state, ok := f.sessionDetails[id]; ok {
		return state, nil
	}
	return vbr.SessionState{State: f.sessions[id], Progress: 100}, nil
}
func (f *fakeClient) RescanProtectionGroup(_ context.Context, pgID string) (vbr.SessionRef, error) {
	f.rescans++
	f.sessions["sess-rescan-"+pgID] = "success"
	return vbr.SessionRef{ID: "sess-rescan-" + pgID}, nil
}
func (f *fakeClient) GetDiscoveredEntities(_ context.Context, pgID string) ([]vbr.DiscoveredEntity, error) {
	return f.entities[pgID], nil
}

func fastPoll() PollOptions { return PollOptions{Interval: time.Millisecond, Timeout: time.Second} }

// A duplicate name is rejected so the UI never mutates or rescans an existing
// Protection Group by accident.
func TestCreateNameConflict(t *testing.T) {
	c := newFakeClient()
	c.existing["prod-linux"] = "pg-1"

	spec := vbr.ProtectionGroupSpec{Name: "prod-linux"}
	_, _, err := Create(context.Background(), c, spec, fastPoll())
	if _, ok := err.(*ErrNameConflict); !ok {
		t.Fatalf("error = %T (%v), want ErrNameConflict", err, err)
	}
	if c.creates != 0 {
		t.Fatalf("must not call create on conflict; got %d creates", c.creates)
	}
}

func TestCreateNewThenConflict(t *testing.T) {
	c := newFakeClient()
	spec := vbr.ProtectionGroupSpec{Name: "prod-linux"}

	// First call creates.
	id1, created1, err := Create(context.Background(), c, spec, fastPoll())
	if err != nil {
		t.Fatal(err)
	}
	if !created1 || id1 != "pg-prod-linux" {
		t.Fatalf("first create: id=%s created=%v", id1, created1)
	}
	// Second call rejects — no duplicate create or rescan.
	_, _, err = Create(context.Background(), c, spec, fastPoll())
	if _, ok := err.(*ErrNameConflict); !ok {
		t.Fatalf("error = %T (%v), want ErrNameConflict", err, err)
	}
	if c.creates != 1 {
		t.Fatalf("want exactly 1 create, got %d", c.creates)
	}
}

func TestCreateRequiresName(t *testing.T) {
	c := newFakeClient()
	_, _, err := Create(context.Background(), c, vbr.ProtectionGroupSpec{}, fastPoll())
	if err == nil {
		t.Fatal("expected rejection of empty name")
	}
}

func TestDiscoverLayered(t *testing.T) {
	c := newFakeClient()
	c.entities["pg-1"] = []vbr.DiscoveredEntity{
		{Host: "node-1", Online: true, AgentStatus: "Ready", AgentVersion: "6.0"},
	}
	d, err := Discover(context.Background(), c, "pg-1", fastPoll())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Entities) != 1 {
		t.Fatalf("entities = %d", len(d.Entities))
	}
	if got := d.Found["node-1"]; got.AgentStatus != "Ready" {
		t.Fatalf("lookup failed: %+v", got)
	}
	if c.rescans != 1 {
		t.Fatalf("want 1 rescan, got %d", c.rescans)
	}
}

// Empty discovery is NOT an error — distinct layer from install success (IV).
func TestDiscoverEmptyIsNotError(t *testing.T) {
	c := newFakeClient()
	d, err := Discover(context.Background(), c, "pg-1", fastPoll())
	if err != nil {
		t.Fatalf("empty discovery must not error: %v", err)
	}
	if len(d.Entities) != 0 {
		t.Fatalf("expected no entities, got %d", len(d.Entities))
	}
}

func TestAwaitSessionFailure(t *testing.T) {
	c := newFakeClient()
	c.sessions["sess-create-fail"] = "failed"
	if err := awaitSession(context.Background(), c, "sess-create-fail", fastPoll()); err == nil {
		t.Fatal("expected failed-session error")
	}
}

func TestRescanPreservesVBRFailureMessageWithoutExposingUUIDs(t *testing.T) {
	c := newFakeClient()
	const pgID = "d1d9bd7c-883e-4742-b210-e7625de8476b"
	const sessionID = "sess-rescan-" + pgID
	const vbrMessage = "testlab Error: System reboot is required to continue installation"
	c.sessionDetails[sessionID] = vbr.SessionState{
		State:   "Stopped",
		Result:  "Failed",
		Message: vbrMessage,
	}

	err := Rescan(context.Background(), c, pgID, fastPoll())
	if err == nil {
		t.Fatal("expected failed rescan")
	}
	detail, fromVBR := RescanErrorDetail(err)
	if !fromVBR || detail != vbrMessage || err.Error() != vbrMessage {
		t.Fatalf("detail=%q fromVBR=%v error=%q", detail, fromVBR, err)
	}
	if strings.Contains(err.Error(), pgID) || strings.Contains(err.Error(), sessionID) {
		t.Fatalf("operator error exposes UUID: %q", err)
	}
}

func TestRescanUsesUUIDFreeFallbackForGenericVBRResult(t *testing.T) {
	c := newFakeClient()
	const pgID = "d1d9bd7c-883e-4742-b210-e7625de8476b"
	const sessionID = "sess-rescan-" + pgID
	c.sessionDetails[sessionID] = vbr.SessionState{
		State:   "Stopped",
		Result:  "Failed",
		Message: "Failed",
	}

	err := Rescan(context.Background(), c, pgID, fastPoll())
	detail, fromVBR := RescanErrorDetail(err)
	if fromVBR || detail != RescanDetailUnavailable {
		t.Fatalf("detail=%q fromVBR=%v", detail, fromVBR)
	}
	if strings.Contains(err.Error(), pgID) || strings.Contains(err.Error(), sessionID) {
		t.Fatalf("fallback exposes UUID: %q", err)
	}
}

func TestRescanReturnsPerHostTaskFailure(t *testing.T) {
	c := newFakeClient()
	const pgID = "pg-win11"
	const sessionID = "sess-rescan-" + pgID
	const vbrMessage = "testlab Error: System reboot is required to continue installation"
	c.sessionDetails[sessionID] = vbr.SessionState{
		State:   "Stopped",
		Result:  "Failed",
		Message: "Rescan failed, check session log for details.",
		Failures: []vbr.SessionFailure{{
			Host:    "10.10.1.22",
			Message: vbrMessage,
		}},
	}

	err := Rescan(context.Background(), c, pgID, fastPoll())
	var rescanErr *ErrRescan
	if !errors.As(err, &rescanErr) {
		t.Fatalf("error = %T (%v)", err, err)
	}
	if len(rescanErr.Failures) != 1 || rescanErr.Failures[0].Host != "10.10.1.22" || rescanErr.Failures[0].Message != vbrMessage {
		t.Fatalf("failures = %#v", rescanErr.Failures)
	}
	detail, fromVBR := RescanErrorDetail(err)
	if !fromVBR || detail != vbrMessage {
		t.Fatalf("detail=%q fromVBR=%v", detail, fromVBR)
	}
}

func TestAwaitSessionTimeout(t *testing.T) {
	c := newFakeClient()
	// A perpetually-running session with a tiny timeout budget.
	c.sessions["running"] = "running"
	err := awaitSession(context.Background(), c, "running", PollOptions{Interval: time.Millisecond, Timeout: 5 * time.Millisecond})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
