// Package pg drives VBR enrollment for an installed Agent: idempotently create a
// certificate-based Individual Computers Protection Group, trigger Rescan and read
// Discovered Entities (section 13.10, section 12).
//
// It depends only on the shared vbr domain types + a Client abstraction (never on
// *vbr.RESTAdapter concretely — SOLID-D), so it is fully unit-testable with a fake.
//
// Invariants enforced here:
//   - Exclusive PG names: an existing name returns a conflict and is never reused or mutated.
//   - Certificate connection mode only (the trust-by-certificate model).
//   - Discovery success is DISTINCT from install success (Principle IV); an
//     operatingSystem of Unknown/Other is NOT a discovery failure (AB-FR-188).
package pg

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Coku2015/agentbridge/internal/vbr"
)

// ErrNameConflict indicates that a Protection Group with the requested name
// already exists. AgentBridge deliberately refuses to reuse or mutate it so
// edits made in VBR remain authoritative.
type ErrNameConflict struct {
	Name string
}

func (e *ErrNameConflict) Error() string {
	return fmt.Sprintf("protection group %q already exists; choose a different name or edit the existing group in VBR", e.Name)
}

// sessionWaitError retains the session ID and underlying cause for server-side
// diagnostics while keeping Error() safe for any caller that might surface it
// to an operator. VBR's result message is kept verbatim when it contains a real
// explanation instead of only repeating the result enum.
type sessionWaitError struct {
	kind       string
	sessionID  string
	vbrMessage string
	failures   []vbr.SessionFailure
	cause      error
}

func (e *sessionWaitError) Error() string {
	if e.vbrMessage != "" {
		return e.vbrMessage
	}
	switch e.kind {
	case "timeout":
		return "VBR session timed out"
	case "poll":
		return "VBR session status could not be read"
	default:
		return "VBR session failed"
	}
}

func (e *sessionWaitError) Unwrap() error { return e.cause }

// Client abstracts the VBR Protection-Group operations enrollment needs. The
// concrete *vbr.RESTAdapter satisfies it structurally; pg never names RESTAdapter.
type Client interface {
	// FindByName returns the VBR id of a PG with the given name, or "" + false.
	// It is used as a preflight name-conflict check; existing groups are never reused.
	FindByName(ctx context.Context, name string) (id string, found bool, err error)
	CreateProtectionGroup(ctx context.Context, spec vbr.ProtectionGroupSpec) (vbr.SessionRef, error)
	GetSession(ctx context.Context, id string) (vbr.SessionState, error)
	RescanProtectionGroup(ctx context.Context, id string) (vbr.SessionRef, error)
	GetDiscoveredEntities(ctx context.Context, pgID string) ([]vbr.DiscoveredEntity, error)
}

// PollOptions bounds async-session polling. Zero values default to sane bounds.
type PollOptions struct {
	Interval time.Duration
	Timeout  time.Duration
}

func (p PollOptions) interval() time.Duration {
	if p.Interval <= 0 {
		return time.Second
	}
	return p.Interval
}
func (p PollOptions) timeout() time.Duration {
	if p.Timeout <= 0 {
		return 2 * time.Minute
	}
	return p.Timeout
}

// Create creates a certificate-based Individual Computers PG. Existing names
// are rejected rather than reused or updated, preserving any VBR-side edits.
func Create(ctx context.Context, c Client, spec vbr.ProtectionGroupSpec, poll PollOptions) (string, bool, error) {
	spec.Name = strings.TrimSpace(spec.Name)
	if err := validateSpec(spec); err != nil {
		return "", false, err
	}
	// Pre-create query: names are intentionally exclusive. A caller that retries
	// after losing the response must choose whether to inspect VBR explicitly;
	// AgentBridge never guesses and never overwrites an existing group.
	if id, found, err := c.FindByName(ctx, spec.Name); err != nil {
		return "", false, fmt.Errorf("pg create: pre-query %q: %w", spec.Name, err)
	} else if found {
		_ = id
		return "", false, &ErrNameConflict{Name: spec.Name}
	}
	ref, err := c.CreateProtectionGroup(ctx, spec)
	if err != nil {
		return "", false, fmt.Errorf("pg create: submit %q: %w", spec.Name, err)
	}
	if err := awaitSession(ctx, c, ref.ID, poll); err != nil {
		return "", false, fmt.Errorf("pg create %q: %w", spec.Name, err)
	}
	// The create session yields a reference, not the entity id; resolve by name.
	id, found, err := c.FindByName(ctx, spec.Name)
	if err != nil || !found {
		return "", false, fmt.Errorf("pg create %q: created PG not found after session", spec.Name)
	}
	return id, true, nil
}

// validateSpec enforces a non-empty name. The certificate model is inherent to
// vbr.ProtectionGroupSpec: every computer is enrolled with connectionType
// "Certificate", so no long-lived VBR credential can even be expressed here.
func validateSpec(spec vbr.ProtectionGroupSpec) error {
	if spec.Name == "" {
		return fmt.Errorf("pg: protection group name is required")
	}
	return nil
}

// awaitSession polls a session until it reaches a terminal state or the poll
// budget is exhausted. Per the 1.3-rev2 SessionModel, outcome lives in `result`
// (Success/Warning/Failed/None) and lifecycle in `state` (Working/Stopped/...):
//   - result Success or Warning  -> done, not an error (a warning means the PG
//     was created with a non-fatal caveat);
//   - result Failed              -> explicit error;
//   - state Stopped with no result -> terminal, treated as success (idle stop).
//
// Matching is case-insensitive so fakes and future enum spellings both work.
func awaitSession(ctx context.Context, c Client, sessionID string, poll PollOptions) error {
	deadline := time.Now().Add(poll.timeout())
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		s, err := c.GetSession(ctx, sessionID)
		if err != nil {
			return &sessionWaitError{kind: "poll", sessionID: sessionID, cause: err}
		}
		switch {
		case eqAny(s.Result, "Success", "Warning") || eqAny(s.State, "Success", "Warning"):
			return nil
		case eqAny(s.Result, "Failed") || eqAny(s.State, "Failed"):
			message := s.Message
			if !meaningfulVBRSessionMessage(message, s.Result) {
				message = ""
			}
			return &sessionWaitError{kind: "failed", sessionID: sessionID, vbrMessage: message, failures: s.Failures}
		case eqAny(s.State, "Stopped") && s.Result == "":
			return nil
		}
		if time.Now().After(deadline) {
			return &sessionWaitError{kind: "timeout", sessionID: sessionID}
		}
		select {
		case <-time.After(poll.interval()):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// meaningfulVBRSessionMessage rejects enum-only placeholders such as "Failed".
// A useful message is otherwise returned to the UI exactly as VBR supplied it.
func meaningfulVBRSessionMessage(message, result string) bool {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" || strings.EqualFold(trimmed, strings.TrimSpace(result)) {
		return false
	}
	lower := strings.ToLower(trimmed)
	if strings.Contains(lower, "check session log for details") || strings.Contains(lower, "check the session log for details") {
		return false
	}
	return !eqAny(trimmed, "None", "Success", "Warning", "Failed", "Failure", "Error")
}

// eqAny reports whether s equals any want, case-insensitively.
func eqAny(s string, want ...string) bool {
	for _, w := range want {
		if strings.EqualFold(s, w) {
			return true
		}
	}
	return false
}
