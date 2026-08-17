package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Coku2015/agentbridge/internal/vbr"
)

// RescanDetailUnavailable is the stable, UUID-free fallback used when VBR marks
// a rescan failed but does not include an operator-facing result.message.
const RescanDetailUnavailable = "VBR did not return detailed rescan information. Open VBR to view the rescan details."

// ErrRescan separates an operator-facing VBR message from technical context.
// VBRMessage is copied verbatim from SessionResultModel.message when available;
// PG/session UUIDs and transport errors remain only in the wrapped cause/logs.
type ErrRescan struct {
	VBRMessage string
	Failures   []vbr.SessionFailure
	cause      error
}

func (e *ErrRescan) Error() string {
	if e.VBRMessage != "" {
		return e.VBRMessage
	}
	if len(e.Failures) > 0 && e.Failures[0].Message != "" {
		return e.Failures[0].Message
	}
	return RescanDetailUnavailable
}

func (e *ErrRescan) Unwrap() error { return e.cause }

// RescanErrorDetail returns a UI-safe detail and whether it came verbatim from
// VBR. Callers use the boolean to localize only the fallback text.
func RescanErrorDetail(err error) (detail string, fromVBR bool) {
	var rescanErr *ErrRescan
	if errors.As(err, &rescanErr) {
		if len(rescanErr.Failures) > 0 {
			messages := make([]string, 0, len(rescanErr.Failures))
			for _, failure := range rescanErr.Failures {
				if failure.Message != "" {
					messages = append(messages, failure.Message)
				}
			}
			if len(messages) > 0 {
				return strings.Join(messages, "\n"), true
			}
		}
		if rescanErr.VBRMessage != "" {
			return rescanErr.VBRMessage, true
		}
		return RescanDetailUnavailable, false
	}
	return RescanDetailUnavailable, false
}

// Discovery is the layered discovery result. A discovered host whose OS reads
// Unknown/Other is STILL a discovery success — the Agent's own status is
// authoritative, not the OS detection (AB-FR-188, Principle IV).
type Discovery struct {
	Entities []vbr.DiscoveredEntity          `json:"entities"`
	Found    map[string]vbr.DiscoveredEntity `json:"found"` // keyed by lowercased host name
}

// indexByHost keys discovered entities by host name for lookup. Matching is
// case-insensitive because VBR host names and operator-provided names often differ
// in case; this is lookup convenience, never a trust decision.
func indexByHost(entities []vbr.DiscoveredEntity) map[string]vbr.DiscoveredEntity {
	m := make(map[string]vbr.DiscoveredEntity, len(entities))
	for _, e := range entities {
		m[strings.ToLower(e.Host)] = e
	}
	return m
}

// Rescan triggers a PG rescan and awaits its session to completion (FR-030).
func Rescan(ctx context.Context, c Client, pgID string, poll PollOptions) error {
	ref, err := c.RescanProtectionGroup(ctx, pgID)
	if err != nil {
		return &ErrRescan{cause: fmt.Errorf("submit protection group %s rescan: %w", pgID, err)}
	}
	if err := awaitSession(ctx, c, ref.ID, poll); err != nil {
		var waitErr *sessionWaitError
		if errors.As(err, &waitErr) {
			return &ErrRescan{VBRMessage: waitErr.vbrMessage, Failures: waitErr.failures, cause: fmt.Errorf("protection group %s rescan session %s: %w", pgID, ref.ID, err)}
		}
		return &ErrRescan{cause: fmt.Errorf("protection group %s rescan session %s: %w", pgID, ref.ID, err)}
	}
	return nil
}

// Discover runs a rescan then reads discovered entities, returning the layered
// discovery view. It does NOT treat an empty result set as an error — a rescan
// that finds nothing is a valid (if disappointing) discovery state the UI surfaces
// as a distinct layer from install success (Principle IV).
func Discover(ctx context.Context, c Client, pgID string, poll PollOptions) (Discovery, error) {
	if err := Rescan(ctx, c, pgID, poll); err != nil {
		return Discovery{}, err
	}
	entities, err := c.GetDiscoveredEntities(ctx, pgID)
	if err != nil {
		return Discovery{}, fmt.Errorf("pg discover %s: read entities: %w", pgID, err)
	}
	return Discovery{Entities: entities, Found: indexByHost(entities)}, nil
}

// Contains reports whether a host matching name (by host name, case-insensitive)
// was discovered. Used by the batch engine to resolve per-host discovery status.
func (d Discovery) Contains(name string) bool {
	if name == "" {
		return false
	}
	if _, ok := d.Found[strings.ToLower(name)]; ok {
		return true
	}
	return false
}
