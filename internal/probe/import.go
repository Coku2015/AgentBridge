package probe

import (
	"encoding/json"
	"fmt"
)

// Import decodes an operator-supplied (offline) probe result and validates its
// schema version (FR-017). The offline path lets a locked-down host's facts be
// brought in without AgentBridge ever holding an SSH credential to it. It carries
// no secrets: a probe Result is pure facts.
func Import(raw []byte) (Result, error) {
	var r Result
	if err := json.Unmarshal(stripShellNoise(raw), &r); err != nil {
		return Result{}, fmt.Errorf("probe import: decode: %w", err)
	}
	if r.SchemaVersion != SchemaVersion {
		return Result{}, fmt.Errorf("probe import: schema mismatch: got %q want %q", r.SchemaVersion, SchemaVersion)
	}
	return r, nil
}
