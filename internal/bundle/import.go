package bundle

import (
	"encoding/json"
	"fmt"
)

// ImportOptions controls how an imported bundle result is verified before
// AgentBridge continues to VBR enrollment (AB-FR-143).
type ImportOptions struct {
	// ExpectedJobID, when non-empty, must equal Result.JobID. This correlates a
	// result to the bundle AgentBridge generated (AB-FR-142).
	ExpectedJobID string
	// ExpectedProfile, when non-empty, must equal Result.DeploymentProfile. This
	// guarantees the installed profile is the one the operator selected.
	ExpectedProfile string
}

// Import decodes an offline bundle result (the result.json emitted by
// install.sh or the OfflineExecutor) and verifies it against opts before
// returning. It performs NO network/credential operation. A mismatched JobID or
// profile is an error — AgentBridge must not enroll against an uncorrelated
// result (AB-FR-143).
func Import(raw []byte, opts ImportOptions) (*Result, error) {
	var r Result
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("bundle: decode result: %w", err)
	}
	if r.SchemaVersion != ResultSchemaVersion {
		return nil, fmt.Errorf("bundle: schema mismatch: got %q want %q", r.SchemaVersion, ResultSchemaVersion)
	}
	if !r.OK {
		if r.Error == "" {
			r.Error = "bundle install reported failure"
		}
		return &r, fmt.Errorf("bundle: install failed: %s", r.Error)
	}
	if !IsSupportedProfile(r.DeploymentProfile) {
		return nil, fmt.Errorf("bundle: unsupported deployment profile %q; every profile must include Deployment Kit", r.DeploymentProfile)
	}
	if opts.ExpectedJobID != "" && r.JobID != opts.ExpectedJobID {
		return nil, fmt.Errorf("bundle: job id mismatch: got %q want %q", r.JobID, opts.ExpectedJobID)
	}
	if opts.ExpectedProfile != "" && r.DeploymentProfile != "" && r.DeploymentProfile != opts.ExpectedProfile {
		return nil, fmt.Errorf("bundle: profile mismatch: got %q want %q", r.DeploymentProfile, opts.ExpectedProfile)
	}
	return &r, nil
}
