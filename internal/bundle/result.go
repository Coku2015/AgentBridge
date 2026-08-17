package bundle

import (
	"encoding/json"
	"strings"
)

// ResultSchemaVersion is the structured bundle-result schema (AB-FR-142).
const ResultSchemaVersion = "1.0"

// AddressList is a []string that decodes from either a JSON array or a single
// comma-separated string. The POSIX install.sh emits a string (shell simplicity)
// while the Go OfflineExecutor emits a real array; both decode correctly here.
type AddressList []string

// UnmarshalJSON accepts ["1.2.3.4","5.6.7.8"] or "1.2.3.4,5.6.7.8".
func (a *AddressList) UnmarshalJSON(data []byte) error {
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*a = AddressList(arr)
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	out := AddressList{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	*a = out
	return nil
}

// Result is the importable structured outcome the bundle's install.sh emits and
// AgentBridge imports back (AB-FR-142/143). It carries NO credentials: only job
// correlation, target identity and the layered install/verify summaries. The
// importer verifies JobID, schema version and the selected package profile
// before AgentBridge continues to VBR enrollment (AB-FR-143).
type Result struct {
	SchemaVersion     string         `json:"schemaVersion"`
	JobID             string         `json:"jobId"`
	OK                bool           `json:"ok"`
	Error             string         `json:"error,omitempty"`
	DeploymentProfile string         `json:"deploymentProfile,omitempty"` // "kit-only" | "agent-plus-kit"
	Target            ResultTarget   `json:"target"`
	Install           InstallSummary `json:"install"`
	Verify            VerifySummary  `json:"verify"`
}

// ResultTarget captures the identity of the host that ran the bundle. The
// importer cross-checks it against the configured target to warn on mismatches
// (AB-FR-086).
type ResultTarget struct {
	HostName     string      `json:"hostName"`
	Architecture string      `json:"architecture"`
	Addresses    AddressList `json:"addresses"`
}

// InstallSummary mirrors executor.InstallResult's non-secret fields (section
// 14.3). Install success is its own layer (Principle IV).
type InstallSummary struct {
	PackageInstalled   bool `json:"packageInstalled"`
	DeploymentKitReady bool `json:"deploymentKitReady"`
	RebootRequired     bool `json:"rebootRequired"`
}

// VerifySummary mirrors executor.LocalVerifyResult's non-secret fields
// (AB-FR-164). Each fact is surfaced independently — never a single green flag.
type VerifySummary struct {
	PackageVersion string `json:"packageVersion"`
	ServiceStatus  string `json:"serviceStatus"`
	AgentStatus    string `json:"agentStatus"`
}
