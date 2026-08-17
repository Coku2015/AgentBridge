package executor

import "context"

// BootstrapExecutor abstracts how AgentBridge probes, prepares, installs,
// verifies and cleans up a target host (section 9). The orchestrator must not
// reference SSH or any concrete transport directly.
type BootstrapExecutor interface {
	Probe(ctx context.Context, target Target) (ProbeResult, error)
	Prepare(ctx context.Context, plan InstallPlan) (PreparedArtifact, error)
	Install(ctx context.Context, plan InstallPlan) (InstallResult, error)
	Verify(ctx context.Context, target Target) (LocalVerifyResult, error)
	Cleanup(ctx context.Context, target Target) error
}

// Kind enumerates the MVP executor types (section 9, MVP 23.1).
type Kind string

const (
	KindSSH      Kind = "ssh"      // SSH Push (9.1)
	KindLocal    Kind = "local"    // Local Run (9.2)
	KindExternal Kind = "external" // External Automation Handoff (9.3)
	KindOffline  Kind = "offline"  // Offline / Air-gap (9.4)
)

// Target identifies a single host. Identifiers only; never secrets.
type Target struct {
	Host      string
	Addresses []string
	Kind      Kind
}

// ProbeResult mirrors the relevant facts gathered by this executor's Probe step.
type ProbeResult struct {
	JSON string // raw versioned probe JSON (probe.Result serialized)
}

// InstallPlan describes what to install. The Deployment Kit IS the install
// payload: a ZIP archive carrying the official installer, the deployment
// service packages and the per-campaign certificates. The executor extracts it
// and runs install-deployment-kit.sh, which sets up the deployment service and
// pairs the certificate; VBR can later push the Agent package through that
// service, or a separately exported standalone package can be used by the
// offline bundle path. Carries no live
// credentials.
type InstallPlan struct {
	DeploymentProfile string // informational, e.g. "kit-payload"
	KitPath           string // staged Deployment Kit — the install payload
}

// PreparedArtifact is the staged artifact (uploaded bundle / local bundle)
// before installation.
type PreparedArtifact struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	RemoteDir string `json:"remoteDir"` // for SSH Push
}

// InstallResult is the per-host local install outcome (section 14.3 layers).
type InstallResult struct {
	PackageInstalled   bool   `json:"packageInstalled"`
	LocalAgentHealthy  bool   `json:"localAgentHealthy"`
	DeploymentKitReady bool   `json:"deploymentKitReady"`
	RebootRequired     bool   `json:"rebootRequired"`
	StructuredResult   string `json:"structuredResult"` // local install script JSON output (AB-FR-142)
}

// LocalVerifyResult captures post-install verification (AB-FR-164).
type LocalVerifyResult struct {
	PackageVersion       string `json:"packageVersion"`
	DeploymentKitVersion string `json:"deploymentKitVersion"`
	ServiceStatus        string `json:"serviceStatus"`
	DeployerStatus       string `json:"deployerStatus"`
	AgentStatus          string `json:"agentStatus"`
	DriverStatus         string `json:"driverStatus"`
}
