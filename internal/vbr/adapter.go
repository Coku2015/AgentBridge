package vbr

import (
	"context"
	"io"
	"time"
)

// VBRAdapter isolates the rest of AgentBridge from a concrete VBR REST API
// revision (section 20). Implementations must:
//   - pin TLS on first connect and never set a global InsecureSkipVerify
//     (section 17.3);
//   - poll async Task/Session with unified timeout/cancel semantics;
//   - use idempotency keys or pre-create queries so retries never duplicate a
//     Protection Group or Kit Campaign (AB-NFR-005).
type VBRAdapter interface {
	Connect(ctx context.Context, cfg ConnectionConfig) error
	ServerInfo(ctx context.Context) (ServerInfo, error)
	Capabilities(ctx context.Context) (Capabilities, error)

	ListLinuxAgentPackages(ctx context.Context) ([]AgentPackage, error)
	DownloadAgentPackages(ctx context.Context, request PackageRequest) (io.ReadCloser, error)

	CreateDeploymentKit(ctx context.Context, request KitRequest) (TaskRef, error)
	WaitTask(ctx context.Context, task TaskRef) error
	DownloadDeploymentKit(ctx context.Context, task TaskRef) (io.ReadCloser, error)

	CreateProtectionGroup(ctx context.Context, spec ProtectionGroupSpec) (SessionRef, error)
	RescanProtectionGroup(ctx context.Context, id string) (SessionRef, error)
	GetSession(ctx context.Context, id string) (SessionState, error)
	GetDiscoveredEntities(ctx context.Context, pgID string) ([]DiscoveredEntity, error)
}

// ConnectionConfig holds non-secret VBR connection parameters. The VBR password
// and bearer token are intentionally absent: they live only in memory and are
// supplied to the adapter out-of-band (AB-FR-024). There is deliberately no
// InsecureSkipVerify field — TLS pinning is mandatory (section 17.3).
type ConnectionConfig struct {
	Server   string // host or URL of the VBR REST API
	Port     int
	Username string

	// PinnedTLSSHA256 is the confirmed VBR TLS fingerprint (colon-separated
	// uppercase hex). Connect REQUIRES a non-empty value: the operator MUST
	// confirm the fingerprint (via CaptureFingerprint) before any authenticated
	// request (AB-FR-022). Non-secret.
	PinnedTLSSHA256 string
}

// ServerInfo describes the connected VBR build (AB-FR-021). Version, host and
// time come from GET /api/v1/serverInfo + /api/v1/serverTime (1.3-rev2); the
// API revision is kept for diagnostics but is never operator-facing.
type ServerInfo struct {
	ProductVersion string     `json:"productVersion"`
	Host           string     `json:"host"`
	VBRID          string     `json:"vbrId,omitempty"`
	Patches        []string   `json:"patches,omitempty"`
	ServerTime     *time.Time `json:"serverTime,omitempty"`
	TimeZone       string     `json:"timeZone,omitempty"`
	IANAZone       string     `json:"ianaTimeZoneId,omitempty"`
	// Platform identifies the VBR server platform when the API exposes it.
	// Older 1.3-rev2 builds may omit the field; callers must treat empty as
	// unknown rather than guessing.
	Platform string `json:"platform,omitempty"`
	// APIRevision is an implementation detail used by the adapter. It is
	// deliberately excluded from the HTTP response and therefore never shown
	// to operators; the UI needs VBR identity, not the REST contract label.
	APIRevision string `json:"-"`
}

// Capabilities reports which REST operations the connected build exposes. A
// false flag MUST disable the corresponding UI path up front (AB-FR-023).
type Capabilities struct {
	AgentPackages      bool `json:"agentPackages"`
	DeploymentKit      bool `json:"deploymentKit"`
	ProtectionGroup    bool `json:"protectionGroup"`
	Rescan             bool `json:"rescan"`
	Session            bool `json:"session"`
	DiscoveredEntities bool `json:"discoveredEntities"`
}

// AgentPackage is an entry in VBR's Linux Agent package catalog (AB-FR-040). VBR
// exposes only package metadata via LinuxPackageModel — there is NO per-package
// download endpoint in any revision; the Deployment Kit is the install payload.
// Fields mirror the OpenAPI LinuxPackageModel verbatim.
type AgentPackage struct {
	Name         string `json:"packageName"`      // e.g. "veeamagent" (LinuxPackageModel.packageName)
	Distribution string `json:"distributionName"` // e.g. "rhel" (LinuxPackageModel.distributionName)
	Architecture string `json:"packageBitness"`   // EOSBitness: "x64" | "x86" | "Unknown" (LinuxPackageModel.packageBitness)
}

// PackageRequest selects the Linux packages VBR should export through a
// temporary PreInstalledAgents protection group. PackageNames must match the
// packageName values returned by ListLinuxAgentPackages. Format is "Tar" or
// "Zip"; AgentBridge requests Zip for consistent decoding across VBR builds.
type PackageRequest struct {
	PackageNames []string
	Format       string
}

// KitRequest parameterizes Deployment Kit generation (AB-FR-060). Platforms
// defaults to Windows + Linux; Unix is never implicitly enabled.
type KitRequest struct {
	IncludeWindowsPackages bool
	IncludeLinuxPackages   bool
	IncludeUnixPackages    bool
	ValidityHours          int
}

// TaskRef identifies an async VBR task (e.g. Kit generation).
type TaskRef struct{ ID string }

// SessionRef identifies an async VBR session (e.g. PG create / rescan).
type SessionRef struct{ ID string }

// SessionState is the polled state of an async session (AB-FR-186). VBR splits
// lifecycle (`state`: Working/Stopped/..., ESessionState) from outcome
// (`result`: Success/Warning/Failed/None, ESessionResult); both are carried so
// callers can decide terminality without guessing.
type SessionState struct {
	State    string           // lifecycle: Working | Stopped | ... (ESessionState)
	Result   string           // outcome: Success | Warning | Failed | None (ESessionResult)
	Message  string           // VBR's verbatim detailed message, when supplied
	Failures []SessionFailure // per-machine failures from child task-session logs
	Progress int              // 0..100
}

// SessionFailure is one failed child task in a VBR session. Host and Message
// are taken directly from VBR's task-session name and failed log records.
type SessionFailure struct {
	Host    string `json:"host"`
	Message string `json:"message"`
}

// DiscoveredEntity is a host discovered in a Protection Group (AB-FR-187).
type DiscoveredEntity struct {
	Host          string `json:"host"`
	Online        bool   `json:"online"`
	AgentStatus   string `json:"agentStatus"`
	AgentVersion  string `json:"agentVersion"`
	LastConnected string `json:"lastConnected"`
}

// IndividualComputer is one enrolled target in an Individual Computers PG. The
// certificate model is inherent to the spec type — every computer is enrolled
// with connectionType "Certificate" (the deployment-kit pairing); no long-lived
// VBR credential is ever referenced.
type IndividualComputer struct {
	HostName string // DNS name or IP of the target (identifier, never a secret)
}

// ProtectionGroupSpec describes a certificate-based Individual Computers PG to
// create (AB-FR-181..182). Serialized per the 1.3-rev2 OpenAPI
// IndividualComputersProtectionGroupSpec: {name, description, type:
// "IndividualComputers", computers: [{hostName, connectionType: "Certificate"}]}.
type ProtectionGroupSpec struct {
	Name        string               // validated against collisions (AB-FR-185)
	Description string               // REQUIRED by VBR; defaulted when empty
	Computers   []IndividualComputer // hosts enrolled via the kit certificate
}
