package matcher

// Recommendation is the explanatory package recommendation shown to the user
// (section 15.2, AB-FR-101). It is interpretive only; the user makes the final
// decision.
type Recommendation struct {
	RecommendedPackageID         string   `json:"recommendedPackageId"`
	PackageMode                  string   `json:"packageMode,omitempty"` // "standard" or "nosnap"
	CompatibilityFamily          string   `json:"compatibilityFamily,omitempty"`
	CompatibilityBasis           string   `json:"compatibilityBasis,omitempty"`
	Confidence                   string   `json:"confidence"` // "high" | "medium" | "low"
	Evidence                     []string `json:"evidence"`
	Warnings                     []string `json:"warnings"`
	RequiresExplicitConfirmation bool     `json:"requiresExplicitConfirmation"`
}

// RuleLevel classifies the trust level of a match (section 15.3). Only
// VendorSupported comes from the official Veeam matrix. CompatibilityInferred
// is AgentBridge's upstream-family inference and is never a vendor-support
// claim.
type RuleLevel string

const (
	VendorSupported       RuleLevel = "VendorSupported"
	LabValidated          RuleLevel = "LabValidated"
	CompatibilityInferred RuleLevel = "CompatibilityInferred"
	UserSelected          RuleLevel = "UserSelected"
	Blocked               RuleLevel = "Blocked"
)

// Matcher applies embedded, versioned rules to probe facts and returns an
// explanatory recommendation. Implementations must be deterministic and
// unit-testable (AB-FR-105, AB-NFR-008).
type Matcher interface {
	Match(input Input) (Recommendation, RuleLevel, error)
}

// Input is the matcher-facing projection of a probe.Result, kept local to
// avoid a probe->matcher dependency. Populated from probe.Result by the
// orchestrator.
type Input struct {
	PackageFormat string   // "rpm" | "deb"
	Architecture  string   // "x86_64" | ...
	ID            string   // os-release ID
	IDLike        []string // os-release ID_LIKE
	VersionID     string
	RHELMacro     string
	Glibc         string
	Kernel        string
	SecureBoot    string
	ExistingAgent bool
}
