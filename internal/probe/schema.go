package probe

// SchemaVersion is the current Probe output schema version (AB-FR-084).
const SchemaVersion = "1.0"

// Result is the versioned Probe output consumed by the matcher (section 15.1).
// It carries only facts; no credentials.
type Result struct {
	SchemaVersion         string   `json:"schemaVersion"`
	Target                Target   `json:"target"`
	OS                    OSInfo   `json:"os"`
	Kernel                string   `json:"kernel"`
	Glibc                 string   `json:"glibc"`
	PackageFormat         string   `json:"packageFormat"`  // "rpm" | "deb"
	PackageManager        string   `json:"packageManager"` // "yum" | "dnf" | "apt"
	RHELMacro             string   `json:"rhelMacro"`
	SecureBoot            string   `json:"secureBoot"` // "enabled" | "disabled" | "unknown"
	ExistingVeeamPackages []string `json:"existingVeeamPackages"`
	AvailableTempBytes    int64    `json:"availableTempBytes"`
}

// Target identifies the probed host. Cross-checked against the configured
// host name / IP / SSH host key to warn on mismatches (AB-FR-086).
type Target struct {
	HostName     string   `json:"hostName"`
	Addresses    []string `json:"addresses"`
	Architecture string   `json:"architecture"` // e.g. "x86_64"
}

// OSInfo captures /etc/os-release identity used by the matcher (AB-FR-083).
type OSInfo struct {
	ID        string   `json:"id"`        // e.g. "kylin", "rocky", "centos"
	VersionID string   `json:"versionId"` // e.g. "V10", "8.6"
	IDLike    []string `json:"idLike"`    // e.g. ["rhel","centos"]
}
