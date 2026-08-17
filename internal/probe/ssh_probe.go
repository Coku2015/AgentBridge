package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Coku2015/agentbridge/internal/executor/templates"
)

// CommandRunner runs a shell command and returns combined stdout/stderr. The
// concrete SSH transport satisfies this structurally at the executor call site,
// keeping this package free of an sshtransport import (SOLID-D).
type CommandRunner interface {
	Run(ctx context.Context, cmd string) ([]byte, error)
}

// SSHProbe gathers compatibility facts by running the fixed, static POSIX probe
// script over a command runner (AB-FR-081..083, AB-NFR-009). Because the script
// is a constant with no caller interpolation, there is no injection surface
// (red line 5); the runner never concatenates a raw caller string.
type SSHProbe struct {
	runner CommandRunner
}

// NewSSHProbe wraps a command runner (typically an *sshtransport.Client).
func NewSSHProbe(runner CommandRunner) *SSHProbe {
	return &SSHProbe{runner: runner}
}

// Probe runs the static fact script and decodes its versioned JSON into a
// Result. It validates the schema version so a mismatched (e.g. future) emitter
// is rejected explicitly rather than misinterpreted.
func (p *SSHProbe) Probe(ctx context.Context) (Result, error) {
	out, err := p.runner.Run(ctx, templates.ProbeScript)
	if err != nil {
		return Result{}, fmt.Errorf("probe: run facts: %w", redactShellErr(err))
	}
	return decodeResult(out)
}

// decodeResult normalizes + decodes raw script JSON into a Result, validating
// the schema version. Shared by the SSH and Local probes.
func decodeResult(out []byte) (Result, error) {
	cleaned := stripShellNoise(out)
	var w wireResult
	if err := json.Unmarshal(cleaned, &w); err != nil {
		return Result{}, fmt.Errorf("probe: decode facts: %w (raw redacted)", redactShellErr(err))
	}
	if w.SchemaVersion != SchemaVersion {
		return Result{}, fmt.Errorf("probe: schema mismatch: got %q want %q", w.SchemaVersion, SchemaVersion)
	}
	return w.toResult(), nil
}

// wireResult mirrors the POSIX probe script's JSON (scalar strings) and converts
// to the public Result (slice fields). Keeping the wire shape POSIX-friendly
// avoids fragile shell-side JSON-array construction.
type wireResult struct {
	SchemaVersion string `json:"schemaVersion"`
	Target        struct {
		HostName     string `json:"hostName"`
		Architecture string `json:"architecture"`
	} `json:"target"`
	OS struct {
		ID        string `json:"id"`
		VersionID string `json:"versionId"`
		IDLike    string `json:"idLike"`
	} `json:"os"`
	Kernel                string `json:"kernel"`
	Glibc                 string `json:"glibc"`
	PackageFormat         string `json:"packageFormat"`
	PackageManager        string `json:"packageManager"`
	RHELMacro             string `json:"rhelMacro"`
	SecureBoot            string `json:"secureBoot"`
	ExistingVeeamPackages string `json:"existingVeeamPackages"`
	AvailableTempBytes    int64  `json:"availableTempBytes"`
}

func (w wireResult) toResult() Result {
	r := Result{
		SchemaVersion:         w.SchemaVersion,
		Kernel:                w.Kernel,
		Glibc:                 w.Glibc,
		PackageFormat:         w.PackageFormat,
		PackageManager:        w.PackageManager,
		RHELMacro:             w.RHELMacro,
		SecureBoot:            w.SecureBoot,
		AvailableTempBytes:    w.AvailableTempBytes,
		ExistingVeeamPackages: splitNonEmpty(w.ExistingVeeamPackages, ","),
	}
	r.Target.HostName = w.Target.HostName
	r.Target.Architecture = w.Target.Architecture
	r.OS.ID = w.OS.ID
	r.OS.VersionID = w.OS.VersionID
	r.OS.IDLike = fieldsNonEmpty(w.OS.IDLike)
	return r
}

// splitNonEmpty splits s on sep, dropping empties.
func splitNonEmpty(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// fieldsNonEmpty splits s on whitespace, dropping empties.
func fieldsNonEmpty(s string) []string {
	return strings.Fields(s)
}

// stripShellNoise trims any stray non-JSON leader/trailer the shell may emit
// (PS1 fragments, stderr leaks) by slicing to the first '{' and last '}'.
func stripShellNoise(out []byte) []byte {
	s := string(out)
	if i := strings.IndexByte(s, '{'); i >= 0 {
		s = s[i:]
	}
	if j := strings.LastIndexByte(s, '}'); j >= 0 {
		s = s[:j+1]
	}
	return []byte(s)
}

// redactShellErr avoids leaking potential secret-bearing shell output into logs.
func redactShellErr(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%v", err)
}
