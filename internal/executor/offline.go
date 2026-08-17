package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Coku2015/agentbridge/internal/bundle"
	"github.com/Coku2015/agentbridge/internal/executor/templates"
	"github.com/Coku2015/agentbridge/internal/kitzip"
	"github.com/Coku2015/agentbridge/internal/probe"
)

// LocalRunner runs a local command by name+args (os/exec). Abstracted so tests
// inject a fake. The offline executor passes template-built strings as a single
// argv element to `sh -c`, so no caller string is ever concatenated into a
// shell command (red line 5) — safer even than the SSH path.
type LocalRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// osLocalRunner is the production runner backed by os/exec.
type osLocalRunner struct{}

func (osLocalRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// OfflineExecutor implements BootstrapExecutor for the Local Run (9.2) and
// Offline / Air-gap (9.4) paths. It runs the SAME fixed templates as the SSH
// executor, but locally via `sh -c`. Runnable by an admin with sudo: when the
// process is already root, PrivRoot templates need no prefix (FR-035). It emits
// an importable structured result (AB-FR-142) identical in schema to the bundle
// install.sh, so a local install and an air-gapped install are indistinguishable
// to the importer.
//
// The Local Run executor currently handles the kit-only path: Prepare extracts
// the Deployment Kit ZIP into the work dir (no unzip dependency anywhere), and
// Install runs the kit's own official installer with bash. The zero-credential
// manual bundle path adds the target-selected Agent package and uses the same
// fixed install script for the full Agent-plus-Kit flow.
type OfflineExecutor struct {
	runner    LocalRunner
	privilege templates.PrivilegeMode
	kitPath   string
	workDir   string
	jobID     string
	profile   string

	stagedPath  string
	lastInstall InstallResult
	lastVerify  LocalVerifyResult
}

// OfflineExecutorConfig configures a single-host local/offline install. No
// credential field exists — this path never holds a Linux password or key
// (FR-034). Privilege defaults to PrivRoot (the admin runs with sudo).
type OfflineExecutorConfig struct {
	Runner    LocalRunner
	KitPath   string // local Deployment Kit to stage and run (the install payload)
	Privilege templates.PrivilegeMode
	WorkDir   string // staging dir; default <TempDir>/agentbridge-*
	JobID     string // correlation id for the emitted result
	Profile   string // informational, e.g. "kit-payload"
}

// NewOfflineExecutor builds a local/offline executor.
func NewOfflineExecutor(cfg OfflineExecutorConfig) *OfflineExecutor {
	priv := cfg.Privilege
	if priv == "" {
		priv = templates.PrivRoot
	}
	profile := cfg.Profile
	if profile == "" {
		profile = bundle.ProfileKitOnly
	}
	return &OfflineExecutor{
		runner:    cfg.Runner,
		privilege: priv,
		kitPath:   cfg.KitPath,
		workDir:   cfg.WorkDir,
		jobID:     cfg.JobID,
		profile:   profile,
	}
}

// runnerOr returns the production runner when none was injected.
func (e *OfflineExecutor) runnerOr() LocalRunner {
	if e.runner != nil {
		return e.runner
	}
	return osLocalRunner{}
}

// Probe runs the static POSIX fact script locally and returns the serialized
// probe Result (schema 1.0). No package operation, no root strictly required.
func (e *OfflineExecutor) Probe(ctx context.Context, _ Target) (ProbeResult, error) {
	out, err := e.runnerOr().Run(ctx, "sh", "-c", templates.ProbeScript)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("offline executor: probe: %w", err)
	}
	// Validate the JSON shape before handing it upstream.
	var pr probe.Result
	if err := json.Unmarshal(out, &pr); err != nil {
		return ProbeResult{}, fmt.Errorf("offline executor: probe json: %w", err)
	}
	return ProbeResult{JSON: string(out)}, nil
}

// Prepare stages the Deployment Kit by extracting the kit ZIP into
// <workDir>/kit/ (Go stdlib — no unzip dependency anywhere). The work dir is
// the ONLY place staged bytes live; Cleanup removes it.
func (e *OfflineExecutor) Prepare(_ context.Context, _ InstallPlan) (PreparedArtifact, error) {
	if e.kitPath == "" {
		return PreparedArtifact{}, fmt.Errorf("offline executor: no kit path")
	}
	if e.workDir == "" {
		dir, err := os.MkdirTemp("", "agentbridge-offline-*")
		if err != nil {
			return PreparedArtifact{}, err
		}
		e.workDir = dir
	}
	raw, err := os.ReadFile(e.kitPath)
	if err != nil {
		return PreparedArtifact{}, fmt.Errorf("offline executor: read kit: %w", err)
	}
	files, err := kitzip.Extract(bytes.NewReader(raw))
	if err != nil {
		return PreparedArtifact{}, fmt.Errorf("offline executor: %w", err)
	}
	kitDir := filepath.Join(e.workDir, "kit")
	if err := os.MkdirAll(kitDir, 0o700); err != nil {
		return PreparedArtifact{}, err
	}
	for _, f := range files {
		mode := os.FileMode(0o644)
		if f.Name == kitzip.InstallerName {
			mode = 0o755
		}
		dst := filepath.Join(kitDir, filepath.FromSlash(f.Name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return PreparedArtifact{}, err
		}
		if err := os.WriteFile(dst, f.Data, mode); err != nil {
			return PreparedArtifact{}, fmt.Errorf("offline executor: stage %s: %w", f.Name, err)
		}
	}
	e.stagedPath = filepath.Join(kitDir, kitzip.InstallerName)
	return PreparedArtifact{Path: e.stagedPath, SHA256: shaHex(raw), RemoteDir: e.workDir}, nil
}

// Install runs the kit's official installer (`bash install-deployment-kit.sh`)
// from its staged extraction dir. Commands are template-built; the path is the
// only interpolated value and is quoted. The full Agent-plus-Kit manual flow is
// implemented by the generated bundle install script, which can inspect the
// target before installing its package-set payload.
func (e *OfflineExecutor) Install(ctx context.Context, _ InstallPlan) (InstallResult, error) {
	if e.stagedPath == "" {
		return InstallResult{}, fmt.Errorf("offline executor: Prepare must run before Install")
	}
	if _, err := e.runnerOr().Run(ctx, "sh", "-c", templates.InstallKitCmd(e.stagedPath, e.privilege)); err != nil {
		res := InstallResult{PackageInstalled: false}
		e.lastInstall = res
		return res, fmt.Errorf("offline executor: install kit: %w", err)
	}
	res := InstallResult{PackageInstalled: false, DeploymentKitReady: true}
	e.lastInstall = res
	return res, nil
}

// Verify runs the fixed verify template locally and parses the independent
// package/service facts (AB-FR-164).
func (e *OfflineExecutor) Verify(ctx context.Context, _ Target) (LocalVerifyResult, error) {
	out, err := e.runnerOr().Run(ctx, "sh", "-c", templates.VerifyCmd(e.privilege))
	if err != nil {
		return LocalVerifyResult{}, fmt.Errorf("offline executor: verify: %w", err)
	}
	v := parseVerify(string(out))
	e.lastVerify = v
	return v, nil
}

// Cleanup removes the staged work dir (bounded footprint, AB-FR-123).
func (e *OfflineExecutor) Cleanup(_ context.Context, _ Target) error {
	if e.workDir == "" {
		return nil
	}
	err := os.RemoveAll(e.workDir)
	e.workDir = ""
	e.stagedPath = ""
	return err
}

// Result assembles the importable structured result from the last Probe/Install/
// Verify (AB-FR-142). It captures local identity (hostname/arch/addresses) so
// the importer can cross-check it against the configured target (AB-FR-086).
func (e *OfflineExecutor) Result(ctx context.Context) (bundle.Result, error) {
	host, _ := e.runnerOr().Run(ctx, "hostname")
	arch, _ := e.runnerOr().Run(ctx, "uname", "-m")
	addrBytes, _ := e.runnerOr().Run(ctx, "sh", "-c", "hostname -I 2>/dev/null | tr ' ' '\\n'")
	return bundle.Result{
		SchemaVersion: bundle.ResultSchemaVersion,
		JobID:         e.jobID,
		// Overall OK = the payload step this run performed succeeded: the kit
		// path proves DeploymentKitReady, a package path proves
		// PackageInstalled (layered honesty, red line 11).
		OK:                e.lastInstall.PackageInstalled || e.lastInstall.DeploymentKitReady,
		DeploymentProfile: e.profile,
		Target: bundle.ResultTarget{
			HostName:     trimStr(host),
			Architecture: trimStr(arch),
			Addresses:    splitLines(addrBytes),
		},
		Install: bundle.InstallSummary{
			PackageInstalled:   e.lastInstall.PackageInstalled,
			DeploymentKitReady: e.lastInstall.DeploymentKitReady,
			RebootRequired:     e.lastInstall.RebootRequired,
		},
		Verify: bundle.VerifySummary{
			PackageVersion: e.lastVerify.PackageVersion,
			ServiceStatus:  e.lastVerify.ServiceStatus,
			AgentStatus:    e.lastVerify.AgentStatus,
		},
	}, nil
}

func trimStr(b []byte) string {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return string(b)
}

func splitLines(b []byte) bundle.AddressList {
	var out bundle.AddressList
	for _, line := range splitBytes(b) {
		s := trimStr(line)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func splitBytes(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' || c == ' ' || c == '\t' {
			if i > start {
				out = append(out, b[start:i])
			}
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}
