package executor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Coku2015/agentbridge/internal/executor/templates"
	"github.com/Coku2015/agentbridge/internal/kitzip"
	"github.com/Coku2015/agentbridge/internal/probe"
)

// RemoteSession abstracts the connected remote shell + upload channel. The SSH
// transport satisfies it structurally; tests inject a fake. The executor never
// imports a concrete transport (SOLID-D, frozen contract).
type RemoteSession interface {
	// Run executes a command and returns combined stdout/stderr.
	Run(ctx context.Context, cmd string) ([]byte, error)
	// RunWithSecret executes a fixed command and provides a password through
	// stdin. requestPTY enables a terminal with echo disabled for sudo/su.
	RunWithSecret(ctx context.Context, cmd string, secret []byte, requestPTY bool) ([]byte, error)
	// Upload streams r to remotePath and returns the content SHA-256.
	Upload(ctx context.Context, r io.Reader, remotePath string) (sha string, err error)
	// Close releases the session.
	Close() error
}

// Connector produces a connected RemoteSession for a target. Implementations
// hold memory-only credentials and a pinned host key (red line 4).
type Connector interface {
	Connect(ctx context.Context) (RemoteSession, error)
}

// SSHExecutor implements BootstrapExecutor over a remote shell (section 9.1).
// It depends only on Connector + templates, never on a concrete SSH transport.
// Secrets live only in the Connector (memory). An instance is single-use per
// host: Prepare stages a remote dir that Install/Verify/Cleanup reuse.
//
// Prepare extracts the Deployment Kit ZIP LOCALLY (Go stdlib — the target needs
// no unzip binary) and uploads its payload files. When PackagePath is present,
// the target-matched Agent RPM/DEB set is uploaded too and installed before the
// kit. Kit-only installs retain the DeploymentKitReady-only result; the
// Agent-plus-Kit path reports both layers independently (red line 11).
type SSHExecutor struct {
	connect     Connector
	privilege   templates.PrivilegeMode
	kitPath     string // local Deployment Kit ZIP extracted + uploaded by Prepare
	packagePath string // target-matched Agent RPM/DEB or package-set archive

	remoteDir         string // unpredictable staging dir, created by Prepare
	scriptPath        string // staged install-deployment-kit.sh inside <remoteDir>/kit
	packageRemotePath string
	sudoPassword      []byte
	rootPassword      []byte
}

// SSHExecutorConfig configures a single-host SSH install lifecycle.
type SSHExecutorConfig struct {
	Connector   Connector
	Privilege   templates.PrivilegeMode
	KitPath     string // local Deployment Kit ZIP to extract, upload and run (the payload)
	PackagePath string // target-matched Agent RPM/DEB or package-set archive
	// SudoPassword is the connected account's sudo password; RootPassword is
	// used only by the explicitly selected su/sudoers paths. Both are copied
	// into this single-use executor and must be cleared with ClearSecrets.
	SudoPassword []byte
	RootPassword []byte
}

// NewSSHExecutor builds an executor bound to memory-only credentials via the
// connector.
func NewSSHExecutor(cfg SSHExecutorConfig) *SSHExecutor {
	return &SSHExecutor{
		connect:      cfg.Connector,
		privilege:    cfg.Privilege,
		kitPath:      cfg.KitPath,
		packagePath:  cfg.PackagePath,
		sudoPassword: append([]byte(nil), cfg.SudoPassword...),
		rootPassword: append([]byte(nil), cfg.RootPassword...),
	}
}

// ClearSecrets wipes the executor's transient elevation passwords. HTTP
// handlers defer this immediately after constructing the executor.
func (e *SSHExecutor) ClearSecrets() {
	wipeBytes(e.sudoPassword)
	wipeBytes(e.rootPassword)
	e.sudoPassword = nil
	e.rootPassword = nil
}

// Probe runs the static POSIX fact script and returns the serialized probe
// Result (schema 1.0). It performs no package operation.
func (e *SSHExecutor) Probe(ctx context.Context, _ Target) (ProbeResult, error) {
	sess, err := e.connect.Connect(ctx)
	if err != nil {
		return ProbeResult{}, err
	}
	defer sess.Close()
	res, err := probe.NewSSHProbe(&sessionRunner{sess: sess}).Probe(ctx)
	if err != nil {
		return ProbeResult{}, err
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return ProbeResult{}, err
	}
	return ProbeResult{JSON: string(raw)}, nil
}

// Prepare extracts the Deployment Kit ZIP locally (Go stdlib — the target
// needs no unzip binary), then uploads every payload file into a per-host
// unpredictable remote dir (AB-FR-123). Each upload is atomic on the remote
// side (templates.UploadOpenCmd writes .part then renames). What lands on the
// target is exactly what VBR shipped: the official installer plus its sibling
// packages and certificates.
func (e *SSHExecutor) Prepare(ctx context.Context, plan InstallPlan) (PreparedArtifact, error) {
	profile := plan.DeploymentProfile
	if profile == "" {
		profile = "kit-only"
	}
	if profile != "kit-only" && profile != "agent-plus-kit" {
		return PreparedArtifact{}, fmt.Errorf("ssh executor: unsupported deployment profile %q; Deployment Kit is required", profile)
	}
	if e.kitPath == "" {
		return PreparedArtifact{}, fmt.Errorf("ssh executor: no local Deployment Kit path to prepare")
	}
	wantsAgent := profile == "agent-plus-kit"
	if wantsAgent && e.packagePath == "" {
		return PreparedArtifact{}, fmt.Errorf("ssh executor: Agent plus Deployment Kit requires a local Agent package")
	}
	if !wantsAgent && e.packagePath != "" {
		return PreparedArtifact{}, fmt.Errorf("ssh executor: kit-only profile cannot include a standalone Agent package")
	}
	var raw []byte
	var files []kitzip.File
	var err error
	if e.kitPath != "" {
		raw, err = os.ReadFile(e.kitPath)
		if err != nil {
			return PreparedArtifact{}, fmt.Errorf("ssh executor: open kit: %w", err)
		}
		files, err = kitzip.Extract(bytes.NewReader(raw))
		if err != nil {
			return PreparedArtifact{}, fmt.Errorf("ssh executor: %w", err)
		}
	}

	remoteDir, err := randomRemoteDir()
	if err != nil {
		return PreparedArtifact{}, err
	}
	e.remoteDir = remoteDir
	if e.kitPath != "" {
		e.scriptPath = path.Join(remoteDir, "kit", kitzip.InstallerName)
	}

	sess, err := e.connect.Connect(ctx)
	if err != nil {
		return PreparedArtifact{}, err
	}
	defer sess.Close()
	for _, f := range files {
		remote := path.Join(remoteDir, "kit", f.Name)
		if _, err := sess.Upload(ctx, bytes.NewReader(f.Data), remote); err != nil {
			return PreparedArtifact{}, fmt.Errorf("ssh executor: upload %s: %w", f.Name, err)
		}
	}
	if wantsAgent {
		pkg, err := os.ReadFile(e.packagePath)
		if err != nil {
			return PreparedArtifact{}, fmt.Errorf("ssh executor: open selected Agent package: %w", err)
		}
		name := "agent-package.rpm"
		lower := strings.ToLower(e.packagePath)
		if strings.HasSuffix(lower, ".deb") {
			name = "agent-package.deb"
		} else if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
			name = "agent-package.tar.gz"
		} else if ext := strings.ToLower(filepath.Ext(e.packagePath)); ext == ".rpm" || ext == ".deb" {
			name = "agent-package" + ext
		}
		e.packageRemotePath = path.Join(remoteDir, name)
		if _, err := sess.Upload(ctx, bytes.NewReader(pkg), e.packageRemotePath); err != nil {
			return PreparedArtifact{}, fmt.Errorf("ssh executor: upload selected Agent package: %w", err)
		}
	}
	// SHA256 identifies the Deployment Kit archive (traceability). Every
	// supported profile contains this archive.
	return PreparedArtifact{Path: e.scriptPath, SHA256: shaHex(raw), RemoteDir: remoteDir}, nil
}

// Install optionally installs the already target-matched Agent artifact, then
// runs the kit's official installer (`bash install-deployment-kit.sh`) from its
// staged extraction dir. Commands are template-built and quoted (red line 5);
// no raw caller string reaches the shell.
func (e *SSHExecutor) Install(ctx context.Context, _ InstallPlan) (InstallResult, error) {
	if e.scriptPath == "" && e.packageRemotePath == "" {
		return InstallResult{}, fmt.Errorf("ssh executor: Prepare must run before Install")
	}
	sess, err := e.connect.Connect(ctx)
	if err != nil {
		return InstallResult{}, err
	}
	defer sess.Close()

	if e.packageRemotePath != "" {
		if _, err := e.runPrivileged(ctx, sess, templates.InstallAgentCmd(e.packageRemotePath, e.privilege)); err != nil {
			return InstallResult{PackageInstalled: false}, fmt.Errorf("ssh executor: install Agent package: %w", err)
		}
	}
	if e.scriptPath == "" {
		return InstallResult{PackageInstalled: true}, nil
	}
	out, err := e.runPrivileged(ctx, sess, templates.InstallKitCmd(e.scriptPath, e.privilege))
	if err != nil {
		// yum/dnf exit 1 with "Nothing to do" when the staged RPMs match the
		// versions already installed. That is the idempotent same-version case
		// (red line 6), not a failure: confirm against the RPM database before
		// believing either side.
		if yumNothingToDo(string(out)) {
			if qout, qerr := sess.Run(ctx, templates.KitInstalledCmd()); qerr == nil && rpmReportsInstalled(string(qout)) {
				return InstallResult{PackageInstalled: e.packageRemotePath != "", DeploymentKitReady: true}, nil
			}
		}
		return InstallResult{PackageInstalled: false}, fmt.Errorf("ssh executor: install kit: %w", err)
	}
	return InstallResult{PackageInstalled: e.packageRemotePath != "", DeploymentKitReady: true}, nil
}

// yumNothingToDo reports whether installer output is the package manager
// refusing to reinstall the already-installed version rather than a real
// install error. yum and dnf phrase it the same way.
func yumNothingToDo(out string) bool {
	return strings.Contains(out, "Nothing to do") ||
		strings.Contains(out, "does not update installed package")
}

// rpmReportsInstalled: `rpm -q veeamdeployment` prints the package nevra on
// success and exits non-zero (empty output) when absent, so reaching here
// with output means the deployment service package is present.
func rpmReportsInstalled(out string) bool {
	return strings.TrimSpace(out) != ""
}

// Verify runs the fixed verify command and parses package/service facts
// (AB-FR-164). It never trusts a single green flag: each fact is surfaced
// independently (Principle IV).
func (e *SSHExecutor) Verify(ctx context.Context, _ Target) (LocalVerifyResult, error) {
	sess, err := e.connect.Connect(ctx)
	if err != nil {
		return LocalVerifyResult{}, err
	}
	defer sess.Close()
	out, err := e.runPrivileged(ctx, sess, templates.VerifyCmd(e.privilege))
	if err != nil {
		return LocalVerifyResult{}, fmt.Errorf("ssh executor: verify: %w", err)
	}
	return parseVerify(string(out)), nil
}

func (e *SSHExecutor) runPrivileged(ctx context.Context, sess RemoteSession, cmd string) ([]byte, error) {
	switch e.privilege {
	case templates.PrivSudoPassword:
		return sess.RunWithSecret(ctx, cmd, e.sudoPassword, true)
	case templates.PrivSu:
		return sess.RunWithSecret(ctx, cmd, e.rootPassword, true)
	default:
		return sess.Run(ctx, cmd)
	}
}

func wipeBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

// Cleanup removes the whole staged remote dir (AB-FR-123: bounded footprint).
func (e *SSHExecutor) Cleanup(ctx context.Context, _ Target) error {
	if e.remoteDir == "" {
		return nil
	}
	sess, err := e.connect.Connect(ctx)
	if err != nil {
		return err
	}
	defer sess.Close()
	_, err = sess.Run(ctx, templates.CleanupCmd(e.remoteDir))
	e.packageRemotePath = ""
	return err
}

// sessionRunner adapts RemoteSession to probe.CommandRunner.
type sessionRunner struct{ sess RemoteSession }

func (s *sessionRunner) Run(ctx context.Context, cmd string) ([]byte, error) {
	return s.sess.Run(ctx, cmd)
}

// parseVerify decodes the `key:value\n` output of templates.VerifyCmd into the
// independent verification fields.
func parseVerify(out string) LocalVerifyResult {
	r := LocalVerifyResult{}
	var ver string
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "pkg":
			// rpm -q nevra; used only to confirm presence when ver is empty.
			if r.PackageVersion == "" {
				r.PackageVersion = strings.TrimSpace(v)
			}
		case "svc":
			r.ServiceStatus = strings.TrimSpace(v)
		case "ver":
			ver = strings.TrimSpace(v)
		case "kitver":
			kitVersion := strings.TrimSpace(v)
			if kitVersion != "" && kitVersion != "none" {
				r.DeploymentKitVersion = kitVersion
			}
		case "deployer":
			r.DeployerStatus = strings.TrimSpace(v)
		case "agent":
			r.AgentStatus = strings.TrimSpace(v)
		}
	}
	// The clean version-release wins over the long nevra.
	if ver != "" && ver != "none" {
		r.PackageVersion = ver
	} else if ver == "none" {
		r.PackageVersion = ""
	}
	// Keep ServiceStatus as the legacy overall service field while exposing
	// deployer and Agent states independently for honest install verification.
	if r.DeployerStatus != "" {
		r.ServiceStatus = r.DeployerStatus
	} else if r.ServiceStatus != "" {
		r.DeployerStatus = r.ServiceStatus
	}
	return r
}

// randomRemoteDir returns an unpredictable per-host staging dir under /tmp
// (AB-FR-123). Predictable paths are an injection/overwrite vector.
func randomRemoteDir() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return path.Join("/tmp", "agentbridge-"+hex.EncodeToString(b)), nil
}

// shaHex returns the hex SHA-256 of b (kit archive identity).
func shaHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
