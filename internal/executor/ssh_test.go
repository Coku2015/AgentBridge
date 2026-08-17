package executor

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/Coku2015/agentbridge/internal/executor/templates"
	"github.com/Coku2015/agentbridge/internal/kitzip"
)

// fakeSession records commands/uploads and serves canned outputs.
type fakeSession struct {
	runs      []string
	probeJSON string
	verifyOut string
	uploadSha string
	uploads   map[string][]byte

	installOut []byte // output of `bash '<installer>'`
	installErr error  // non-nil simulates the installer exiting non-zero
	rpmOut     []byte // output of `rpm -q veeamdeployment`
	rpmErr     error
}

func (s *fakeSession) RunWithSecret(ctx context.Context, cmd string, _ []byte, _ bool) ([]byte, error) {
	return s.Run(ctx, cmd)
}

func (s *fakeSession) Run(_ context.Context, cmd string) ([]byte, error) {
	s.runs = append(s.runs, cmd)
	switch {
	case strings.Contains(cmd, "printf") && strings.Contains(cmd, "schemaVersion"):
		return []byte(s.probeJSON), nil
	case strings.Contains(cmd, "bash '"):
		return s.installOut, s.installErr
	case strings.Contains(cmd, "rpm -q veeamdeployment") && !strings.Contains(cmd, "pkg:"):
		return s.rpmOut, s.rpmErr
	case strings.Contains(cmd, "rm -rf"):
		return nil, nil
	case strings.Contains(cmd, "pkg:"):
		return []byte(s.verifyOut), nil
	default:
		return nil, nil
	}
}

func (s *fakeSession) Upload(_ context.Context, r io.Reader, remotePath string) (string, error) {
	b, _ := io.ReadAll(r)
	if s.uploads == nil {
		s.uploads = map[string][]byte{}
	}
	s.uploads[remotePath] = b
	return s.uploadSha, nil
}

func (s *fakeSession) Close() error { return nil }

type fakeConnector struct{ sess *fakeSession }

func (c *fakeConnector) Connect(_ context.Context) (RemoteSession, error) { return c.sess, nil }

// makeKitZip writes a minimal but VALID Deployment Kit ZIP (official installer
// + a package + a cert) — the kit is an archive, never a bare script.
func makeKitZip(t *testing.T, entries map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"install-deployment-kit.sh", "veeamdeployment.rpm", "client-cert.pem"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(entries[name])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(t.TempDir(), "kit-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func TestSSHProbeReturnsSerializedResult(t *testing.T) {
	sess := &fakeSession{probeJSON: `{"schemaVersion":"1.0","target":{"hostName":"n","architecture":"x86_64"},"os":{"id":"rocky","versionId":"8.6","idLike":"rhel"},"packageFormat":"rpm","glibc":"2.28"}`}
	e := NewSSHExecutor(SSHExecutorConfig{Connector: &fakeConnector{sess: sess}})
	res, err := e.Probe(context.Background(), Target{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.JSON, `"id":"rocky"`) {
		t.Fatalf("probe JSON missing os id: %s", res.JSON)
	}
}

func TestSSHPipelinePrepareInstallVerifyCleanup(t *testing.T) {
	sess := &fakeSession{
		verifyOut: "pkg:veeam\nver:none\nkitver:13.1.1.18-1\ndeployer:active\nagent:unknown",
	}
	e := NewSSHExecutor(SSHExecutorConfig{
		Connector: &fakeConnector{sess: sess},
		Privilege: templates.PrivRoot,
		KitPath: makeKitZip(t, map[string]string{
			"install-deployment-kit.sh": "#!/bin/bash\nexit 0\n",
			"veeamdeployment.rpm":       "RPM-BYTES",
			"client-cert.pem":           "CERT",
		}),
	})

	prep, err := e.Prepare(context.Background(), InstallPlan{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if !strings.HasPrefix(prep.Path, "/tmp/agentbridge-") {
		t.Fatalf("staged path not in unpredictable dir: %s", prep.Path)
	}
	if !strings.HasSuffix(prep.Path, "/kit/"+kitzip.InstallerName) {
		t.Fatalf("staged path is not the official installer: %s", prep.Path)
	}
	// Every kit payload file must be uploaded under <dir>/kit/, contents intact.
	for name, want := range map[string]string{
		"install-deployment-kit.sh": "#!/bin/bash\nexit 0\n",
		"veeamdeployment.rpm":       "RPM-BYTES",
		"client-cert.pem":           "CERT",
	} {
		got, ok := sess.uploads[path.Join(prep.RemoteDir, "kit", name)]
		if !ok {
			t.Fatalf("kit file %s not uploaded; uploads=%v", name, sess.uploads)
		}
		if string(got) != want {
			t.Fatalf("kit file %s content = %q, want %q", name, got, want)
		}
	}
	if len(sess.uploads) != 3 {
		t.Fatalf("unexpected extra uploads: %v", sess.uploads)
	}

	inst, err := e.Install(context.Background(), InstallPlan{})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	// Layered honesty: the kit proves the deployment service + certificate,
	// NOT the Agent package (VBR pushes it later).
	if inst.PackageInstalled || !inst.DeploymentKitReady {
		t.Fatalf("install layers wrong: %+v", inst)
	}

	v, err := e.Verify(context.Background(), Target{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.ServiceStatus != "active" || v.DeployerStatus != "active" || !strings.HasPrefix(v.DeploymentKitVersion, "13.1.1.18") || v.PackageVersion != "" {
		t.Fatalf("verify parse wrong: %+v", v)
	}

	if err := e.Cleanup(context.Background(), Target{}); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	// Every command run must be template-built and quoted (red line 5).
	joined := strings.Join(sess.runs, " | ")
	if strings.Contains(joined, "; rm -rf") {
		t.Fatalf("injection vector present in commands: %s", joined)
	}
	// Install must run the OFFICIAL installer with bash on the quoted staged
	// path — never `sh <kit>` (the kit is a ZIP; that is the exit-126 bug) and
	// never a direct `rpm -Uvh`.
	if !containsRun(sess.runs, "bash '"+prep.Path+"'") {
		t.Fatalf("install did not run the official installer; runs=%v", sess.runs)
	}
	if containsRun(sess.runs, "--silent") {
		t.Fatalf("install must not carry legacy kit flags; runs=%v", sess.runs)
	}
	// No command may execute a PATH via `sh '<path>'` (the exit-126 bug was
	// `sh <kit-zip>`); `sh -c '<fixed script>'` (Verify) is fine.
	for _, r := range sess.runs {
		if strings.HasPrefix(r, "sh '") {
			t.Fatalf("command executes a path via sh (kit must run under bash): %q", r)
		}
	}
	if containsRun(sess.runs, "rpm -Uvh") {
		t.Fatalf("install must not use rpm directly (kit is the payload); runs=%v", sess.runs)
	}
	// Cleanup must remove the whole staging dir.
	if !containsRun(sess.runs, "rm -rf '"+prep.RemoteDir+"'") {
		t.Fatalf("cleanup did not remove staging dir; runs=%v", sess.runs)
	}
}

// A kit that is not a ZIP must be rejected at Prepare — before anything is
// uploaded — with an actionable error (the exit-126 root cause).
func TestSSHPrepareRejectsNonZipKit(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "kit-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("#!/bin/sh\nnot a zip"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	sess := &fakeSession{}
	e := NewSSHExecutor(SSHExecutorConfig{Connector: &fakeConnector{sess: sess}, KitPath: f.Name()})
	_, err = e.Prepare(context.Background(), InstallPlan{})
	if err == nil || !strings.Contains(err.Error(), "not a Deployment Kit archive") {
		t.Fatalf("err = %v, want 'not a Deployment Kit archive'", err)
	}
	if len(sess.uploads) != 0 {
		t.Fatalf("nothing may be uploaded for an invalid kit: %v", sess.uploads)
	}
}

func TestSSHPrepareRejectsAgentOnlyProfile(t *testing.T) {
	e := NewSSHExecutor(SSHExecutorConfig{
		Connector: &fakeConnector{sess: &fakeSession{}},
		KitPath: makeKitZip(t, map[string]string{
			"install-deployment-kit.sh": "#!/bin/bash\nexit 0\n",
			"veeamdeployment.rpm":       "RPM-BYTES",
			"client-cert.pem":           "CERT",
		}),
	})
	if _, err := e.Prepare(context.Background(), InstallPlan{DeploymentProfile: "agent-only"}); err == nil || !strings.Contains(err.Error(), "Deployment Kit is required") {
		t.Fatalf("legacy Agent-only profile was not rejected: %v", err)
	}
}

// Install before Prepare must fail (no staged path) — guards ordering.
func TestSSHInstallRequiresPrepare(t *testing.T) {
	e := NewSSHExecutor(SSHExecutorConfig{Connector: &fakeConnector{sess: &fakeSession{}}})
	if _, err := e.Install(context.Background(), InstallPlan{}); err == nil {
		t.Fatal("expected error when Install runs before Prepare")
	}
}

// yum/dnf exiting 1 with "Nothing to do" means the staged RPMs match the
// installed versions — the idempotent same-version case (red line 6). When
// the RPM database confirms veeamdeployment is present, Install must report
// the kit ready instead of failing.
func TestSSHInstallToleratesYumNothingToDo(t *testing.T) {
	sess := &fakeSession{
		installOut: []byte("Examining /tmp/x/kit/veeamdeployment-13.1.1.18-1.x86_64.rpm: does not update installed package.\nError: Nothing to do\n"),
		installErr: errors.New("sshtransport: run: Process exited with status 1"),
		rpmOut:     []byte("veeamdeployment-13.1.1.18-1.x86_64\n"),
	}
	e := NewSSHExecutor(SSHExecutorConfig{
		Connector: &fakeConnector{sess: sess},
		KitPath: makeKitZip(t, map[string]string{
			"install-deployment-kit.sh": "#!/bin/bash\nexit 1\n",
			"veeamdeployment.rpm":       "RPM-BYTES",
			"client-cert.pem":           "CERT",
		}),
	})
	if _, err := e.Prepare(context.Background(), InstallPlan{}); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	inst, err := e.Install(context.Background(), InstallPlan{})
	if err != nil {
		t.Fatalf("Install must tolerate already-installed kit: %v", err)
	}
	if !inst.DeploymentKitReady || inst.PackageInstalled {
		t.Fatalf("install layers wrong: %+v", inst)
	}
	// The tolerance decision must rest on the RPM database, not the yum text alone.
	if !containsRun(sess.runs, "rpm -q veeamdeployment") {
		t.Fatalf("install did not confirm via rpm -q; runs=%v", sess.runs)
	}
}

// "Nothing to do" WITHOUT the package in the RPM database is a real failure:
// the tolerance path must not mask it.
func TestSSHInstallNothingToDoWithoutPackageFails(t *testing.T) {
	sess := &fakeSession{
		installOut: []byte("Error: Nothing to do\n"),
		installErr: errors.New("sshtransport: run: Process exited with status 1"),
		rpmErr:     errors.New("sshtransport: run: Process exited with status 1"),
	}
	e := NewSSHExecutor(SSHExecutorConfig{
		Connector: &fakeConnector{sess: sess},
		KitPath: makeKitZip(t, map[string]string{
			"install-deployment-kit.sh": "#!/bin/bash\nexit 1\n",
			"veeamdeployment.rpm":       "RPM-BYTES",
			"client-cert.pem":           "CERT",
		}),
	})
	if _, err := e.Prepare(context.Background(), InstallPlan{}); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	_, err := e.Install(context.Background(), InstallPlan{})
	if err == nil || !strings.Contains(err.Error(), "install kit") {
		t.Fatalf("err = %v, want a real install failure", err)
	}
}

func TestRandomRemoteDirUnpredictable(t *testing.T) {
	a, _ := randomRemoteDir()
	b, _ := randomRemoteDir()
	if a == b {
		t.Fatal("remote dirs must be unpredictable per call")
	}
	if !strings.HasPrefix(path.Dir(a), "/tmp") {
		t.Fatalf("remote dir not under /tmp: %s", a)
	}
}

func containsRun(runs []string, want string) bool {
	for _, r := range runs {
		if strings.Contains(r, want) {
			return true
		}
	}
	return false
}
