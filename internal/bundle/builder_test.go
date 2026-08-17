package bundle

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// secretish reports whether a struct field name looks like a secret carrier.
func secretish(name string) bool {
	n := strings.ToLower(name)
	for _, bad := range []string{"password", "passphrase", "privatekey", "token", "secret", "credential"} {
		if strings.Contains(n, bad) {
			return true
		}
	}
	return false
}

// TestNoSecretFields asserts the zero-credential invariant at the type level
// (FR-034, red line 1): neither the request nor the manifest may carry a field
// whose name denotes a secret. This is the structural guarantee that bundle
// generation never holds a Linux password or private key.
func TestNoSecretFields(t *testing.T) {
	for _, ty := range []reflect.Type{reflect.TypeOf(GenerateRequest{}), reflect.TypeOf(Manifest{})} {
		for i := 0; i < ty.NumField(); i++ {
			if secretish(ty.Field(i).Name) {
				t.Fatalf("%s.%s is a secret-shaped field (red line 1)", ty.Name(), ty.Field(i).Name)
			}
		}
	}
}

// TestGenerateProducesZeroCredentialBundle builds a bundle from a fake package
// and asserts: the archive exists, contains the expected members, install.sh is
// executable, config.sh sources cleanly under sh (ShellQuote round-trip), and
// SHA256SUMS verifies. No credential is supplied anywhere.
func TestGenerateProducesZeroCredentialBundle(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "veeam-1.0.x86_64.rpm")
	if err := os.WriteFile(pkg, []byte("FAKE-RPM-BYTES"), 0o600); err != nil {
		t.Fatal(err)
	}
	kit := makeKit(t, root)
	b, err := NewBuilder(filepath.Join(root, "out"))
	if err != nil {
		t.Fatal(err)
	}
	bun, err := b.Generate(GenerateRequest{
		PackagePath:       pkg,
		PackageID:         "rhel8-x86_64",
		KitPath:           kit,
		DeploymentProfile: ProfileAgentPlusKit,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if bun.JobID == "" || bun.Path == "" || bun.SHA256 == "" {
		t.Fatalf("incomplete bundle: %+v", bun)
	}
	if bun.Manifest.PackageFile != "veeam-1.0.x86_64.rpm" {
		t.Fatalf("package file = %s", bun.Manifest.PackageFile)
	}

	modes, contents := extractTar(t, bun.Path)
	for _, name := range []string{"install.sh", "config.sh", "manifest.json", "SHA256SUMS", "veeam-1.0.x86_64.rpm", "kit/install-deployment-kit.sh"} {
		if _, ok := contents[name]; !ok {
			t.Fatalf("tar missing %s; have %v", name, keys(contents))
		}
	}
	// install.sh must be executable (admin runs sudo ./install.sh).
	if modes["install.sh"]&0o111 == 0 {
		t.Fatalf("install.sh not executable: mode %o", modes["install.sh"])
	}

	// config.sh must source cleanly and expose the quoted values (ShellQuote
	// round-trip) — the red-line-5 proof for the generated config.
	cfgPath := filepath.Join(root, "cfgtest.sh")
	if err := os.WriteFile(cfgPath, contents["config.sh"], 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "-c", ". "+cfgPath+"; printf '%s' \"$PACKAGE_FILE\"").Output()
	if err != nil || string(out) != "veeam-1.0.x86_64.rpm" {
		t.Fatalf("config.sh did not source cleanly: out=%q err=%v", string(out), err)
	}

	// install.sh must reference no secret config key (AB-FR-141).
	inst := string(contents["install.sh"])
	for _, bad := range []string{"PASSWORD=", "PRIVATE_KEY=", "TOKEN=", "sshpass"} {
		if strings.Contains(inst, bad) {
			t.Fatalf("install.sh references secret key %q (AB-FR-141)", bad)
		}
	}

	// SHA256SUMS must verify against the shipped artifacts (AB-FR-144).
	if _, err := exec.LookPath("sha256sum"); err == nil {
		ext := t.TempDir()
		writeMembers(t, ext, contents)
		if out, err := exec.Command("sh", "-c", "cd "+ext+" && sha256sum -c SHA256SUMS").CombinedOutput(); err != nil {
			t.Fatalf("sha256sum -c failed: %v\n%s", err, out)
		}
	}
}

// TestGeneratePackageSetBundle keeps a VBR multi-payload export intact. The
// generated target script must extract and select only the role-complete
// target-compatible payloads, rather than treating the package-set archive as
// one RPM/DEB file or installing every alternative.
func TestGeneratePackageSetBundle(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "agent-set.tar.gz")
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	for _, item := range []struct {
		name string
		data string
	}{
		{name: "veeam-agent.rpm", data: "AGENT-RPM"},
		{name: "veeam-agent-dependency.rpm", data: "DEPENDENCY-RPM"},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: item.name, Mode: 0o644, Size: int64(len(item.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(item.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pkg, raw.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	b, err := NewBuilder(filepath.Join(root, "out"))
	if err != nil {
		t.Fatal(err)
	}
	bun, err := b.Generate(GenerateRequest{PackagePath: pkg, KitPath: makeKit(t, root), DeploymentProfile: ProfileAgentPlusKit})
	if err != nil {
		t.Fatalf("generate package set: %v", err)
	}
	if bun.Manifest.PackageFile != "agent-set.tar.gz" {
		t.Fatalf("package file = %s", bun.Manifest.PackageFile)
	}
	_, contents := extractTar(t, bun.Path)
	if _, ok := contents["agent-set.tar.gz"]; !ok {
		t.Fatalf("package set missing from bundle; have %v", keys(contents))
	}
	install := string(contents["install.sh"])
	for _, want := range []string{
		"*.tar.gz|*.tgz",
		`rpm -qp --qf '%{NAME}\t%{ARCH}\t%{RELEASE}' "$f"`,
		`veeam|veeam-*|veeam_*) PKG_ROLE=agent`,
		"no compatible RPM payloads",
		`rpm -Uvh "$selected_file"`,
	} {
		if !strings.Contains(install, want) {
			t.Fatalf("install.sh missing package-set handling %q", want)
		}
	}
}

func TestGeneratedBundleUsesStableNonEpochTimestamps(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "veeam.rpm")
	if err := os.WriteFile(pkg, []byte("RPM"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := NewBuilder(filepath.Join(root, "out"))
	if err != nil {
		t.Fatal(err)
	}
	bun, err := b.Generate(GenerateRequest{PackagePath: pkg, KitPath: makeKit(t, root), DeploymentProfile: ProfileAgentPlusKit})
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(bun.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !hdr.ModTime.Equal(archiveModTime) || hdr.ModTime.Before(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)) {
			t.Fatalf("member %s modtime = %s", hdr.Name, hdr.ModTime)
		}
	}
}

// TestGenerateUniversalMixedCatalogBundle pins the manual-install contract:
// one reverse-pull command may carry both RPM and DEB catalog families. The
// target-side script must choose its native package manager instead of
// rejecting the bundle as a mixed-format payload.
func TestGenerateUniversalMixedCatalogBundle(t *testing.T) {
	root := t.TempDir()
	rpm := filepath.Join(root, "red-hat-agent.rpm")
	deb := filepath.Join(root, "debian-agent.deb")
	if err := os.WriteFile(rpm, []byte("RPM"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deb, []byte("DEB"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := NewBuilder(filepath.Join(root, "out"))
	if err != nil {
		t.Fatal(err)
	}
	bun, err := b.Generate(GenerateRequest{
		PackagePaths:      []string{rpm, deb},
		KitPath:           makeKit(t, root),
		DeploymentProfile: ProfileAgentPlusKit,
	})
	if err != nil {
		t.Fatalf("generate universal package set: %v", err)
	}
	if bun.Manifest.PackageFile != "agent-packages.tar.gz" {
		t.Fatalf("package file = %s", bun.Manifest.PackageFile)
	}
	_, contents := extractTar(t, bun.Path)
	install := string(contents["install.sh"])
	for _, want := range []string{
		`[ -f /etc/debian_version ] && command -v dpkg`,
		`elif command -v rpm`,
		`if [ -z "$PKG_ERR" ] && [ -n "$RPM_FILES" ]`,
		`elif [ -z "$PKG_ERR" ] && [ -n "$DEB_FILES" ]`,
	} {
		if !strings.Contains(install, want) {
			t.Fatalf("install.sh missing mixed-catalog selection %q", want)
		}
	}
	if strings.Contains(install, "package set contains mixed RPM/DEB payloads") {
		t.Fatal("install.sh still rejects a universal mixed catalog")
	}
}

func TestInstallScriptIsPOSIXSyntaxValid(t *testing.T) {
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(installScript)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install.sh syntax invalid: %v\n%s", err, out)
	}
}

// TestGenerateWithKit ships package + kit under agent-plus-kit and asserts both
// payload flags are set in config.sh and the kit is EXTRACTED into kit/ (the
// target needs no unzip).
func TestGenerateWithKit(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "agent.rpm")
	kit := makeKit(t, root)
	_ = os.WriteFile(pkg, []byte("PKG"), 0o600)
	b, _ := NewBuilder(filepath.Join(root, "out"))
	bun, err := b.Generate(GenerateRequest{
		PackagePath: pkg, KitPath: kit, DeploymentProfile: ProfileAgentPlusKit, JobID: "fixed-job",
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if bun.JobID != "fixed-job" {
		t.Fatalf("job id not honored: %s", bun.JobID)
	}
	if bun.Manifest.DeploymentProfile != ProfileAgentPlusKit {
		t.Fatalf("profile = %s", bun.Manifest.DeploymentProfile)
	}
	if bun.Manifest.KitFile != "kit.zip" || bun.Manifest.KitSHA256 == "" {
		t.Fatalf("kit identity missing from manifest: %+v", bun.Manifest)
	}
	_, contents := extractTar(t, bun.Path)
	for _, name := range []string{"agent.rpm", "kit/install-deployment-kit.sh", "kit/veeamdeployment.rpm", "kit/client-cert.pem"} {
		if _, ok := contents[name]; !ok {
			t.Fatalf("%s not shipped in bundle; have %v", name, keys(contents))
		}
	}
	if string(contents["kit/veeamdeployment.rpm"]) != "DEPLOY-RPM" {
		t.Fatalf("kit package content corrupted: %q", contents["kit/veeamdeployment.rpm"])
	}
	cfg := string(contents["config.sh"])
	for _, want := range []string{"HAVE_PACKAGE='yes'", "HAVE_KIT='yes'"} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("config.sh missing %s:\n%s", want, cfg)
		}
	}
}

// TestGenerateKitOnly builds a kit-only bundle (no standalone package) — the
// primary profile under the Kit-is-the-payload model — and asserts the package
// is absent, the kit is extracted, and install.sh runs the official installer
// with bash (never executes the ZIP itself).
func TestGenerateKitOnly(t *testing.T) {
	root := t.TempDir()
	kit := makeKit(t, root)
	b, _ := NewBuilder(filepath.Join(root, "out"))
	bun, err := b.Generate(GenerateRequest{KitPath: kit}) // profile inferred
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if bun.Manifest.DeploymentProfile != ProfileKitOnly {
		t.Fatalf("inferred profile = %s, want %s", bun.Manifest.DeploymentProfile, ProfileKitOnly)
	}
	if bun.Manifest.PackageFile != "" {
		t.Fatalf("kit-only manifest records a package file: %q", bun.Manifest.PackageFile)
	}
	modes, contents := extractTar(t, bun.Path)
	if _, ok := contents["kit/install-deployment-kit.sh"]; !ok {
		t.Fatalf("kit not extracted into kit/; have %v", keys(contents))
	}
	// The official installer ships executable.
	if modes["kit/install-deployment-kit.sh"]&0o111 == 0 {
		t.Fatalf("kit installer not executable: mode %o", modes["kit/install-deployment-kit.sh"])
	}
	cfg := string(contents["config.sh"])
	for _, want := range []string{"HAVE_PACKAGE='no'", "HAVE_KIT='yes'", "PACKAGE_FILE=''"} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("config.sh missing %s:\n%s", want, cfg)
		}
	}
	// install.sh must run the official installer with bash and must NOT execute
	// the kit archive directly (the exit-126 bug) and not reference any kit
	// config variable that no longer exists.
	inst := string(contents["install.sh"])
	if !strings.Contains(inst, "bash kit/install-deployment-kit.sh") {
		t.Fatalf("install.sh does not run the official installer:\n%s", inst)
	}
	for _, bad := range []string{"--silent", "$KIT_FILE"} {
		if strings.Contains(inst, bad) {
			t.Fatalf("install.sh still references %q:\n%s", bad, inst)
		}
	}
	// SHA256SUMS must not reference the standalone agent package (not shipped).
	if strings.Contains(string(contents["SHA256SUMS"]), "agent.rpm") {
		t.Fatalf("SHA256SUMS references an unshipped package:\n%s", contents["SHA256SUMS"])
	}
}

// TestGenerateRejectsInvalidKit proves a non-ZIP kit (the exit-126 foot-gun)
// fails at generate time with an actionable error, never on the target.
func TestGenerateRejectsInvalidKit(t *testing.T) {
	root := t.TempDir()
	bogus := filepath.Join(root, "kit.bin")
	_ = os.WriteFile(bogus, []byte("#!/bin/sh\nnot a zip"), 0o600)
	b, _ := NewBuilder(filepath.Join(root, "out"))
	if _, err := b.Generate(GenerateRequest{KitPath: bogus}); err == nil || !strings.Contains(err.Error(), "not a Deployment Kit archive") {
		t.Fatalf("err = %v, want 'not a Deployment Kit archive'", err)
	}
}

// TestGenerateValidatesProfiles pins the per-profile path requirements.
func TestGenerateValidatesProfiles(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "agent.rpm")
	kit := filepath.Join(root, "kit.bin")
	_ = os.WriteFile(pkg, []byte("PKG"), 0o600)
	_ = os.WriteFile(kit, []byte("KIT"), 0o600)
	b, _ := NewBuilder(filepath.Join(root, "out"))

	cases := []struct {
		name    string
		req     GenerateRequest
		wantErr string
	}{
		{"no payload at all", GenerateRequest{}, "no payload"},
		{"package without kit", GenerateRequest{PackagePath: pkg}, "Deployment Kit is required"},
		{"kit-only without kit", GenerateRequest{DeploymentProfile: ProfileKitOnly, PackagePath: pkg}, "requires a kit path"},
		{"legacy agent-only profile", GenerateRequest{DeploymentProfile: "agent-only", KitPath: kit, PackagePath: pkg}, "unsupported deployment profile"},
		{"agent-plus-kit without package", GenerateRequest{DeploymentProfile: ProfileAgentPlusKit, KitPath: kit}, "requires a package path"},
		{"agent-plus-kit without kit", GenerateRequest{DeploymentProfile: ProfileAgentPlusKit, PackagePath: pkg}, "requires a kit path"},
		{"unknown profile", GenerateRequest{DeploymentProfile: "bogus", PackagePath: pkg}, "unsupported deployment profile"},
	}
	for _, tc := range cases {
		if _, err := b.Generate(tc.req); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantErr)
		}
	}
}

func TestImportRoundTrip(t *testing.T) {
	valid := `{"schemaVersion":"1.0","jobId":"abc","ok":true,"deploymentProfile":"agent-plus-kit","target":{"hostName":"h","architecture":"x86_64","addresses":"1.2.3.4,5.6.7.8"},"install":{"packageInstalled":true,"deploymentKitReady":true,"rebootRequired":false},"verify":{"packageVersion":"1.0","serviceStatus":"active","agentStatus":"active"}}`

	r, err := Import([]byte(valid), ImportOptions{ExpectedJobID: "abc"})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	want := AddressList{"1.2.3.4", "5.6.7.8"}
	if len(r.Target.Addresses) != len(want) {
		t.Fatalf("addresses = %v", r.Target.Addresses)
	}
	for i := range want {
		if r.Target.Addresses[i] != want[i] {
			t.Fatalf("address[%d] = %s", i, r.Target.Addresses[i])
		}
	}

	if _, err := Import([]byte(valid), ImportOptions{ExpectedJobID: "other"}); err == nil {
		t.Fatal("job id mismatch must error")
	}
	if _, err := Import([]byte(valid), ImportOptions{ExpectedProfile: "kit-only"}); err == nil {
		t.Fatal("profile mismatch must error")
	}
	legacyAgentOnly := `{"schemaVersion":"1.0","jobId":"abc","ok":true,"deploymentProfile":"agent-only"}`
	if _, err := Import([]byte(legacyAgentOnly), ImportOptions{}); err == nil {
		t.Fatal("Agent-only result must be rejected")
	}
	if _, err := Import([]byte(`{"schemaVersion":"9.9","jobId":"abc","ok":true}`), ImportOptions{}); err == nil {
		t.Fatal("schema mismatch must error")
	}
	if _, err := Import([]byte(`{"schemaVersion":"1.0","jobId":"abc","ok":false,"error":"boom"}`), ImportOptions{}); err == nil {
		t.Fatal("ok=false must error")
	}
}

// TestAddressListAcceptsArray proves the Go OfflineExecutor's array form also
// decodes (parity with the shell string form).
func TestAddressListAcceptsArray(t *testing.T) {
	var tgt ResultTarget
	if err := json.Unmarshal([]byte(`{"hostName":"h","architecture":"x86_64","addresses":["10.0.0.1","10.0.0.2"]}`), &tgt); err != nil {
		t.Fatal(err)
	}
	if len(tgt.Addresses) != 2 || tgt.Addresses[0] != "10.0.0.1" {
		t.Fatalf("array addresses = %v", tgt.Addresses)
	}
}

// --- helpers ---

// makeKit builds a minimal but VALID Deployment Kit ZIP (official installer +
// deployment-service package + cert): the kit is an archive, never a script.
func makeKit(t *testing.T, dir string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range []struct{ name, body string }{
		{"install-deployment-kit.sh", "#!/bin/bash\nexit 0\n"},
		{"veeamdeployment.rpm", "DEPLOY-RPM"},
		{"client-cert.pem", "CERT"},
	} {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "kit.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func extractTar(t *testing.T, path string) (map[string]int64, map[string][]byte) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	modes := map[string]int64{}
	contents := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, tr)
		modes[hdr.Name] = hdr.Mode
		contents[hdr.Name] = buf.Bytes()
	}
	return modes, contents
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func writeMembers(t *testing.T, dir string, contents map[string][]byte) {
	t.Helper()
	for name, b := range contents {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
