package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Coku2015/agentbridge/internal/executor/templates"
	"github.com/Coku2015/agentbridge/internal/kitzip"
)

// Deployment profiles select the bundle payload (AB-FR-143). Exactly one ships
// per bundle; the fixed install.sh derives its steps from the same profile.
const (
	// ProfileKitOnly ships only the Deployment Kit: the kit archive's own
	// official installer runs on the target and sets up the deployment service
	// + campaign certificate (the Agent package is pushed later by VBR).
	ProfileKitOnly = "kit-only"
	// ProfileAgentPlusKit ships both: the package installs first, then the Kit.
	ProfileAgentPlusKit = "agent-plus-kit"
)

// archiveModTime keeps generated bundles byte-for-byte reproducible without
// using the Unix epoch. GNU tar reports epoch-zero members as "implausibly
// old", which obscures the actual installer output on older Linux targets.
var archiveModTime = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

// IsSupportedProfile reports whether p is a certificate-ready deployment
// profile. Every supported profile includes the Deployment Kit; AgentBridge
// never creates a credential-based Protection Group for a host without it.
func IsSupportedProfile(p string) bool {
	return p == ProfileKitOnly || p == ProfileAgentPlusKit
}

// profileWantsPackage reports whether the profile ships a standalone package.
func profileWantsPackage(p string) bool { return p == ProfileAgentPlusKit }

// profileWantsKit reports whether the profile ships the Deployment Kit.
func profileWantsKit(p string) bool { return IsSupportedProfile(p) }

// Manifest is the non-secret manifest shipped inside the bundle. It correlates
// the bundle to a job and records the selected deployment profile (AB-FR-143).
// No secret field is ever present (red line 1).
type Manifest struct {
	SchemaVersion     string `json:"schemaVersion"`
	JobID             string `json:"jobId"`
	PackageID         string `json:"packageId,omitempty"`
	PackageSHA256     string `json:"packageSha256,omitempty"`
	PackageFile       string `json:"packageFile,omitempty"`
	DeploymentProfile string `json:"deploymentProfile"` // "kit-only" | "agent-plus-kit"
	KitFile           string `json:"kitFile,omitempty"` // original kit archive name (traceability)
	KitSHA256         string `json:"kitSha256,omitempty"`
	GeneratedAt       string `json:"generatedAt"` // RFC3339
}

// GenerateRequest describes a bundle to build. It intentionally carries NO
// secret of any kind: the zero-credential invariant (FR-034, red line 1) means
// generation never obtains or holds a Linux password, private key, VBR password,
// bearer token or one-shot download token. The package/kit bytes are already
// cached on disk by US2 (the customer's own VBR artifacts).
type GenerateRequest struct {
	PackagePath       string // local standalone Agent package (agent-plus-kit only)
	PackageID         string // VBR package id (non-secret)
	PackageSHA256     string // expected package content hash (non-secret)
	PackagePaths      []string
	PackageIDs        []string
	PackageSHA256s    []string
	KitPath           string // local cached Deployment Kit (kit-only / agent-plus-kit)
	DeploymentProfile string // "kit-only" | "agent-plus-kit"; inferred from paths when empty
	JobID             string // optional correlation id; generated when empty
}

// Bundle is the generated tarball reference returned to the caller.
type Bundle struct {
	Path     string
	SHA256   string
	JobID    string
	Manifest Manifest
}

// Builder writes bundles into a protected root dir (0o700). Output files are
// 0o600; bundle bytes never reach logs (AB-FR-141).
type Builder struct {
	rootDir string
}

// NewBuilder creates a Builder rooted at rootDir.
func NewBuilder(rootDir string) (*Builder, error) {
	if err := os.MkdirAll(rootDir, 0o700); err != nil {
		return nil, fmt.Errorf("bundle: root dir: %w", err)
	}
	return &Builder{rootDir: rootDir}, nil
}

// Generate assembles a self-contained Local/Offline bundle (FR-034/035). The
// deployment profile selects the payload: kit-only or Agent plus Kit. When
// the profile is empty it is inferred from which paths were supplied. Generate
// writes a generated config.sh (ShellQuote'd), a fixed install.sh, manifest.json
// and SHA256SUMS, then tars+gzips the lot. No credential is read, held or
// written.
func (b *Builder) Generate(req GenerateRequest) (*Bundle, error) {
	packagePaths := append([]string(nil), req.PackagePaths...)
	if len(packagePaths) == 0 && req.PackagePath != "" {
		packagePaths = []string{req.PackagePath}
	}
	profile := req.DeploymentProfile
	if profile == "" {
		switch {
		case req.KitPath != "" && len(packagePaths) > 0:
			profile = ProfileAgentPlusKit
		case req.KitPath != "":
			profile = ProfileKitOnly
		case len(packagePaths) > 0:
			return nil, fmt.Errorf("bundle: Deployment Kit is required for every supported deployment profile")
		default:
			return nil, fmt.Errorf("bundle: no payload — supply a kit path and/or a package path")
		}
	}
	if !IsSupportedProfile(profile) {
		return nil, fmt.Errorf("bundle: unsupported deployment profile %q (want %s or %s; every profile must include Deployment Kit)",
			profile, ProfileKitOnly, ProfileAgentPlusKit)
	}

	var pkgFile, kitFile, kitSHA string
	var pkgBytes []byte
	var kitFiles []kitzip.File
	if profileWantsPackage(profile) {
		if len(packagePaths) == 0 {
			return nil, fmt.Errorf("bundle: profile %q requires a package path", profile)
		}
		if len(packagePaths) == 1 {
			f, bs, err := readArtifact(packagePaths[0])
			if err != nil {
				return nil, fmt.Errorf("bundle: read package: %w", err)
			}
			pkgFile, pkgBytes = f, bs
		} else {
			bs, err := packageSetArchive(packagePaths)
			if err != nil {
				return nil, fmt.Errorf("bundle: combine Agent packages: %w", err)
			}
			pkgFile, pkgBytes = "agent-packages.tar.gz", bs
			// A universal manual bundle must let the target-side selector inspect
			// every downloaded catalog set rather than inheriting one package's
			// standard/nosnap hint.
			req.PackageID = ""
			req.PackageSHA256 = ""
		}
		if req.PackageSHA256 == "" {
			req.PackageSHA256 = shaHex(pkgBytes)
		}
	}
	if profileWantsKit(profile) {
		if req.KitPath == "" {
			return nil, fmt.Errorf("bundle: profile %q requires a kit path", profile)
		}
		f, raw, err := readArtifact(req.KitPath)
		if err != nil {
			return nil, fmt.Errorf("bundle: read kit: %w", err)
		}
		kitFile, kitSHA = f, shaHex(raw)
		// The kit is a ZIP: extract it at GENERATE time so the target never
		// needs unzip — the bundle ships the official installer + its sibling
		// packages/certs as plain files under kit/.
		kitFiles, err = kitzip.Extract(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("bundle: %w", err)
		}
	}

	jobID := req.JobID
	if jobID == "" {
		id, err := randID(8)
		if err != nil {
			return nil, err
		}
		jobID = id
	}
	manifest := Manifest{
		SchemaVersion: ResultSchemaVersion, JobID: jobID,
		PackageID: req.PackageID, PackageSHA256: req.PackageSHA256, PackageFile: pkgFile,
		DeploymentProfile: profile, KitFile: kitFile, KitSHA256: kitSHA,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	cfg := configScript(manifest)
	manifestJSON, _ := json.MarshalIndent(manifest, "", "  ")

	// Single payload map is the source of truth for BOTH the tar and its
	// checksums (DRY): only artifacts the profile ships are present.
	files := map[string][]byte{
		"install.sh":    []byte(installScript),
		"config.sh":     []byte(cfg),
		"manifest.json": manifestJSON,
	}
	if pkgFile != "" {
		files[pkgFile] = pkgBytes
	}
	for _, f := range kitFiles {
		files["kit/"+f.Name] = f.Data
	}
	sums := sha256sums(files)
	files["SHA256SUMS"] = sums

	outPath := filepath.Join(b.rootDir, "bundle-"+jobID+".tar.gz")
	if err := writeTar(outPath, files); err != nil {
		return nil, err
	}
	return &Bundle{Path: outPath, SHA256: fileSHA(outPath), JobID: jobID, Manifest: manifest}, nil
}

// configScript renders the generated config.sh consumed by the fixed install.sh.
// Every value is wrapped by templates.ShellQuote (single-quote quoting, red line
// 5). These are AgentBridge-owned artifact names + a random job id — never user
// input, never a credential. PACKAGE_ID gives the target-side selector the
// non-secret VBR catalog identity (not a filename or a command); HAVE_PACKAGE/
// HAVE_KIT tell install.sh which payload steps the profile actually ships. The
// kit payload location is the fixed literal dir `kit/` (AgentBridge-owned), so
// it needs no config variable.
func configScript(m Manifest) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "RESULT_SCHEMA=%s\n", templates.ShellQuote(m.SchemaVersion))
	fmt.Fprintf(&sb, "JOB_ID=%s\n", templates.ShellQuote(m.JobID))
	fmt.Fprintf(&sb, "PROFILE=%s\n", templates.ShellQuote(m.DeploymentProfile))
	fmt.Fprintf(&sb, "PACKAGE_ID=%s\n", templates.ShellQuote(m.PackageID))
	fmt.Fprintf(&sb, "PACKAGE_FILE=%s\n", templates.ShellQuote(m.PackageFile))
	fmt.Fprintf(&sb, "HAVE_PACKAGE=%s\n", quotedYesNo(m.PackageFile != ""))
	fmt.Fprintf(&sb, "HAVE_KIT=%s\n", quotedYesNo(kitWanted(m)))
	return sb.String()
}

// kitWanted reports whether the manifest's profile ships the Deployment Kit.
func kitWanted(m Manifest) bool { return profileWantsKit(m.DeploymentProfile) }

// quotedYesNo renders yes/no through ShellQuote so config.sh stays fully quoted.
func quotedYesNo(v bool) string {
	if v {
		return templates.ShellQuote("yes")
	}
	return templates.ShellQuote("no")
}

// sha256sums renders the `sha256sum -c` manifest (lines of "<sha>  <name>") for
// every shipped artifact — the fixed scripts, the standalone package and the
// extracted kit files. The bundle's install.sh verifies every listed artifact
// before touching the OS (AB-FR-144).
func sha256sums(files map[string][]byte) []byte {
	var sb strings.Builder
	for _, n := range payloadOrder(files) {
		fmt.Fprintf(&sb, "%s  %s\n", shaHex(files[n]), n)
	}
	return []byte(sb.String())
}

// payloadOrder returns the fixed scripts first, then any other map keys sorted,
// so checksums and tar members are deterministic across runs.
func payloadOrder(files map[string][]byte) []string {
	fixed := []string{"install.sh", "config.sh", "manifest.json"}
	var rest []string
	for n := range files {
		if !contains(fixed, n) {
			rest = append(rest, n)
		}
	}
	sort.Strings(rest)
	out := make([]string, 0, len(fixed)+len(rest))
	for _, n := range fixed {
		if _, ok := files[n]; ok {
			out = append(out, n)
		}
	}
	return append(out, rest...)
}

// writeTar streams the payload map into a gzipped tar in payloadOrder. Only
// install.sh is executable; every other member is 0o644.
func writeTar(outPath string, files map[string][]byte) error {
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("bundle: create archive: %w", err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	for _, name := range payloadOrder(files) {
		mode := int64(0o644)
		if name == "install.sh" || name == "kit/"+kitzip.InstallerName {
			mode = 0o755
		}
		content := files[name]
		hdr := &tar.Header{Name: name, Mode: mode, Size: int64(len(content)), ModTime: archiveModTime}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("bundle: tar header %s: %w", name, err)
		}
		if _, err := tw.Write(content); err != nil {
			return fmt.Errorf("bundle: tar write %s: %w", name, err)
		}
	}
	return nil
}

func readArtifact(path string) (string, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	return filepath.Base(path), b, nil
}

// packageSetArchive combines independently downloaded VBR package sets into
// one target-side candidate archive. The fixed installer already probes
// /etc/os-release, architecture and kernel details, so it can select the
// correct RPM/DEB roles without asking the operator to choose an artifact.
func packageSetArchive(paths []string) ([]byte, error) {
	files := make(map[string][]byte)
	for i, source := range paths {
		name, raw, err := readArtifact(source)
		if err != nil {
			return nil, err
		}
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, ".rpm") || strings.HasSuffix(lower, ".deb") {
			files[fmt.Sprintf("set-%03d/%s", i, filepath.Base(name))] = raw
			continue
		}
		entries, err := packageArchiveEntries(raw)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		for _, entry := range entries {
			files[fmt.Sprintf("set-%03d/%s", i, filepath.Base(entry.name))] = entry.data
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no RPM/DEB payloads found")
	}
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for _, name := range payloadOrder(files) {
		data := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: archiveModTime}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

type packageArchiveEntry struct {
	name string
	data []byte
}

func packageArchiveEntries(raw []byte) ([]packageArchiveEntry, error) {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("unsupported package archive: %w", err)
	}
	decompressed, err := io.ReadAll(gz)
	_ = gz.Close()
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(bytes.NewReader(decompressed))
	var out []packageArchiveEntry
	for {
		hdr, nextErr := tr.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return nil, nextErr
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		ext := strings.ToLower(filepath.Ext(hdr.Name))
		if ext != ".rpm" && ext != ".deb" {
			continue
		}
		data, readErr := io.ReadAll(tr)
		if readErr != nil {
			return nil, readErr
		}
		out = append(out, packageArchiveEntry{name: hdr.Name, data: data})
	}
	return out, nil
}

func shaHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func fileSHA(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return shaHex(b)
}

func randID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// installScript is the FIXED POSIX bundle installer (AB-FR-035). It is a
// constant: all variable values arrive via config.sh (generated, ShellQuote'd).
// No caller string is concatenated unquoted into a command (red line 5). Run on
// the target as `sudo ./install.sh`; it emits result.json for import (AB-FR-142).
//
// The deployment profile (PROFILE) selects the payload steps:
//
//	kit-only       -> run the kit's official installer only. The kit archive is
//	                  a ZIP that AgentBridge already EXTRACTED into kit/ at
//	                  generate time, so the target needs no unzip — the script
//	                  runs `bash kit/install-deployment-kit.sh`, which installs
//	                  the deployment service and pairs the campaign certificate
//	                  (the Agent package itself is pushed later by VBR through
//	                  that service);
//	agent-plus-kit -> install the package, then run the kit installer.
//
// Overall success = the steps the profile requires all succeeded. The kit dir
// name `kit` is an AgentBridge-owned literal, never caller input.
const installScript = `#!/bin/sh
# AgentBridge offline bundle installer. Run on the target as: sudo ./install.sh
# FIXED SCRIPT: every external value comes from config.sh, which AgentBridge
# generates with single-quote quoting. No user string is concatenated unquoted
# into a command (red line 5). This bundle holds NO password, private key, VBR
# password, bearer token or one-shot download token (AB-FR-141).
set -u
cd "$(dirname "$0")" || exit 1
[ -f config.sh ] || { echo "config.sh missing"; exit 1; }
. ./config.sh

bool() { if [ "$1" = "yes" ]; then echo true; else echo false; fi; }

fail() {
  msg=$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')
  printf '{"schemaVersion":"%s","jobId":"%s","ok":false,"deploymentProfile":"%s","error":"%s"}\n' \
    "$RESULT_SCHEMA" "$JOB_ID" "$PROFILE" "$msg" > result.json
  cat result.json
  exit 1
}

# 1. integrity: verify every shipped artifact before touching the OS (AB-FR-144).
if command -v sha256sum >/dev/null 2>&1 && [ -f SHA256SUMS ]; then
  sha256sum -c SHA256SUMS >/dev/null 2>&1 || fail "integrity check failed"
fi

# 2. target identity (AB-FR-086).
HOST=$(hostname 2>/dev/null || echo "")
ARCH=$(uname -m 2>/dev/null || echo "")
KERNEL=$(uname -r 2>/dev/null || echo "")
ADDRS=$(hostname -I 2>/dev/null | tr ' ' ',' || echo "")
SECURE_BOOT=unknown
if command -v mokutil >/dev/null 2>&1; then
  if mokutil --sb-state 2>/dev/null | grep -qi 'secureboot enabled'; then
    SECURE_BOOT=enabled
  elif mokutil --sb-state 2>/dev/null | grep -qi 'secureboot disabled'; then
    SECURE_BOOT=disabled
  fi
elif [ -d /sys/firmware/efi/efivars ]; then
  for sb_file in /sys/firmware/efi/efivars/SecureBoot-*; do
    [ -f "$sb_file" ] || continue
    sb_byte=$(od -An -t u1 "$sb_file" 2>/dev/null | awk '{last=$NF} END{print last}')
    [ "$sb_byte" = "1" ] && SECURE_BOOT=enabled
    [ "$sb_byte" = "0" ] && SECURE_BOOT=disabled
    break
  done
fi

# 3. install the payload steps the profile ships. For a VBR package-set archive
# the target-side selector inspects package headers and installs only the role
# complete set for this OS/architecture. It deliberately does NOT run
# rpm -Uvh *.rpm: a VBR export can contain standard/nosnap and kernel-module
# alternatives in one archive.
PKG_OK=no
KIT_OK=no
PKG_ERR=""
KIT_ERR=""
if [ "$HAVE_PACKAGE" = "yes" ] && [ -n "$PACKAGE_FILE" ] && [ -f "$PACKAGE_FILE" ]; then
	case "$PACKAGE_FILE" in
	  *.rpm)
	      if rpm -Uvh "$PACKAGE_FILE" >/tmp/ab-agent.log 2>&1; then PKG_OK=yes; else PKG_ERR="agent RPM install failed"; fi
	      ;;
	  *.deb)
	      if dpkg -i "$PACKAGE_FILE" >/tmp/ab-agent.log 2>&1; then PKG_OK=yes; else PKG_ERR="agent DEB install failed"; fi
	      ;;
	  *.tar.gz|*.tgz)
	      PKG_DIR=$(mktemp -d /tmp/agentbridge-package-set.XXXXXX 2>/dev/null || true)
	      if [ -z "$PKG_DIR" ] || ! tar -xzf "$PACKAGE_FILE" -C "$PKG_DIR" >/tmp/ab-agent.log 2>&1; then
	        PKG_ERR="agent package set extraction failed"
	      else
	        RPM_FILES=$(find "$PKG_DIR" -type f -name '*.rpm' -print)
	        DEB_FILES=$(find "$PKG_DIR" -type f -name '*.deb' -print)
	        if [ -n "$RPM_FILES" ] && [ -n "$DEB_FILES" ]; then
	          # A universal bundle may intentionally carry both catalog
	          # families. Choose the target's native format before selecting
	          # package roles; never pass both families to an installer.
	          if [ -f /etc/debian_version ] && command -v dpkg >/dev/null 2>&1; then
	            RPM_FILES=""
	          elif command -v rpm >/dev/null 2>&1; then
	            DEB_FILES=""
	          elif command -v dpkg >/dev/null 2>&1; then
	            RPM_FILES=""
	          else
	            PKG_ERR="target has no supported RPM/DEB package manager"
	          fi
	        fi
	        if [ -z "$PKG_ERR" ] && [ -n "$RPM_FILES" ]; then
	          if ! command -v rpm >/dev/null 2>&1; then
	            PKG_ERR="target has no rpm command"
	          else
	            TARGET_ID=""
	            TARGET_VERSION=""
	            TARGET_LIKE=""
	            if [ -f /etc/os-release ]; then
	              . /etc/os-release
	              TARGET_ID=${ID:-}
	              TARGET_VERSION=${VERSION_ID:-}
	              TARGET_LIKE=${ID_LIKE:-}
	            fi
	            TARGET_MAJOR=$(printf '%s' "$TARGET_VERSION" | sed -n 's/^\([0-9][0-9]*\).*/\1/p')
	            TARGET_ARCH="$ARCH"
	            PACKAGE_MODE=standard
	            case "$(printf '%s' "$PACKAGE_ID" | tr '[:upper:]' '[:lower:]')" in
	              *nosnap*) PACKAGE_MODE=nosnap ;;
	            esac

	            # The files below are the selector's output. The scan runs in a
	            # pipeline so candidate paths are written to files rather than
	            # relying on non-POSIX shell arrays or leaking paths into eval.
	            SELECT_DIR=$(mktemp -d /tmp/agentbridge-package-select.XXXXXX 2>/dev/null || true)
	            if [ -z "$SELECT_DIR" ]; then
	              PKG_ERR="cannot create package selection workspace"
	            else
	              : > "$SELECT_DIR/libs.path"
	              : > "$SELECT_DIR/libs.score"
	              : > "$SELECT_DIR/agent.path"
	              : > "$SELECT_DIR/agent.score"
	              : > "$SELECT_DIR/nosnap.path"
	              : > "$SELECT_DIR/nosnap.score"
	              : > "$SELECT_DIR/snapshot.path"
	              : > "$SELECT_DIR/snapshot.score"

	              find "$PKG_DIR" -type f -name '*.rpm' -print | while IFS= read -r f; do
	                META=$(rpm -qp --qf '%{NAME}\t%{ARCH}\t%{RELEASE}' "$f" 2>/dev/null) || continue
	                TAB=$(printf '\t')

	                PKG_NAME=""
	                PKG_ARCH=""
	                PKG_RELEASE=""
	                IFS="$TAB" read -r PKG_NAME PKG_ARCH PKG_RELEASE <<EOF
$META
EOF

	                case "$PKG_ARCH:$TARGET_ARCH" in
	                  noarch:*|x86_64:x86_64|amd64:x86_64|aarch64:aarch64|arm64:aarch64|ppc64le:ppc64le|s390x:s390x) ;;
	                  *) continue ;;
	                esac

	                # RHEL-family RPMs carry .elN in RELEASE. If it is present,
	                # reject a different major; packages without that marker are
	                # allowed because some Veeam dependency RPMs are generic.
	                case "$PKG_RELEASE" in
	                  *.el[0-9]*)
	                    if [ -n "$TARGET_MAJOR" ]; then
	                      case "$PKG_RELEASE" in
	                        *".el$TARGET_MAJOR"*) ;;
	                        *) continue ;;
	                      esac
	                    fi
	                    ;;
	                esac

	                PKG_ROLE=unknown
	                case "$PKG_NAME" in
	                  veeam-ueficert*) PKG_ROLE=uefi-cert ;;
	                  veeam-release*) PKG_ROLE=release ;;
	                  veeam-libs*) PKG_ROLE=libs ;;
	                  veeam-nosnap*) PKG_ROLE=nosnap ;;
	                  kmod-veeamsnap*|veeamsnap*|kmod-blksnap*|blksnap*) PKG_ROLE=snapshot ;;
	                  veeamdeployment*|veeam-deployment*) PKG_ROLE=deployment ;;
	                  veeam|veeam-*|veeam_*) PKG_ROLE=agent ;;
	                esac

	                case "$PACKAGE_MODE:$PKG_ROLE" in
	                  standard:nosnap)
	                    [ "$TARGET_ARCH" = "ppc64le" ] || continue ;;
	                  nosnap:snapshot|nosnap:agent|nosnap:uefi-cert|*:deployment|*:unknown|*:release) continue ;;
	                esac

	                SCORE=0
	                case "$PKG_ROLE" in
	                  snapshot)
	                    case "$TARGET_ID $TARGET_LIKE" in
	                      *sles*|*suse*)
	                        case "$PKG_NAME" in
	                          *-kmp-preempt*) SCORE=150 ;;
	                          *-kmp-default*) SCORE=160 ;;
	                          *) SCORE=70 ;;
	                        esac
	                        case "$(printf '%s' "$KERNEL" | tr '[:upper:]' '[:lower:]'):$PKG_NAME" in
	                          *preempt*:*kmp-preempt*) SCORE=$((SCORE+25)) ;;
	                          *preempt*:*kmp-default*) SCORE=$((SCORE-20)) ;;
	                          *:*kmp-preempt*) SCORE=$((SCORE-10)) ;;
	                        esac
	                        ;;
	                      *)
	                        case "$TARGET_MAJOR" in
	                          9|10|11|12|13|14|15|16|17|18|19|20)
	                            case "$PKG_NAME" in *blksnap*) SCORE=120 ;; *kmod-*) SCORE=110 ;; *) SCORE=100 ;; esac ;;
	                          *)
	                            case "$PKG_NAME" in *veeamsnap*) SCORE=120 ;; *kmod-*) SCORE=110 ;; *) SCORE=100 ;; esac ;;
	                        esac
	                        ;;
	                    esac
	                    case "$TARGET_ID $TARGET_LIKE:$PKG_NAME" in
	                      *oracle*:*kmod-*|*ol*:*kmod-*) SCORE=$((SCORE-40)) ;;
	                    esac
	                    ;;
	                  libs|agent) SCORE=100 ;;
	                esac

	                SCORE_FILE="$SELECT_DIR/$PKG_ROLE.score"
	                PATH_FILE="$SELECT_DIR/$PKG_ROLE.path"
	                OLD_SCORE=-1
	                [ -s "$SCORE_FILE" ] && OLD_SCORE=$(cat "$SCORE_FILE")
	                if [ "$SCORE" -gt "$OLD_SCORE" ]; then
	                  printf '%s' "$SCORE" > "$SCORE_FILE"
	                  printf '%s\n' "$f" > "$PATH_FILE"
	                fi
              done

	              MISSING=""
	              case "$PACKAGE_MODE" in
	                standard)
	                  if [ -s "$SELECT_DIR/libs.path" ] && [ -s "$SELECT_DIR/nosnap.path" ] && [ ! -s "$SELECT_DIR/snapshot.path" ] && [ ! -s "$SELECT_DIR/agent.path" ]; then
	                    PACKAGE_MODE=nosnap
	                    cat "$SELECT_DIR/nosnap.path" > "$SELECT_DIR/agent.path"
	                  else
	                    [ -s "$SELECT_DIR/snapshot.path" ] || MISSING="snapshot"
	                    [ -s "$SELECT_DIR/libs.path" ] || MISSING="${MISSING:+$MISSING, }libs"
	                    [ -s "$SELECT_DIR/agent.path" ] || MISSING="${MISSING:+$MISSING, }agent"
	                  fi
	                  ;;
                nosnap)
                  [ -s "$SELECT_DIR/libs.path" ] || MISSING="libs"
                  # nosnap is kept in its own role so the standard Agent RPM
                  # can never be selected accidentally.
                  if [ -s "$SELECT_DIR/nosnap.path" ]; then
                    cat "$SELECT_DIR/nosnap.path" > "$SELECT_DIR/agent.path"
                  else
                    MISSING="${MISSING:+$MISSING, }nosnap"
                  fi
                  ;;
              esac

              if [ -n "$MISSING" ]; then
                PKG_ERR="no compatible RPM payloads for $TARGET_ID $TARGET_VERSION $TARGET_ARCH (missing: $MISSING)"
              else
                INSTALL_LIST="$SELECT_DIR/install.list"
                : > "$INSTALL_LIST"
                if [ "$PACKAGE_MODE" = standard ]; then
                  cat "$SELECT_DIR/snapshot.path" >> "$INSTALL_LIST"
                  cat "$SELECT_DIR/libs.path" >> "$INSTALL_LIST"
                  cat "$SELECT_DIR/agent.path" >> "$INSTALL_LIST"
                  # A UEFI certificate is optional and only belongs on a
                  # Secure Boot target; never install it merely because it is
                  # present in the VBR export.
                  if [ "$SECURE_BOOT" = enabled ] && [ -s "$SELECT_DIR/uefi-cert.path" ]; then
                    cat "$SELECT_DIR/uefi-cert.path" >> "$INSTALL_LIST"
                  fi
                else
                  cat "$SELECT_DIR/libs.path" >> "$INSTALL_LIST"
                  cat "$SELECT_DIR/agent.path" >> "$INSTALL_LIST"
                fi
                PKG_OK=yes
                : > /tmp/ab-agent.log
                while IFS= read -r selected_file; do
                  if ! rpm -Uvh "$selected_file" >>/tmp/ab-agent.log 2>&1; then
                    PKG_OK=no
                    PKG_ERR="selected RPM install failed (see /tmp/ab-agent.log on the target)"
                    break
                  fi
                done < "$INSTALL_LIST"
              fi
              rm -rf "$SELECT_DIR"
            fi
          fi
	        elif [ -z "$PKG_ERR" ] && [ -n "$DEB_FILES" ]; then
	          if ! command -v dpkg >/dev/null 2>&1 || ! command -v dpkg-deb >/dev/null 2>&1; then
	            PKG_ERR="target has no dpkg/dpkg-deb command"
	          else
	            TARGET_ID=""
	            TARGET_VERSION=""
	            TARGET_LIKE=""
	            if [ -f /etc/os-release ]; then
	              . /etc/os-release
	              TARGET_ID=${ID:-}
	              TARGET_VERSION=${VERSION_ID:-}
	              TARGET_LIKE=${ID_LIKE:-}
	            fi
	            TARGET_ARCH="$ARCH"
	            PACKAGE_MODE=standard
	            case "$(printf '%s' "$PACKAGE_ID" | tr '[:upper:]' '[:lower:]')" in
	              *nosnap*) PACKAGE_MODE=nosnap ;;
	            esac

	            SELECT_DIR=$(mktemp -d /tmp/agentbridge-package-select.XXXXXX 2>/dev/null || true)
	            if [ -z "$SELECT_DIR" ]; then
	              PKG_ERR="cannot create package selection workspace"
	            else
	              : > "$SELECT_DIR/libs.path"
	              : > "$SELECT_DIR/libs.score"
	              : > "$SELECT_DIR/agent.path"
	              : > "$SELECT_DIR/agent.score"
	              : > "$SELECT_DIR/snapshot.path"
	              : > "$SELECT_DIR/snapshot.score"

	              find "$PKG_DIR" -type f -name '*.deb' -print | while IFS= read -r f; do
	                PKG_NAME=$(dpkg-deb -f "$f" Package 2>/dev/null) || continue
	                PKG_ARCH=$(dpkg-deb -f "$f" Architecture 2>/dev/null) || continue
                PKG_VERSION=$(dpkg-deb -f "$f" Version 2>/dev/null) || continue
                case "$PKG_ARCH:$TARGET_ARCH" in
	                  all:*|amd64:x86_64|x86_64:x86_64|arm64:aarch64|aarch64:aarch64|ppc64el:ppc64le|ppc64le:ppc64le|s390x:s390x) ;;
	                  *) continue ;;
	                esac
                PKG_ROLE=unknown
                case "$PKG_NAME" in
	                  veeam-ueficert*) PKG_ROLE=uefi-cert ;;
	                  veeam-release*) PKG_ROLE=release ;;
	                  veeam-libs*) PKG_ROLE=libs ;;
	                  veeam-nosnap*) PKG_ROLE=nosnap ;;
	                  veeamsnap*|blksnap*) PKG_ROLE=snapshot ;;
	                  veeamdeployment*|veeam-deployment*) PKG_ROLE=deployment ;;
	                  veeam-*|veeam_*) PKG_ROLE=agent ;;
	                esac
	                case "$PACKAGE_MODE:$PKG_ROLE" in
	                  nosnap:snapshot|nosnap:agent|nosnap:uefi-cert|*:deployment|*:unknown|*:release) continue ;;
	                esac
                SCORE=100
	                if [ "$PKG_ROLE" = snapshot ]; then
	                  case "$TARGET_VERSION:$PKG_NAME" in
	                    11*:*blksnap*|12*:*blksnap*|13*:*blksnap*|14*:*blksnap*|15*:*blksnap*|16*:*blksnap*|17*:*blksnap*|18*:*blksnap*|19*:*blksnap*|20*:*blksnap*) SCORE=120 ;;
	                    *:*veeamsnap*) SCORE=120 ;;
	                  esac
	                fi
                SCORE_FILE="$SELECT_DIR/$PKG_ROLE.score"
                PATH_FILE="$SELECT_DIR/$PKG_ROLE.path"
                OLD_SCORE=-1
                [ -s "$SCORE_FILE" ] && OLD_SCORE=$(cat "$SCORE_FILE")
                if [ "$SCORE" -gt "$OLD_SCORE" ]; then
                  printf '%s' "$SCORE" > "$SCORE_FILE"
                  printf '%s\n' "$f" > "$PATH_FILE"
                fi
              done

	              MISSING=""
	              case "$PACKAGE_MODE" in
	                standard)
	                  if [ -s "$SELECT_DIR/libs.path" ] && [ -s "$SELECT_DIR/nosnap.path" ] && [ ! -s "$SELECT_DIR/snapshot.path" ] && [ ! -s "$SELECT_DIR/agent.path" ]; then
	                    PACKAGE_MODE=nosnap
	                    cat "$SELECT_DIR/nosnap.path" > "$SELECT_DIR/agent.path"
	                  else
	                    [ -s "$SELECT_DIR/snapshot.path" ] || MISSING="snapshot"
	                    [ -s "$SELECT_DIR/libs.path" ] || MISSING="${MISSING:+$MISSING, }libs"
	                    [ -s "$SELECT_DIR/agent.path" ] || MISSING="${MISSING:+$MISSING, }agent"
	                  fi
                  ;;
                nosnap)
                  [ -s "$SELECT_DIR/libs.path" ] || MISSING="libs"
                  if [ -s "$SELECT_DIR/nosnap.path" ]; then
                    cat "$SELECT_DIR/nosnap.path" > "$SELECT_DIR/agent.path"
                  else
                    MISSING="${MISSING:+$MISSING, }nosnap"
                  fi
                  ;;
              esac
              if [ -n "$MISSING" ]; then
                PKG_ERR="no compatible DEB payloads for $TARGET_ID $TARGET_VERSION $TARGET_ARCH (missing: $MISSING)"
              else
                INSTALL_LIST="$SELECT_DIR/install.list"
                : > "$INSTALL_LIST"
                if [ "$PACKAGE_MODE" = standard ]; then
                  cat "$SELECT_DIR/snapshot.path" >> "$INSTALL_LIST"
                  cat "$SELECT_DIR/libs.path" >> "$INSTALL_LIST"
                  cat "$SELECT_DIR/agent.path" >> "$INSTALL_LIST"
                  if [ "$SECURE_BOOT" = enabled ] && [ -s "$SELECT_DIR/uefi-cert.path" ]; then
                    cat "$SELECT_DIR/uefi-cert.path" >> "$INSTALL_LIST"
                  fi
                else
                  cat "$SELECT_DIR/libs.path" >> "$INSTALL_LIST"
                  cat "$SELECT_DIR/agent.path" >> "$INSTALL_LIST"
                fi
                PKG_OK=yes
                : > /tmp/ab-agent.log
                while IFS= read -r selected_file; do
                  if ! dpkg -i "$selected_file" >>/tmp/ab-agent.log 2>&1; then
                    PKG_OK=no
                    PKG_ERR="selected DEB install failed (see /tmp/ab-agent.log on the target)"
                    break
                  fi
                done < "$INSTALL_LIST"
              fi
              rm -rf "$SELECT_DIR"
            fi
	        fi
	        else
	          PKG_ERR="agent package set contains no RPM/DEB payloads"
	        fi
	      fi
	      [ -z "$PKG_DIR" ] || rm -rf "$PKG_DIR"
	      ;;
	  *)
	      PKG_ERR="unsupported Agent package format"
	      ;;
  esac
fi
if [ "$HAVE_KIT" = "yes" ] && [ -f "kit/install-deployment-kit.sh" ]; then
  if bash kit/install-deployment-kit.sh >/tmp/ab-kit.log 2>&1; then KIT_OK=yes; else
    # yum/dnf exit 1 with "Nothing to do" when the staged RPMs match the
    # installed versions — the idempotent same-version case (red line 6), so
    # confirm against the RPM database before calling it a failure.
    if grep -q 'Nothing to do\|does not update installed package' /tmp/ab-kit.log 2>/dev/null \
       && rpm -q veeamdeployment >/dev/null 2>&1; then KIT_OK=yes; else KIT_ERR="deployment kit install failed (see /tmp/ab-kit.log on the target)"; fi
  fi
fi

# 4. verify — independent facts, never one collapsed flag (Principle IV, AB-FR-164).
# The kit installs the deployment service (veeamdeployment); the veeam Agent
# package arrives later via VBR, so its absence here is NOT a kit failure.
PKG_VER=""
if command -v rpm >/dev/null 2>&1; then
  if rpm -q veeam >/dev/null 2>&1; then
    PKG_VER=$(rpm -q --qf '%{VERSION}-%{RELEASE}' veeam 2>/dev/null || echo "")
  elif rpm -q veeamdeployment >/dev/null 2>&1; then
    PKG_VER=$(rpm -q --qf '%{VERSION}-%{RELEASE}' veeamdeployment 2>/dev/null || echo "")
  fi
elif command -v dpkg-query >/dev/null 2>&1; then
  if dpkg-query -W veeam >/dev/null 2>&1; then
    PKG_VER=$(dpkg-query -W -f='${Version}' veeam 2>/dev/null || echo "")
  elif dpkg-query -W veeamdeployment >/dev/null 2>&1; then
    PKG_VER=$(dpkg-query -W -f='${Version}' veeamdeployment 2>/dev/null || echo "")
  fi
fi

service_state() {
  fallback=unknown
  for service_name in "$@"; do
    state=$(systemctl is-active "$service_name" 2>/dev/null || true)
    case "$state" in
      active) echo active; return ;;
      inactive|failed|activating|deactivating)
        [ "$fallback" = unknown ] && fallback="$state"
        ;;
    esac
  done
  echo "$fallback"
}
DEPLOY_SVC=$(service_state veeamdeployment veeamdeploymentsvc)
AGENT_SVC=$(service_state veeamservice veeam.service)
SVC="$DEPLOY_SVC"

# 5. overall success = the steps the selected profile requires all succeeded.
OK=false
case "$PROFILE" in
  kit-only)         [ "$KIT_OK" = "yes" ] && OK=true ;;
  agent-plus-kit|*) [ "$PKG_OK" = "yes" ] && [ "$KIT_OK" = "yes" ] && OK=true ;;
esac
ERR=""
[ -n "$PKG_ERR" ] && ERR="$PKG_ERR"
[ -n "$KIT_ERR" ] && ERR="${ERR:+$ERR; }$KIT_ERR"

if [ "$OK" = "true" ]; then
  printf '{"schemaVersion":"%s","jobId":"%s","ok":true,"deploymentProfile":"%s","target":{"hostName":"%s","architecture":"%s","addresses":"%s"},"install":{"packageInstalled":%s,"deploymentKitReady":%s,"rebootRequired":false},"verify":{"packageVersion":"%s","serviceStatus":"%s","agentStatus":"%s"}}\n' \
    "$RESULT_SCHEMA" "$JOB_ID" "$PROFILE" "$HOST" "$ARCH" "$ADDRS" \
    "$(bool "$PKG_OK")" "$(bool "$KIT_OK")" "$PKG_VER" "$SVC" "$AGENT_SVC" > result.json
else
  printf '{"schemaVersion":"%s","jobId":"%s","ok":false,"deploymentProfile":"%s","error":"%s","target":{"hostName":"%s","architecture":"%s","addresses":"%s"},"install":{"packageInstalled":%s,"deploymentKitReady":%s,"rebootRequired":false},"verify":{"packageVersion":"%s","serviceStatus":"%s","agentStatus":"%s"}}\n' \
    "$RESULT_SCHEMA" "$JOB_ID" "$PROFILE" "$ERR" "$HOST" "$ARCH" "$ADDRS" \
    "$(bool "$PKG_OK")" "$(bool "$KIT_OK")" "$PKG_VER" "$SVC" "$AGENT_SVC" > result.json
fi
cat result.json
[ "$OK" = "true" ] || exit 1
`

// Export the script + config builder for the OfflineExecutor to reuse a single
// source of truth (DRY): the local-run executor writes the same fixed script and
// generated config so a local install and an air-gapped install are identical.
var (
	// InstallScript is the fixed bundle installer (exported for reuse/tests).
	InstallScript = installScript
	// ConfigScript renders config.sh for a manifest (exported for reuse/tests).
	ConfigScript = configScript
)

// WriteScript writes the fixed install.sh + generated config.sh + manifest.json
// into dir, used by the OfflineExecutor to run a local install with identical
// artifacts to an air-gapped bundle (DRY, AB-FR-142). Returns the paths.
func WriteScript(dir string, m Manifest) (installPath, cfgPath, manifestPath string, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", "", err
	}
	installPath = filepath.Join(dir, "install.sh")
	if err := os.WriteFile(installPath, []byte(installScript), 0o755); err != nil {
		return "", "", "", err
	}
	cfgPath = filepath.Join(dir, "config.sh")
	if err := os.WriteFile(cfgPath, []byte(configScript(m)), 0o644); err != nil {
		return "", "", "", err
	}
	manifestPath = filepath.Join(dir, "manifest.json")
	mb, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(manifestPath, mb, 0o644); err != nil {
		return "", "", "", err
	}
	return installPath, cfgPath, manifestPath, nil
}

// Reader is re-exported so callers can stream bundle bytes without holding the
// whole archive in memory.
type Reader = io.Reader
