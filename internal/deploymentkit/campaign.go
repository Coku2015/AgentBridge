package deploymentkit

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Coku2015/agentbridge/internal/vbr"
)

// Generator abstracts VBR Kit generation + download. *vbr.RESTAdapter satisfies it
// structurally (SOLID-D). Kit bytes are streamed and written to a protected temp
// dir; private-key material never reaches logs (AB-FR-066).
type Generator interface {
	CreateDeploymentKit(ctx context.Context, req vbr.KitRequest) (vbr.TaskRef, error)
	// WaitTask polls the async generation task to terminal state; the campaign
	// MUST call it before download (downloadKit 400s while the task is Working).
	WaitTask(ctx context.Context, task vbr.TaskRef) error
	DownloadDeploymentKit(ctx context.Context, task vbr.TaskRef) (io.ReadCloser, error)
}

// Campaign is one active Deployment Kit campaign for a VBR. At most one is active
// per VBR at a time (R8/R9): generating/importing a new Kit invalidates previously
// issued unpaired temporary certificates. Kit bytes live only in a protected temp
// file and are deleted when the campaign closes (AB-FR-065).
type Campaign struct {
	id        string      // task ref (generated) or import id
	source    string      // "generated" | "imported"
	path      string      // protected temp file holding the kit bytes
	taskRef   vbr.TaskRef // set when generated
	createdAt time.Time
	platforms []string
	sha256    string
}

// Source reports how the kit was obtained ("generated" | "imported").
func (c *Campaign) Source() string { return c.source }

// ID returns the campaign/task identifier.
func (c *Campaign) ID() string { return c.id }

// Path returns the protected on-disk kit path for the executor to consume.
func (c *Campaign) Path() string { return c.path }

// Platforms returns the platform payloads requested for this campaign.
func (c *Campaign) Platforms() []string { return append([]string(nil), c.platforms...) }

// SHA256 returns the archive digest used by remote and manual installers.
func (c *Campaign) SHA256() string { return c.sha256 }

// Close deletes the kit temp file. Idempotent.
func (c *Campaign) Close() error {
	if c.path == "" {
		return nil
	}
	err := os.Remove(c.path)
	c.path = ""
	return err
}

// KitFileInfo describes one kit archive entry — name and size only. Entry
// contents are never surfaced (server-key.pem is private-key material,
// AB-FR-066).
type KitFileInfo struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// KitInfo is the read-only operator view of a campaign (the step-一 kit
// drawer). Expiry comes from the campaign certificates' NotAfter; a kit whose
// certificates cannot be parsed simply omits it.
type KitInfo struct {
	Path      string        `json:"path"`
	Source    string        `json:"source"`
	ID        string        `json:"id"`
	CreatedAt time.Time     `json:"createdAt"`
	ExpiresAt *time.Time    `json:"expiresAt,omitempty"`
	Platforms []string      `json:"platforms,omitempty"`
	SHA256    string        `json:"sha256,omitempty"`
	TotalSize int64         `json:"totalSize"`
	Files     []KitFileInfo `json:"files"`
}

// Info lists the kit archive entries (central directory only) and parses the
// public certificate entries for the campaign expiry. Display-only and
// best-effort: key entries are listed by name/size and never opened, and no
// per-entry failure aborts the listing.
func (c *Campaign) Info() KitInfo {
	info := KitInfo{
		Path: c.path, Source: c.source, ID: c.id,
		Platforms: append([]string(nil), c.platforms...), SHA256: c.sha256,
		CreatedAt: c.createdAt, Files: []KitFileInfo{},
	}
	f, err := os.Open(c.path)
	if err != nil {
		return info
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return info
	}
	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		return info
	}
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		size := int64(zf.UncompressedSize64)
		info.Files = append(info.Files, KitFileInfo{Name: zf.Name, Size: size})
		info.TotalSize += size
		if isCertEntry(zf.Name) {
			if exp := certExpiry(zf); exp != nil && (info.ExpiresAt == nil || exp.Before(*info.ExpiresAt)) {
				info.ExpiresAt = exp
			}
		}
	}
	sort.Slice(info.Files, func(i, j int) bool { return info.Files[i].Name < info.Files[j].Name })
	return info
}

// isCertEntry matches the kit's public certificate entries (client-cert.pem /
// server-cert.pem). Key entries must never match.
func isCertEntry(name string) bool {
	base := path.Base(strings.ToLower(name))
	return strings.HasSuffix(base, ".pem") && strings.Contains(base, "cert") && !strings.Contains(base, "key")
}

// certExpiry parses a public certificate entry and returns its NotAfter.
func certExpiry(zf *zip.File) *time.Time {
	rc, err := zf.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()
	raw, err := io.ReadAll(io.LimitReader(rc, 1<<20))
	if err != nil {
		return nil
	}
	for len(raw) > 0 {
		block, rest := pem.Decode(raw)
		if block == nil {
			return nil
		}
		raw = rest
		if crt, err := x509.ParseCertificate(block.Bytes); err == nil {
			return &crt.NotAfter
		}
	}
	return nil
}

// Manager enforces the single-active-campaign-per-VBR invariant (R8/R9). All kit
// bytes are confined to rootDir (0o700) and never logged.
type Manager struct {
	mu      sync.Mutex
	gen     Generator
	rootDir string // protected temp root (0o700)
	active  *Campaign
}

// NewManager creates a Kit campaign manager rooted at rootDir (created 0o700).
func NewManager(gen Generator, rootDir string) (*Manager, error) {
	if err := os.MkdirAll(rootDir, 0o700); err != nil {
		return nil, fmt.Errorf("deploymentkit: temp root: %w", err)
	}
	return &Manager{gen: gen, rootDir: rootDir}, nil
}

// SetGenerator injects the VBR generator after a connection is established. The
// manager is created once (process-wide, to enforce single-active); the generator
// arrives when VBR connects. Import works with no generator.
func (m *Manager) SetGenerator(gen Generator) {
	m.mu.Lock()
	m.gen = gen
	m.mu.Unlock()
}

// Generate starts a new campaign: submit generation, then download the Kit into a
// protected temp file. If a campaign is already active it is INVALIDATED (its
// unpaired temp certs are void) and closed; the returned `invalidated` flag lets
// the UI warn the operator (AB-FR-063).
func (m *Manager) Generate(ctx context.Context, req vbr.KitRequest) (*Campaign, bool, error) {
	task, err := m.gen.CreateDeploymentKit(ctx, req)
	if err != nil {
		return nil, false, fmt.Errorf("deploymentkit: generate: %w", err)
	}
	// Kit generation is async: wait for the task to finish before downloading,
	// or downloadKit rejects with 400 (FR-012).
	if err := m.gen.WaitTask(ctx, task); err != nil {
		return nil, false, fmt.Errorf("deploymentkit: wait: %w", err)
	}
	body, err := m.gen.DownloadDeploymentKit(ctx, task)
	if err != nil {
		return nil, false, fmt.Errorf("deploymentkit: download: %w", err)
	}
	defer body.Close()

	path, err := m.writeKit(body)
	if err != nil {
		return nil, false, err
	}
	platforms := kitPlatforms(req)
	camp := &Campaign{
		id: task.ID, source: "generated", path: path, taskRef: task,
		createdAt: time.Now().UTC(), platforms: platforms, sha256: fileSHA256(path),
	}
	invalidated := m.swapActive(camp)
	return camp, invalidated, nil
}

// Import admits an admin-supplied Kit file (used when Capabilities.DeploymentKit=
// false, FR-011). It becomes the single active campaign, displacing any prior one.
func (m *Manager) Import(r io.Reader) (*Campaign, bool, error) {
	path, err := m.writeKit(r)
	if err != nil {
		return nil, false, err
	}
	camp := &Campaign{
		id: "import-" + randID(6), source: "imported", path: path,
		createdAt: time.Now().UTC(), platforms: detectKitPlatforms(path), sha256: fileSHA256(path),
	}
	invalidated := m.swapActive(camp)
	return camp, invalidated, nil
}

func kitPlatforms(req vbr.KitRequest) []string {
	platforms := make([]string, 0, 2)
	if req.IncludeWindowsPackages || (!req.IncludeWindowsPackages && !req.IncludeLinuxPackages && !req.IncludeUnixPackages) {
		platforms = append(platforms, "windows")
	}
	if req.IncludeLinuxPackages || (!req.IncludeWindowsPackages && !req.IncludeLinuxPackages && !req.IncludeUnixPackages) {
		platforms = append(platforms, "linux")
	}
	if req.IncludeUnixPackages {
		platforms = append(platforms, "unix")
	}
	return platforms
}

func fileSHA256(name string) string {
	f, err := os.Open(name)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func detectKitPlatforms(name string) []string {
	f, err := os.Open(name)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	for _, zf := range zr.File {
		lower := strings.ToLower(zf.Name)
		if strings.HasSuffix(lower, ".msi") || strings.HasSuffix(lower, ".exe") || strings.Contains(lower, "windows") {
			seen["windows"] = true
		}
		if strings.HasSuffix(lower, ".rpm") || strings.HasSuffix(lower, ".deb") || strings.Contains(lower, "linux") || strings.HasSuffix(lower, ".sh") {
			seen["linux"] = true
		}
	}
	platforms := make([]string, 0, len(seen))
	for _, p := range []string{"windows", "linux", "unix"} {
		if seen[p] {
			platforms = append(platforms, p)
		}
	}
	if len(platforms) == 0 {
		// VBR may use opaque artifact names. Imported Kits are treated as the
		// public combined default unless their archive explicitly identifies a
		// narrower platform set.
		platforms = []string{"windows", "linux"}
	}
	return platforms
}

// Active returns the current campaign (nil if none).
func (m *Manager) Active() *Campaign {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

// swapActive installs camp as the single active campaign. If a prior campaign
// existed it is invalidated (closed) and the caller is told via the return flag.
func (m *Manager) swapActive(camp *Campaign) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := m.active
	m.active = camp
	if prev != nil {
		_ = prev.Close() // invalidate unpaired temp certs + remove old bytes
		return true
	}
	return false
}

// writeKit copies a kit stream into a fresh protected temp file (0o600) kept
// in Veeam's original ZIP format — the ".zip" name and the untouched bytes are
// the operator-facing contract (the kit is never repackaged). The ZIP magic is
// verified here so a non-ZIP upload fails immediately with an actionable error
// instead of surfacing at push time. The file is the ONLY place kit bytes live;
// logs never contain its contents (AB-FR-066).
func (m *Manager) writeKit(r io.Reader) (string, error) {
	f, err := os.CreateTemp(m.rootDir, "kit-*.zip")
	if err != nil {
		return "", err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	// Sniff the ZIP magic ("PK\x03\x04" etc.) before committing the bytes.
	head := make([]byte, 4)
	n, err := io.ReadFull(r, head)
	if err != nil || !bytes.HasPrefix(head[:n], []byte("PK")) {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("deploymentkit: write kit: not a Deployment Kit archive (expected the ZIP generated/downloaded from VBR)")
	}
	if _, err := io.Copy(f, io.MultiReader(bytes.NewReader(head[:n]), r)); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("deploymentkit: write kit: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func randID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
