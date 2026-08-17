package packages

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Coku2015/agentbridge/internal/vbr"
)

const maxAgentPackageArchiveBytes = 1 << 30 // 1 GiB safety bound for VBR exports.

// packageArchiveModTime preserves deterministic package-set archives while
// avoiding GNU tar's warning for epoch-zero timestamps on older Linux hosts.
var packageArchiveModTime = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

// PackageDownloader is the narrow VBR capability needed by the artifact
// store. The REST implementation creates and removes the temporary package
// source Protection Group around the returned stream.
type PackageDownloader interface {
	DownloadAgentPackages(ctx context.Context, request vbr.PackageRequest) (io.ReadCloser, error)
}

// Payload describes one RPM/DEB inside a VBR package export. A single catalog
// selection can legitimately contain several payloads (the Agent plus its
// platform-specific dependencies), so an Artifact may represent a package set.
type Payload struct {
	FileName string `json:"fileName"`
	Format   string `json:"format"`
	Role     string `json:"role,omitempty"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

// Artifact is the locally cached install payload for one catalog selection.
// XML/readme files that VBR includes for the PreInstalledAgents workflow never
// reach the artifact path. When VBR returns multiple RPM/DEB files, Path points
// to a small AgentBridge-owned tar.gz containing that complete package set.
type Artifact struct {
	Path        string    `json:"path"`
	PackageName string    `json:"packageName"`
	FileName    string    `json:"fileName"`
	Format      string    `json:"format"`
	Size        int64     `json:"size"`
	SHA256      string    `json:"sha256"`
	Payloads    []Payload `json:"payloads,omitempty"`
}

// ArtifactStore keeps downloaded Agent packages in a protected local cache.
// The VBR adapter remains responsible for remote temporary-PG cleanup; this
// store only owns the extracted package file.
type ArtifactStore struct{ rootDir string }

// NewArtifactStore creates a protected package cache directory.
func NewArtifactStore(rootDir string) (*ArtifactStore, error) {
	if err := os.MkdirAll(rootDir, 0o700); err != nil {
		return nil, fmt.Errorf("packages: create cache: %w", err)
	}
	return &ArtifactStore{rootDir: rootDir}, nil
}

// Download retrieves one selected package from VBR. It is kept as a convenience
// wrapper for callers that need a single artifact; the HTTP batch path uses
// DownloadMany so a single selection follows the same complete package-set
// path as the batch endpoint.
func (s *ArtifactStore) Download(ctx context.Context, d PackageDownloader, packageName string) (Artifact, error) {
	packageName = strings.TrimSpace(packageName)
	if packageName == "" {
		return Artifact{}, fmt.Errorf("packages: package name is required")
	}
	artifacts, err := s.DownloadMany(ctx, d, []string{packageName})
	if err != nil {
		return Artifact{}, err
	}
	return artifacts[0], nil
}

// DownloadMany retrieves all selected catalog packages. Each selection is
// exported separately so VBR's multiple RPM/DEB payloads remain associated with
// the selection that produced them; combining multiple distributions into one
// install set would be unsafe. XML/readme metadata is discarded before writing
// each package set to the protected local cache.
func (s *ArtifactStore) DownloadMany(ctx context.Context, d PackageDownloader, packageNames []string) ([]Artifact, error) {
	names := make([]string, 0, len(packageNames))
	seen := make(map[string]struct{}, len(packageNames))
	for _, rawName := range packageNames {
		name := strings.TrimSpace(rawName)
		if name == "" {
			return nil, fmt.Errorf("packages: package name is required")
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("packages: at least one package name is required")
	}
	artifacts := make([]Artifact, 0, len(names))
	for _, name := range names {
		body, err := d.DownloadAgentPackages(ctx, vbr.PackageRequest{
			PackageNames: []string{name},
			Format:       "Tar",
		})
		if err != nil {
			for _, previous := range artifacts {
				_ = os.Remove(previous.Path)
			}
			return nil, fmt.Errorf("packages: download %q: %w", name, err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(body, maxAgentPackageArchiveBytes+1))
		closeErr := body.Close()
		if readErr != nil {
			for _, previous := range artifacts {
				_ = os.Remove(previous.Path)
			}
			return nil, fmt.Errorf("packages: read %q: %w", name, readErr)
		}
		if closeErr != nil {
			for _, previous := range artifacts {
				_ = os.Remove(previous.Path)
			}
			return nil, fmt.Errorf("packages: clean up temporary source for %q: %w", name, closeErr)
		}
		if len(raw) > maxAgentPackageArchiveBytes {
			for _, previous := range artifacts {
				_ = os.Remove(previous.Path)
			}
			return nil, fmt.Errorf("packages: archive for %q exceeds %d bytes", name, maxAgentPackageArchiveBytes)
		}

		entries, err := packageEntries(raw)
		if err != nil {
			for _, previous := range artifacts {
				_ = os.Remove(previous.Path)
			}
			return nil, fmt.Errorf("packages: parse VBR archive for %q: %w", name, err)
		}
		if len(entries) == 0 {
			for _, previous := range artifacts {
				_ = os.Remove(previous.Path)
			}
			return nil, fmt.Errorf("packages: VBR archive for %q contains no RPM/DEB payloads", name)
		}

		artifact, err := s.writePayloads(entries, name)
		if err != nil {
			for _, previous := range artifacts {
				_ = os.Remove(previous.Path)
			}
			return nil, err
		}
		artifacts = append(artifacts, artifact)
	}
	return artifacts, nil
}

func (s *ArtifactStore) writePayloads(entries []packageEntry, packageName string) (Artifact, error) {
	if len(entries) == 1 {
		return s.writeArtifact(entries[0], packageName)
	}
	return s.writePackageSet(entries, packageName)
}
func (s *ArtifactStore) writeArtifact(entry packageEntry, packageName string) (Artifact, error) {
	ext := strings.ToLower(filepath.Ext(entry.name))
	file, err := os.CreateTemp(s.rootDir, "agent-*"+ext)
	if err != nil {
		return Artifact{}, fmt.Errorf("packages: create artifact: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return Artifact{}, fmt.Errorf("packages: protect artifact: %w", err)
	}
	if _, err := file.Write(entry.data); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return Artifact{}, fmt.Errorf("packages: write artifact: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(file.Name())
		return Artifact{}, fmt.Errorf("packages: close artifact: %w", err)
	}
	h := sha256.Sum256(entry.data)
	return Artifact{
		Path:        file.Name(),
		PackageName: packageName,
		FileName:    filepath.Base(entry.name),
		Format:      strings.TrimPrefix(ext, "."),
		Size:        int64(len(entry.data)),
		SHA256:      hex.EncodeToString(h[:]),
	}, nil
}

func (s *ArtifactStore) writePackageSet(entries []packageEntry, packageName string) (Artifact, error) {
	entries = append([]packageEntry(nil), entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	file, err := os.CreateTemp(s.rootDir, "agent-set-*.tar.gz")
	if err != nil {
		return Artifact{}, fmt.Errorf("packages: create package set: %w", err)
	}
	path := file.Name()
	removeOnError := func(cause error) (Artifact, error) {
		_ = file.Close()
		_ = os.Remove(path)
		return Artifact{}, cause
	}
	if err := file.Chmod(0o600); err != nil {
		return removeOnError(fmt.Errorf("packages: protect package set: %w", err))
	}
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		hdr := &tar.Header{Name: entry.name, Mode: 0o644, Size: int64(len(entry.data)), ModTime: packageArchiveModTime}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return removeOnError(fmt.Errorf("packages: write package set header %q: %w", entry.name, err))
		}
		if _, err := tw.Write(entry.data); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return removeOnError(fmt.Errorf("packages: write package set %q: %w", entry.name, err))
		}
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return removeOnError(fmt.Errorf("packages: close package set tar: %w", err))
	}
	if err := gz.Close(); err != nil {
		return removeOnError(fmt.Errorf("packages: close package set gzip: %w", err))
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return Artifact{}, fmt.Errorf("packages: close package set: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		_ = os.Remove(path)
		return Artifact{}, fmt.Errorf("packages: stat package set: %w", err)
	}
	hash, err := fileSHA256(path)
	if err != nil {
		_ = os.Remove(path)
		return Artifact{}, fmt.Errorf("packages: hash package set: %w", err)
	}
	payloads := make([]Payload, 0, len(entries))
	for _, entry := range entries {
		ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(entry.name)), ".")
		sum := sha256.Sum256(entry.data)
		payloads = append(payloads, Payload{
			FileName: filepath.Base(entry.name),
			Format:   ext,
			Role:     packageRole(entry.name),
			Size:     int64(len(entry.data)),
			SHA256:   hex.EncodeToString(sum[:]),
		})
	}
	return Artifact{
		Path:        path,
		PackageName: packageName,
		FileName:    filepath.Base(path),
		Format:      "package-set",
		Size:        info.Size(),
		SHA256:      hash,
		Payloads:    payloads,
	}, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type packageEntry struct {
	name string
	data []byte
}

func packageEntries(raw []byte) ([]packageEntry, error) {
	if entries, err := zipEntries(raw); err == nil {
		return entries, nil
	}
	if entries, err := tarEntries(raw); err == nil {
		return entries, nil
	}
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		gz, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		decompressed, readErr := io.ReadAll(io.LimitReader(gz, maxAgentPackageArchiveBytes+1))
		_ = gz.Close()
		if readErr != nil {
			return nil, readErr
		}
		return tarEntries(decompressed)
	}
	return nil, fmt.Errorf("unsupported archive format (expected ZIP, TAR or TAR.GZ)")
}

func zipEntries(raw []byte) ([]packageEntry, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, err
	}
	var out []packageEntry
	for _, file := range zr.File {
		if file.FileInfo().IsDir() || !isAgentPackage(file.Name) {
			continue
		}
		name, err := safeArchiveName(file.Name)
		if err != nil {
			return nil, err
		}
		r, err := file.Open()
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(r, maxAgentPackageArchiveBytes+1))
		_ = r.Close()
		if readErr != nil {
			return nil, readErr
		}
		if len(data) > maxAgentPackageArchiveBytes {
			return nil, fmt.Errorf("archive entry %q exceeds %d bytes", file.Name, maxAgentPackageArchiveBytes)
		}
		out = append(out, packageEntry{name: name, data: data})
	}
	return out, nil
}

func tarEntries(raw []byte) ([]packageEntry, error) {
	tr := tar.NewReader(bytes.NewReader(raw))
	var out []packageEntry
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg || !isAgentPackage(hdr.Name) {
			continue
		}
		name, err := safeArchiveName(hdr.Name)
		if err != nil {
			return nil, err
		}
		if hdr.Size < 0 || hdr.Size > maxAgentPackageArchiveBytes {
			return nil, fmt.Errorf("archive entry %q exceeds %d bytes", hdr.Name, maxAgentPackageArchiveBytes)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxAgentPackageArchiveBytes+1))
		if err != nil {
			return nil, err
		}
		if len(data) > maxAgentPackageArchiveBytes {
			return nil, fmt.Errorf("archive entry %q exceeds %d bytes", hdr.Name, maxAgentPackageArchiveBytes)
		}
		out = append(out, packageEntry{name: name, data: data})
	}
}

func isAgentPackage(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".rpm" || ext == ".deb"
}

func safeArchiveName(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "\x00\\") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("unsafe archive entry %q", name)
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
		return "", fmt.Errorf("unsafe archive entry %q", name)
	}
	return clean, nil
}
