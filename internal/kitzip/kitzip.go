package kitzip

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// InstallerName is the official VBR installer entry every kit archive carries.
const InstallerName = "install-deployment-kit.sh"

// maxKitBytes bounds a kit archive in memory (real kits are ~30 MB; this only
// stops an absurd input from exhausting memory).
const maxKitBytes = 1 << 30 // 1 GiB

// File is one extracted kit payload file.
type File struct {
	Name string // slash-separated, relative, validated
	Data []byte
}

// Extract reads a Deployment Kit ZIP from r and returns its payload files,
// sorted by name. It rejects non-ZIP input (the classic exit-126 mistake is
// executing the archive as a shell script), unsafe entry names (absolute,
// traversal, backslash) and kits missing the official installer.
func Extract(r io.Reader) ([]File, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxKitBytes+1))
	if err != nil {
		return nil, fmt.Errorf("kitzip: read kit: %w", err)
	}
	if len(raw) > maxKitBytes {
		return nil, fmt.Errorf("kitzip: kit exceeds %d bytes", maxKitBytes)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("kitzip: not a Deployment Kit archive (expected the ZIP generated/downloaded from VBR): %w", err)
	}

	var files []File
	seen := map[string]bool{}
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		name, err := safeName(zf.Name)
		if err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, fmt.Errorf("kitzip: duplicate entry %q", name)
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, fmt.Errorf("kitzip: open %s: %w", zf.Name, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("kitzip: read %s: %w", zf.Name, err)
		}
		seen[name] = true
		files = append(files, File{Name: name, Data: data})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	if !seen[InstallerName] {
		return nil, fmt.Errorf("kitzip: kit archive carries no %s — not a VBR Deployment Kit", InstallerName)
	}
	return files, nil
}

// safeName validates a ZIP entry name and normalizes it to a clean relative
// slash-separated path. VBR kits are flat; nested names are tolerated, but
// absolute paths, traversal and backslashes are rejected before anything is
// staged to disk or a remote host.
func safeName(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "\x00\\") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("kitzip: unsafe entry name %q", name)
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
		return "", fmt.Errorf("kitzip: unsafe entry name %q", name)
	}
	return clean, nil
}
