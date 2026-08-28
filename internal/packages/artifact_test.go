package packages

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Coku2015/agentbridge/internal/vbr"
)

type fakePackageDownloader struct {
	archive  []byte
	archives map[string][]byte
	closed   bool
	request  vbr.PackageRequest
	requests []vbr.PackageRequest
}

func (f *fakePackageDownloader) DownloadAgentPackages(_ context.Context, req vbr.PackageRequest) (io.ReadCloser, error) {
	f.request = req
	f.requests = append(f.requests, req)
	archive := f.archive
	if len(req.PackageNames) > 0 && f.archives != nil {
		archive = f.archives[req.PackageNames[0]]
	}
	return &trackedReader{Reader: bytes.NewReader(archive), closeFn: func() { f.closed = true }}, nil
}

type trackedReader struct {
	*bytes.Reader
	closeFn func()
}

func (r *trackedReader) Close() error {
	r.closeFn()
	return nil
}

func TestArtifactStoreExtractsOnlyRPMFromZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range map[string]string{
		"agent.xml":              "temporary PG metadata",
		"README-install.txt":     "operator notes",
		"payload/veeamagent.rpm": "rpm-bytes",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(data))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	d := &fakePackageDownloader{archive: buf.Bytes()}
	root := t.TempDir()
	store, err := NewArtifactStore(root)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := store.Download(context.Background(), d, "Ubuntu 24.04 x64 - 13.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !d.closed {
		t.Fatal("package stream must be closed so the temporary PG can be removed")
	}
	if artifact.Format != "rpm" || artifact.FileName != "veeamagent.rpm" || artifact.Size != int64(len("rpm-bytes")) {
		t.Fatalf("artifact = %+v", artifact)
	}
	got, err := os.ReadFile(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "rpm-bytes" {
		t.Fatalf("artifact bytes = %q", got)
	}
	if artifact.SHA256 == "" || d.request.Format != "Zip" || len(d.request.PackageNames) != 1 {
		t.Fatalf("request/artifact metadata = %+v / %+v", d.request, artifact)
	}
}

func TestArtifactStoreReportsInvalidVBRArchiveWithoutLeakingTechnicalDetail(t *testing.T) {
	store, err := NewArtifactStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Download(context.Background(), &fakePackageDownloader{archive: []byte("not-an-archive")}, "Red Hat 7 x64")
	if !errors.Is(err, ErrInvalidVBRArchive) {
		t.Fatalf("error = %v, want ErrInvalidVBRArchive", err)
	}
	if strings.Contains(err.Error(), "zip=") || strings.Contains(err.Error(), "tar=") {
		t.Fatalf("public error leaked decoder details: %v", err)
	}
	diagnostic := ArchiveDiagnostic(err)
	if !strings.Contains(diagnostic, "received_bytes=14") || !strings.Contains(diagnostic, "signature=6e6f742d616e2d61726368697665") || !strings.Contains(diagnostic, "zip=") || !strings.Contains(diagnostic, "tar=") {
		t.Fatalf("diagnostic = %q", diagnostic)
	}
}

func TestArtifactStoreAcceptsWindowsSeparatorsFromVBRZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(`Linux\Red Hat 7 x64 - 13.1.0.252\veeam-13.1.0.252-1.el7.x86_64.rpm`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("rpm-bytes")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := NewArtifactStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := store.Download(context.Background(), &fakePackageDownloader{archive: buf.Bytes()}, "Red Hat 7 x64 - 13.1.0.252")
	if err != nil {
		t.Fatal(err)
	}
	if artifact.FileName != "veeam-13.1.0.252-1.el7.x86_64.rpm" || artifact.Format != "rpm" {
		t.Fatalf("artifact = %+v", artifact)
	}
}

func TestSafeArchiveNameRejectsWindowsTraversalAndAbsolutePaths(t *testing.T) {
	for _, name := range []string{
		`..\evil.rpm`,
		`Linux\..\evil.rpm`,
		`C:\Windows\Temp\evil.rpm`,
		`\\server\share\evil.rpm`,
		`/absolute/evil.rpm`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := safeArchiveName(name); err == nil {
				t.Fatalf("safeArchiveName(%q) unexpectedly succeeded", name)
			}
		})
	}
}

func TestArtifactStoreExtractsDebFromTarGz(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	data := []byte("deb-bytes")
	if err := tw.WriteHeader(&tar.Header{Name: "veeamagent.deb", Mode: 0o644, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := NewArtifactStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := store.Download(context.Background(), &fakePackageDownloader{archive: buf.Bytes()}, "Ubuntu 24.04 x64 - 13.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Format != "deb" {
		t.Fatalf("format = %q", artifact.Format)
	}
}

func TestArtifactStorePreservesMultiplePayloadsAsPackageSet(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"a.rpm", "b.rpm"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte("payload"))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := NewArtifactStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := store.Download(context.Background(), &fakePackageDownloader{archive: buf.Bytes()}, "multiple")
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Format != "package-set" || len(artifact.Payloads) != 2 {
		t.Fatalf("package set artifact = %+v", artifact)
	}
	setBytes, err := os.ReadFile(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := packageEntries(setBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].name != "a.rpm" || entries[1].name != "b.rpm" {
		t.Fatalf("package set entries = %+v", entries)
	}
	f, err := os.Open(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	setGzip, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer setGzip.Close()
	setTar := tar.NewReader(setGzip)
	for {
		hdr, err := setTar.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !hdr.ModTime.Equal(packageArchiveModTime) || hdr.ModTime.Before(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)) {
			t.Fatalf("member %s modtime = %s", hdr.Name, hdr.ModTime)
		}
	}
}

func TestArtifactStoreDownloadsManyPackagesSeparately(t *testing.T) {
	makeArchive := func(name, data string) []byte {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(data))
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	d := &fakePackageDownloader{archives: map[string][]byte{
		"RHEL 7 x64":       makeArchive("rhel/veeamagent.rpm", "rpm-bytes"),
		"Ubuntu 24.04 x64": makeArchive("ubuntu/veeamagent.deb", "deb-bytes"),
	}}
	store, err := NewArtifactStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := store.DownloadMany(context.Background(), d, []string{"RHEL 7 x64", "Ubuntu 24.04 x64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 2 || len(d.requests) != 2 || !d.closed {
		t.Fatalf("artifacts=%+v requests=%+v closed=%v", artifacts, d.requests, d.closed)
	}
	if artifacts[0].PackageName != "RHEL 7 x64" || artifacts[1].PackageName != "Ubuntu 24.04 x64" {
		t.Fatalf("package mapping = %+v", artifacts)
	}
	if len(d.requests[0].PackageNames) != 1 || len(d.requests[1].PackageNames) != 1 {
		t.Fatalf("request grouping = %+v", d.requests)
	}
}
