package deploymentkit

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Coku2015/agentbridge/internal/vbr"
)

// zipKit builds a minimal valid Deployment Kit ZIP — kits are stored and kept
// in Veeam's original ZIP format, never repackaged.
func zipKit(t *testing.T, payload string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("install-deployment-kit.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type fakeGen struct {
	n    int
	body []byte
}

func (f *fakeGen) CreateDeploymentKit(_ context.Context, _ vbr.KitRequest) (vbr.TaskRef, error) {
	f.n++
	return vbr.TaskRef{ID: "task-" + strconv.Itoa(f.n)}, nil
}
func (f *fakeGen) WaitTask(_ context.Context, _ vbr.TaskRef) error { return nil }
func (f *fakeGen) DownloadDeploymentKit(_ context.Context, _ vbr.TaskRef) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(f.body)), nil
}

func newTestManager(t *testing.T, body []byte) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	m, err := NewManager(&fakeGen{body: body}, filepath.Join(dir, "kit"))
	if err != nil {
		t.Fatal(err)
	}
	return m, dir
}

// First generate: no prior campaign → invalidated=false, file on disk.
func TestGenerateFirstCampaign(t *testing.T) {
	m, _ := newTestManager(t, zipKit(t, "KIT-BYTES"))
	camp, invalidated, err := m.Generate(context.Background(), vbr.KitRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if invalidated {
		t.Fatal("first generate must not invalidate")
	}
	if camp.Source() != "generated" {
		t.Fatalf("source = %s", camp.Source())
	}
	if _, err := os.Stat(camp.Path()); err != nil {
		t.Fatalf("kit file must exist: %v", err)
	}
	if m.Active() != camp {
		t.Fatal("Active must return the new campaign")
	}
}

// Second generate invalidates the first: old bytes removed, flag set (R8/R9).
func TestGenerateInvalidatesPrior(t *testing.T) {
	m, _ := newTestManager(t, zipKit(t, "KIT-BYTES"))
	c1, _, err := m.Generate(context.Background(), vbr.KitRequest{})
	if err != nil {
		t.Fatal(err)
	}
	oldPath := c1.Path()

	c2, invalidated, err := m.Generate(context.Background(), vbr.KitRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !invalidated {
		t.Fatal("second generate must invalidate the prior campaign")
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("prior kit bytes must be removed on invalidation, got %v", err)
	}
	if c2.Path() == oldPath {
		t.Fatal("new campaign must use a new temp file")
	}
	if m.Active() != c2 {
		t.Fatal("Active must point at the newest campaign")
	}
}

// Import path (Capabilities.DeploymentKit=false): admin-supplied bytes, no generate.
func TestImportCampaign(t *testing.T) {
	m, _ := newTestManager(t, nil)
	raw := zipKit(t, "ADMIN-KIT")
	camp, invalidated, err := m.Import(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if invalidated {
		t.Fatal("import with no prior must not invalidate")
	}
	if camp.Source() != "imported" {
		t.Fatalf("source = %s, want imported", camp.Source())
	}
	// The kit is stored verbatim in Veeam's original ZIP format — byte-for-byte
	// what was supplied, under a .zip name (never a repackaged ".bin").
	if !strings.HasSuffix(camp.Path(), ".zip") {
		t.Fatalf("kit path = %s, want .zip", camp.Path())
	}
	got, err := os.ReadFile(camp.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("kit bytes must be the untouched ZIP (%d bytes), got %d", len(raw), len(got))
	}
}

// A non-ZIP stream is rejected at write time with an actionable error — kits
// are Veeam ZIP archives and must never be stored under another format.
func TestImportRejectsNonZip(t *testing.T) {
	m, _ := newTestManager(t, nil)
	if _, _, err := m.Import(bytes.NewReader([]byte("not-a-zip"))); err == nil || !strings.Contains(err.Error(), "not a Deployment Kit archive") {
		t.Fatalf("err = %v, want 'not a Deployment Kit archive'", err)
	}
}

// Import displaces an active generated campaign (invalidates it).
func TestImportInvalidatesPrior(t *testing.T) {
	m, _ := newTestManager(t, zipKit(t, "KIT-BYTES"))
	c1, _, _ := m.Generate(context.Background(), vbr.KitRequest{})
	oldPath := c1.Path()
	c2, invalidated, err := m.Import(bytes.NewReader(zipKit(t, "ADMIN-KIT")))
	if err != nil {
		t.Fatal(err)
	}
	if !invalidated {
		t.Fatal("import must invalidate prior campaign")
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatal("prior bytes must be removed")
	}
	_ = c2
}

// Close deletes the kit file and is idempotent.
func TestCampaignClose(t *testing.T) {
	m, _ := newTestManager(t, zipKit(t, "KIT-BYTES"))
	camp, _, _ := m.Generate(context.Background(), vbr.KitRequest{})
	p := camp.Path()
	if err := camp.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("Close must delete the kit file")
	}
	if err := camp.Close(); err != nil {
		t.Fatalf("Close must be idempotent: %v", err)
	}
}

// selfSignedCertPEM mints a certificate with the given NotAfter for Info tests.
func selfSignedCertPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kit-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Info lists the archive entries sorted with sizes and derives the expiry from
// the public certificate entries; key entries are listed but never parsed.
func TestInfoListsFilesAndCertExpiry(t *testing.T) {
	expiry := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	cert := selfSignedCertPEM(t, expiry)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range map[string][]byte{
		"client-cert.pem":                cert,
		"server-cert.pem":                cert,
		"server-key.pem":                 []byte("PRIVATE KEY MATERIAL"),
		"install-deployment-kit.sh":      []byte("#!/bin/bash"),
		"veeamdeployment-1.0.x86_64.rpm": bytes.Repeat([]byte("x"), 128),
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	m, _ := newTestManager(t, nil)
	camp, _, err := m.Import(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	info := camp.Info()

	wantNames := []string{
		"client-cert.pem", "install-deployment-kit.sh",
		"server-cert.pem", "server-key.pem", "veeamdeployment-1.0.x86_64.rpm",
	}
	if len(info.Files) != len(wantNames) {
		t.Fatalf("files = %v, want %v", info.Files, wantNames)
	}
	for i, wf := range wantNames {
		if info.Files[i].Name != wf {
			t.Fatalf("file[%d] = %s, want %s (sorted)", i, info.Files[i].Name, wf)
		}
	}
	if info.TotalSize != int64(len(cert)*2+len("PRIVATE KEY MATERIAL")+len("#!/bin/bash")+128) {
		t.Fatalf("totalSize = %d", info.TotalSize)
	}
	if info.ExpiresAt == nil {
		t.Fatal("expiry must be parsed from the cert entries")
	}
	if diff := info.ExpiresAt.Sub(expiry); diff < -time.Minute || diff > time.Minute {
		t.Fatalf("expiresAt = %v, want ~%v", info.ExpiresAt, expiry)
	}
}

// Info is best-effort: a kit without parseable certificates simply omits the
// expiry instead of failing.
func TestInfoWithoutCertsOmitsExpiry(t *testing.T) {
	m, _ := newTestManager(t, nil)
	camp, _, err := m.Import(bytes.NewReader(zipKit(t, "NO-CERTS")))
	if err != nil {
		t.Fatal(err)
	}
	info := camp.Info()
	if info.ExpiresAt != nil {
		t.Fatalf("expiresAt = %v, want nil", info.ExpiresAt)
	}
	if len(info.Files) != 1 || info.Files[0].Name != "install-deployment-kit.sh" {
		t.Fatalf("files = %v", info.Files)
	}
}
