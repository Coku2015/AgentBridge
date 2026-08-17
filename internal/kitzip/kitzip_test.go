package kitzip

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildZip writes an in-memory ZIP with the given flat entries.
func buildZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"a.rpm", "install-deployment-kit.sh", "server-cert.pem"} {
		if body, ok := entries[name]; ok {
			w, err := zw.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// kitZip is a minimal valid kit archive.
func kitZip(t *testing.T) []byte {
	t.Helper()
	return buildZip(t, map[string]string{
		"install-deployment-kit.sh": "#!/bin/bash\nexit 0\n",
		"a.rpm":                     "RPM-BYTES",
		"server-cert.pem":           "CERT",
	})
}

func TestExtractReturnsSortedFiles(t *testing.T) {
	files, err := Extract(bytes.NewReader(kitZip(t)))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	var names []string
	for _, f := range files {
		names = append(names, f.Name)
	}
	want := []string{"a.rpm", "install-deployment-kit.sh", "server-cert.pem"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("files = %v, want %v (must be sorted)", names, want)
	}
	for _, f := range files {
		if f.Name == "a.rpm" && string(f.Data) != "RPM-BYTES" {
			t.Fatalf("a.rpm content = %q", f.Data)
		}
	}
}

// The exit-126 root cause: executing the archive as a shell script. Extract
// must reject non-ZIP input with an actionable message instead.
func TestExtractRejectsNonZip(t *testing.T) {
	_, err := Extract(strings.NewReader("#!/bin/sh\nnot a zip"))
	if err == nil || !strings.Contains(err.Error(), "not a Deployment Kit archive") {
		t.Fatalf("err = %v, want 'not a Deployment Kit archive'", err)
	}
}

func TestExtractRequiresOfficialInstaller(t *testing.T) {
	_, err := Extract(bytes.NewReader(buildZip(t, map[string]string{"a.rpm": "RPM"})))
	if err == nil || !strings.Contains(err.Error(), InstallerName) {
		t.Fatalf("err = %v, want missing %s", err, InstallerName)
	}
}

func TestExtractRejectsUnsafeEntryNames(t *testing.T) {
	for _, name := range []string{"../evil.sh", "/abs/evil.sh", `back\slash.sh`, ""} {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte("x"))
		_ = zw.Close()
		if _, err := Extract(bytes.NewReader(buf.Bytes())); err == nil {
			t.Fatalf("entry %q must be rejected", name)
		}
	}
}

// The real-world proof: extract the official kit layout (flat files, exactly
// what VBR ships) with directory entries interleaved, as some unzip tools
// produce when re-packing.
func TestExtractHandlesDirEntriesAndRealLayout(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"Certificates/", "Certificates/client-cert.pem", "Linux/", "Linux/veeamdeployment.rpm", "install-deployment-kit.sh", "ReadMe.txt"} {
		if strings.HasSuffix(name, "/") {
			if _, err := zw.Create(name); err != nil {
				t.Fatal(err)
			}
			continue
		}
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("BODY-" + name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	kit := filepath.Join(dir, "kit.bin")
	if err := os.WriteFile(kit, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(kit)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	files, err := Extract(f)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	got := map[string]string{}
	for _, fl := range files {
		got[fl.Name] = string(fl.Data)
	}
	if got["Linux/veeamdeployment.rpm"] != "BODY-Linux/veeamdeployment.rpm" {
		t.Fatalf("nested entry lost: %+v", got)
	}
	if _, ok := got["install-deployment-kit.sh"]; !ok {
		t.Fatalf("installer missing: %+v", got)
	}
	if _, ok := got["Certificates/"]; ok {
		t.Fatalf("dir entry must be skipped: %+v", got)
	}
}
