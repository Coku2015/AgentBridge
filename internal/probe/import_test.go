package probe

import (
	"testing"
)

func TestImportValidResult(t *testing.T) {
	raw := []byte(`{
		"schemaVersion":"1.0",
		"target":{"hostName":"node-1","architecture":"x86_64"},
		"os":{"id":"rocky","versionId":"8.6","idLike":["rhel"]},
		"kernel":"4.18.0","glibc":"2.28","packageFormat":"rpm",
		"packageManager":"dnf","rhelMacro":"x86_64-redhat-linux",
		"secureBoot":"disabled","existingVeeamPackages":[],
		"availableTempBytes":1048576
	}`)
	r, err := Import(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r.OS.ID != "rocky" {
		t.Fatalf("os id = %s", r.OS.ID)
	}
	if r.Target.Architecture != "x86_64" {
		t.Fatalf("arch = %s", r.Target.Architecture)
	}
}

func TestImportSchemaMismatch(t *testing.T) {
	raw := []byte(`{"schemaVersion":"9.9","target":{},"os":{}}`)
	if _, err := Import(raw); err == nil {
		t.Fatal("expected schema mismatch error")
	}
}

func TestImportMalformed(t *testing.T) {
	if _, err := Import([]byte("not json at all")); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestImportStripsShellNoise(t *testing.T) {
	raw := []byte("bash: line 1: foo: command not found\n" + `{"schemaVersion":"1.0","target":{"hostName":"x"},"os":{}}` + "\nPS1$")
	r, err := Import(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r.Target.HostName != "x" {
		t.Fatalf("host = %s", r.Target.HostName)
	}
}
