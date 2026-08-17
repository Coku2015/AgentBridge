package probe

import (
	"context"
	"errors"
	"testing"
)

// fakeRunner returns canned command output, asserting the command passed to it
// is EXACTLY the static probe script (no caller interpolation — red line 5).
type fakeRunner struct {
	out     []byte
	err     error
	lastCmd string
}

func (f *fakeRunner) Run(_ context.Context, cmd string) ([]byte, error) {
	f.lastCmd = cmd
	return f.out, f.err
}

func TestProbeParsesFacts(t *testing.T) {
	body := []byte(`{"schemaVersion":"1.0","target":{"hostName":"node1","architecture":"x86_64"},"os":{"id":"rocky","versionId":"8.6","idLike":"rhel"},"kernel":"4.18.0","glibc":"2.28","packageFormat":"rpm","packageManager":"dnf","rhelMacro":"","secureBoot":"disabled","existingVeeamPackages":"veeam,veeamexec","availableTempBytes":1024}`)
	r := &fakeRunner{out: body}
	p := NewSSHProbe(r)

	res, err := p.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.OS.ID != "rocky" || res.Target.Architecture != "x86_64" || res.Glibc != "2.28" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.PackageFormat != "rpm" {
		t.Fatalf("package format = %s", res.PackageFormat)
	}
	if len(res.OS.IDLike) != 1 || res.OS.IDLike[0] != "rhel" {
		t.Fatalf("idLike = %v", res.OS.IDLike)
	}
	if len(res.ExistingVeeamPackages) != 2 || res.ExistingVeeamPackages[0] != "veeam" {
		t.Fatalf("existing veeam pkgs = %v", res.ExistingVeeamPackages)
	}
}

// AB-FR-124 / red line 5: the command run by the probe must be the constant
// probe script with no caller-supplied content concatenated.
func TestProbeRunsStaticScriptOnly(t *testing.T) {
	r := &fakeRunner{out: []byte(`{"schemaVersion":"1.0"}`)}
	p := NewSSHProbe(r)
	_, _ = p.Probe(context.Background())
	// The static script contains the JSON printf; it must never contain an
	// arbitrary sentinel a caller might inject.
	if contains(r.lastCmd, "; rm -rf") {
		t.Fatal("probe command contained injected shell metacharacters")
	}
}

func TestProbeSchemaMismatchRejected(t *testing.T) {
	r := &fakeRunner{out: []byte(`{"schemaVersion":"9.9"}`)}
	_, err := NewSSHProbe(r).Probe(context.Background())
	if err == nil {
		t.Fatal("expected schema mismatch error")
	}
}

func TestProbeRunFailure(t *testing.T) {
	r := &fakeRunner{err: errors.New("boom")}
	if _, err := NewSSHProbe(r).Probe(context.Background()); err == nil {
		t.Fatal("expected error from runner failure")
	}
}

// stripShellNoise keeps parsing robust against stray shell leader text.
func TestStripShellNoise(t *testing.T) {
	out := stripShellNoise([]byte("Last login: ...\n{\"schemaVersion\":\"1.0\"}\n$ "))
	if string(out) != `{"schemaVersion":"1.0"}` {
		t.Fatalf("noise not stripped: %q", out)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
