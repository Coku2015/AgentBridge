package vbr

import (
	"encoding/json"
	"testing"
	"time"
)

func TestServerInfoJSON(t *testing.T) {
	// Full form: version + host + server time. The REST revision is internal and
	// must not leak into the operator-facing JSON response.
	tm := time.Date(2026, 8, 15, 8, 30, 0, 0, time.UTC)
	in := ServerInfo{ProductVersion: "13.1.1.18", Host: "vbr.corp.local", ServerTime: &tm, APIRevision: APIRevisionBaseline}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"productVersion":"13.1.1.18","host":"vbr.corp.local","serverTime":"2026-08-15T08:30:00Z"}`
	if string(raw) != want {
		t.Fatalf("serverinfo json = %s, want %s", raw, want)
	}
	var out ServerInfo
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.ProductVersion != in.ProductVersion || out.Host != in.Host || out.APIRevision != "" || out.ServerTime == nil || !out.ServerTime.Equal(tm) {
		t.Fatalf("round-trip mismatch: %+v vs %+v", out, in)
	}

	// Degraded form: serverTime endpoint unavailable → field omitted entirely.
	lean := ServerInfo{ProductVersion: "13.1.1.18", Host: "vbr.corp.local", APIRevision: APIRevisionBaseline}
	rawLean, err := json.Marshal(lean)
	if err != nil {
		t.Fatalf("marshal lean: %v", err)
	}
	if stringsContains(string(rawLean), "serverTime") {
		t.Fatalf("lean serverinfo must omit serverTime, got %s", rawLean)
	}
}

func TestCapabilitiesJSON(t *testing.T) {
	in := Capabilities{AgentPackages: true, DeploymentKit: true, ProtectionGroup: false}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Capabilities
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.AgentPackages != true || out.DeploymentKit != true || out.ProtectionGroup != false {
		t.Fatalf("capabilities round-trip mismatch: %+v", out)
	}
}

func TestAgentPackageJSON(t *testing.T) {
	in := AgentPackage{Name: "veeamagent", Distribution: "rhel", Architecture: "x64"}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"packageName":"veeamagent","distributionName":"rhel","packageBitness":"x64"}`
	if string(raw) != want {
		t.Fatalf("package json = %s, want %s", raw, want)
	}
	var out AgentPackage
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("package round-trip mismatch: %+v vs %+v", out, in)
	}
}

func TestConnectionConfigRequiresPin(t *testing.T) {
	// ConnectionConfig carries no secret fields; only the non-secret pin.
	cfg := ConnectionConfig{Server: "vbr", Port: 9419, Username: "admin", PinnedTLSSHA256: "AB:CD"}
	if cfg.PinnedTLSSHA256 == "" {
		t.Fatal("pin should be settable")
	}
	raw, _ := json.Marshal(cfg)
	if stringsContains(string(raw), "password") || stringsContains(string(raw), "token") {
		t.Fatalf("ConnectionConfig leaked secret-looking field: %s", raw)
	}
}

// stringsContains avoids importing strings just for one check.
func stringsContains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
