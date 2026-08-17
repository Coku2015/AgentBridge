package matcher

import (
	"strings"
	"testing"
)

// AB-FR-102 / red line 11: an operator override is always allowed but MUST be
// labelled UserSelected — never re-labelled VendorSupported or LabValidated.
func TestApplyOverrideNeverUpgradesLevel(t *testing.T) {
	rec, level := ApplyOverride(Override{PackageID: "rhel8-x86_64", Reason: "lab-only host", User: "ops"}, []string{"existing evidence"})
	if level != UserSelected {
		t.Fatalf("level = %s, want UserSelected", level)
	}
	if rec.RecommendedPackageID != "rhel8-x86_64" {
		t.Fatalf("package = %s", rec.RecommendedPackageID)
	}
	if !rec.RequiresExplicitConfirmation {
		t.Fatal("override must require explicit confirmation")
	}
	joined := strings.Join(rec.Warnings, " ")
	if !strings.Contains(joined, "not vendor") {
		t.Fatalf("warnings must flag non-validated status, got %v", rec.Warnings)
	}
}

func TestApplyOverrideRecordsUser(t *testing.T) {
	rec, _ := ApplyOverride(Override{PackageID: "p1", User: "alice"}, nil)
	if !strings.Contains(strings.Join(rec.Evidence, " "), "alice") {
		t.Fatalf("evidence must record the confirming operator, got %v", rec.Evidence)
	}
}

func TestApplyOverrideUnknownOperator(t *testing.T) {
	rec, _ := ApplyOverride(Override{PackageID: "p1"}, nil)
	if !strings.Contains(strings.Join(rec.Evidence, " "), "unknown operator") {
		t.Fatalf("missing operator must be labelled unknown, got %v", rec.Evidence)
	}
}

func TestIdentityMismatchWarning(t *testing.T) {
	if w := IdentityMismatchWarning("node-1", "node-2"); w == "" {
		t.Fatal("expected a mismatch warning")
	}
	if w := IdentityMismatchWarning("node-1", "node-1"); w != "" {
		t.Fatalf("identical names must not warn, got %q", w)
	}
	if w := IdentityMismatchWarning("", "node-2"); w != "" {
		t.Fatal("empty configured side must not warn")
	}
	if w := IdentityMismatchWarning("node-1", ""); w != "" {
		t.Fatal("empty probed side must not warn")
	}
}
