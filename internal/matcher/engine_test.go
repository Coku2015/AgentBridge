package matcher

import "testing"

func TestEngineParsesEmbeddedMatrix(t *testing.T) {
	e, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if e.MatrixVersion() != "2.1" {
		t.Fatalf("version = %q, want 2.1", e.MatrixVersion())
	}
}

func TestMatchVendorSupported(t *testing.T) {
	e := mustEngine(t)
	rec, level, err := e.Match(Input{
		PackageFormat: "rpm",
		Architecture:  "x86_64",
		ID:            "rocky",
		VersionID:     "8.6",
		IDLike:        []string{"rhel"},
		Glibc:         "2.28",
	})
	if err != nil {
		t.Fatal(err)
	}
	if level != VendorSupported {
		t.Fatalf("level = %s, want VendorSupported", level)
	}
	if rec.RecommendedPackageID != "rhel8-x86_64" {
		t.Fatalf("package = %s", rec.RecommendedPackageID)
	}
	if rec.Confidence != "high" {
		t.Fatalf("confidence = %s, want high", rec.Confidence)
	}
	if rec.RequiresExplicitConfirmation {
		t.Fatal("official match must not require explicit confirmation")
	}
}

// AB-FR-103: an upstream-family inference MUST require confirmation and MUST
// NOT be labelled VendorSupported.
func TestMatchCompatibilityInferenceRequiresConfirmation(t *testing.T) {
	e := mustEngine(t)
	rec, level, err := e.Match(Input{
		PackageFormat: "rpm",
		Architecture:  "x86_64",
		ID:            "kylin",
		VersionID:     "V10",
		Glibc:         "2.28",
	})
	if err != nil {
		t.Fatal(err)
	}
	if level != CompatibilityInferred {
		t.Fatalf("level = %s, want CompatibilityInferred", level)
	}
	if level == VendorSupported {
		t.Fatal("LabValidated must never surface as VendorSupported (red line 11)")
	}
	if !rec.RequiresExplicitConfirmation {
		t.Fatal("inferred match must require explicit confirmation (AB-FR-103)")
	}
	if rec.RecommendedPackageID != "rhel10-x86_64" {
		t.Fatalf("inferred package = %s, want rhel10-x86_64", rec.RecommendedPackageID)
	}
}

// IDLike fallback: kylin via idLike rhel still resolves to an inferred
// compatibility profile, NOT the VendorSupported rhel rule (no support-lie).
func TestMatchIDLikeDoesNotUpgradeLevel(t *testing.T) {
	e := mustEngine(t)
	_, level, _ := e.Match(Input{
		PackageFormat: "rpm",
		Architecture:  "x86_64",
		ID:            "kylin",
		IDLike:        []string{"rhel"},
		Glibc:         "2.28",
	})
	if level != CompatibilityInferred {
		t.Fatalf("level = %s, want CompatibilityInferred (must not upgrade to VendorSupported via idLike)", level)
	}
}

func TestMatchExistingAgentRequiresConfirmation(t *testing.T) {
	e := mustEngine(t)
	rec, level, _ := e.Match(Input{
		PackageFormat: "rpm",
		Architecture:  "x86_64",
		ID:            "rhel",
		VersionID:     "8.6",
		Glibc:         "2.28",
		ExistingAgent: true,
	})
	if level != VendorSupported {
		t.Fatalf("level = %s", level)
	}
	if !rec.RequiresExplicitConfirmation {
		t.Fatal("existing agent must require confirmation (destructive reinstall)")
	}
}

func TestMatchCentOS7UsesRHEL7CompatibilityProfile(t *testing.T) {
	e := mustEngine(t)
	rec, level, err := e.Match(Input{
		PackageFormat: "rpm",
		Architecture:  "x86_64",
		ID:            "centos",
		VersionID:     "7.9",
		Glibc:         "2.17",
	})
	if err != nil {
		t.Fatal(err)
	}
	if level != CompatibilityInferred || !rec.RequiresExplicitConfirmation {
		t.Fatalf("CentOS 7 match = level %s confirmation=%v", level, rec.RequiresExplicitConfirmation)
	}
	if rec.RecommendedPackageID != "rhel7-x86_64" {
		t.Fatalf("CentOS 7 package = %s, want rhel7-x86_64", rec.RecommendedPackageID)
	}
}

func TestMatchUbuntu22UsesDebianPackageFamily(t *testing.T) {
	e := mustEngine(t)
	rec, level, err := e.Match(Input{
		PackageFormat: "deb",
		Architecture:  "x86_64",
		ID:            "ubuntu",
		VersionID:     "22.04",
		Glibc:         "2.35",
	})
	if err != nil {
		t.Fatal(err)
	}
	if level != VendorSupported || rec.RecommendedPackageID != "debian-x86_64" {
		t.Fatalf("Ubuntu 22 match = level %s package %s", level, rec.RecommendedPackageID)
	}
}

func TestMatchPowerUsesNosnapRepositoryProfile(t *testing.T) {
	e := mustEngine(t)
	rec, level, err := e.Match(Input{
		PackageFormat: "rpm",
		Architecture:  "ppc64le",
		ID:            "rhel",
		VersionID:     "9.8",
	})
	if err != nil {
		t.Fatal(err)
	}
	if level != VendorSupported || rec.RecommendedPackageID != "rhel9-ppc64le" || rec.PackageMode != "nosnap" {
		t.Fatalf("Power match = level %s package %s mode %s", level, rec.RecommendedPackageID, rec.PackageMode)
	}
}

func TestMatchAarch64IsBlockedByCurrentAgentRepository(t *testing.T) {
	e := mustEngine(t)
	rec, level, err := e.Match(Input{
		PackageFormat: "rpm",
		Architecture:  "aarch64",
		ID:            "rhel",
		VersionID:     "9.8",
	})
	if err != nil {
		t.Fatal(err)
	}
	if level != Blocked || rec.RecommendedPackageID != "" {
		t.Fatalf("aarch64 match = level %s package %s", level, rec.RecommendedPackageID)
	}
}

func TestMatchAlpineIsBlocked(t *testing.T) {
	e := mustEngine(t)
	_, level, _ := e.Match(Input{
		PackageFormat: "unknown",
		Architecture:  "x86_64",
		ID:            "alpine",
	})
	if level != Blocked {
		t.Fatalf("Alpine level = %s, want Blocked", level)
	}
}

func TestMatchBlockedArchitecture(t *testing.T) {
	e := mustEngine(t)
	_, level, _ := e.Match(Input{
		PackageFormat: "rpm",
		Architecture:  "mips64",
		ID:            "rocky",
		Glibc:         "2.28",
	})
	if level != Blocked {
		t.Fatalf("level = %s, want Blocked", level)
	}
}

func TestMatchBlockedPackageFormat(t *testing.T) {
	e := mustEngine(t)
	_, level, _ := e.Match(Input{
		PackageFormat: "tar",
		Architecture:  "x86_64",
		ID:            "rocky",
		Glibc:         "2.28",
	})
	if level != Blocked {
		t.Fatalf("level = %s, want Blocked", level)
	}
}

func TestMatchBlockedUnknownOS(t *testing.T) {
	e := mustEngine(t)
	rec, level, _ := e.Match(Input{
		PackageFormat: "rpm",
		Architecture:  "x86_64",
		ID:            "totally-unknown-distro",
		Glibc:         "2.28",
	})
	if level != Blocked {
		t.Fatalf("level = %s, want Blocked for unknown OS", level)
	}
	if rec.RecommendedPackageID != "" {
		t.Fatal("blocked match must not recommend a package")
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.28", "2.28", 0},
		{"2.28", "2.17", 1},
		{"2.17", "2.28", -1},
		{"2.28.1", "2.28", 1},
		{"2.28", "2.28.1", -1},
	}
	for _, c := range cases {
		got, ok := compareVersions(c.a, c.b)
		if !ok {
			t.Fatalf("compareVersions(%q,%q) not ok", c.a, c.b)
		}
		if got != c.want {
			t.Fatalf("compareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	if _, ok := compareVersions("2.x", "2.28"); ok {
		t.Fatal("non-numeric version should be not-ok")
	}
}

// Determinism: identical inputs must yield identical outputs (AB-NFR-008).
func TestMatchDeterministic(t *testing.T) {
	e := mustEngine(t)
	in := Input{PackageFormat: "rpm", Architecture: "x86_64", ID: "rocky", Glibc: "2.28"}
	r1, l1, _ := e.Match(in)
	r2, l2, _ := e.Match(in)
	if l1 != l2 {
		t.Fatal("level not deterministic")
	}
	if r1.RecommendedPackageID != r2.RecommendedPackageID || r1.Confidence != r2.Confidence ||
		r1.RequiresExplicitConfirmation != r2.RequiresExplicitConfirmation ||
		!equalStrings(r1.Evidence, r2.Evidence) || !equalStrings(r1.Warnings, r2.Warnings) {
		t.Fatal("recommendation not deterministic")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mustEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	return e
}
