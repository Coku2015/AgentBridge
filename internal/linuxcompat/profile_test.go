package linuxcompat

import "testing"

func TestResolveEnterpriseAliases(t *testing.T) {
	cases := []struct {
		id     string
		format string
		kind   Kind
		family Family
	}{
		{"rhel", "rpm", Official, RHEL},
		{"rocky", "rpm", Official, RHEL},
		{"centos", "rpm", Inferred, RHEL},
		{"openeuler", "rpm", Inferred, RHEL},
		{"anolis", "rpm", Inferred, RHEL},
		{"ubuntu", "deb", Official, Debian},
		{"linuxmint", "deb", Inferred, Debian},
		{"kali", "deb", Inferred, Debian},
		{"opensuse-leap", "rpm", Inferred, SUSE},
	}
	for _, tc := range cases {
		got := Resolve(tc.id, nil, tc.format)
		if got.Kind != tc.kind || got.Family != tc.family {
			t.Fatalf("Resolve(%q) = kind=%s family=%s, want kind=%s family=%s", tc.id, got.Kind, got.Family, tc.kind, tc.family)
		}
	}
}

func TestResolvePrimaryBeatsBroadIDLike(t *testing.T) {
	got := Resolve("fedora", []string{"rhel"}, "rpm")
	if got.Family != RPM || got.Kind != Inferred {
		t.Fatalf("fedora/rhel = %+v, want inferred generic RPM family", got)
	}
	got = Resolve("alpine", []string{"rhel"}, "rpm")
	if got.Kind != Blocked {
		t.Fatalf("alpine/rhel = %+v, want blocked", got)
	}
}

func TestResolveUOSUsesExplicitBase(t *testing.T) {
	got := Resolve("uos", []string{"debian"}, "deb")
	if got.Family != Debian || got.Kind != Inferred {
		t.Fatalf("UOS/debian = %+v, want inferred Debian family", got)
	}
	got = Resolve("uos", []string{"rhel"}, "rpm")
	if got.Family != RHEL || got.Kind != Inferred {
		t.Fatalf("UOS/rhel = %+v, want inferred RHEL family", got)
	}
}

func TestCanonicalPackageID(t *testing.T) {
	if got := CanonicalPackageID(Profile{Family: RHEL, CanonicalID: "rhel"}, "7.9", "amd64"); got != "rhel7-x86_64" {
		t.Fatalf("RHEL package id = %s", got)
	}
	if got := CanonicalPackageID(Profile{Family: Debian, CanonicalID: "ubuntu"}, "22.04", "x86_64"); got != "ubuntu22-x86_64" {
		t.Fatalf("Ubuntu package id = %s", got)
	}
}
