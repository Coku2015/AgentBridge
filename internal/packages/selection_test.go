package packages

import (
	"archive/zip"
	"bytes"
	"os"
	"testing"

	"github.com/Coku2015/agentbridge/internal/probe"
)

func TestSelectForTargetChoosesStandardRHELSet(t *testing.T) {
	source := makePackageArchive(t, map[string]string{
		"kmod-veeamsnap-13.1.1.4-1.el8.x86_64.rpm": "kmod",
		"veeamsnap-13.1.1.4-1.noarch.rpm":          "dkms",
		"veeam-libs-13.1.1.4-1.x86_64.rpm":         "libs",
		"veeam-13.1.1.4-1.el8.x86_64.rpm":          "agent",
		"veeam-nosnap-13.1.1.4-1.el8.x86_64.rpm":   "nosnap",
		"veeam-13.1.1.4-1.amd64.deb":               "wrong-format",
		"veeam-ueficert-13.1.1.4-1.noarch.rpm":     "uefi",
	})
	store, err := NewArtifactStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifact, selection, err := store.SelectForTarget(source, "Red Hat 8 x64 - 13.1.1.4", probe.Result{
		PackageFormat: "rpm",
		Target:        probe.Target{Architecture: "x86_64"},
		OS:            probe.OSInfo{ID: "rhel", VersionID: "8.10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(artifact.Path)
	if selection.RequiresExplicitConfirmation {
		t.Fatalf("supported RHEL target unexpectedly requires confirmation: %+v", selection)
	}
	if got := payloadNames(selection.Selected); len(got) != 3 || got[0] != "kmod-veeamsnap-13.1.1.4-1.el8.x86_64.rpm" || got[1] != "veeam-libs-13.1.1.4-1.x86_64.rpm" || got[2] != "veeam-13.1.1.4-1.el8.x86_64.rpm" {
		t.Fatalf("selected = %v", got)
	}
	if artifact.Format != "package-set" {
		t.Fatalf("artifact format = %q, want package-set", artifact.Format)
	}
}

func TestSelectForTargetRequiresConfirmationForCentOS7(t *testing.T) {
	source := makePackageArchive(t, map[string]string{
		"veeamsnap-13.1.1.4-1.noarch.rpm":  "snap",
		"veeam-libs-13.1.1.4-1.x86_64.rpm": "libs",
		"veeam-13.1.1.4-1.el7.x86_64.rpm":  "agent",
	})
	store, err := NewArtifactStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifact, selection, err := store.SelectForTarget(source, "Red Hat 7 x64 - 13.1.1.4", probe.Result{
		PackageFormat: "rpm",
		Target:        probe.Target{Architecture: "x86_64"},
		OS:            probe.OSInfo{ID: "centos", VersionID: "7"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(artifact.Path)
	if !selection.RequiresExplicitConfirmation {
		t.Fatalf("CentOS 7 must require explicit confirmation: %+v", selection)
	}
	if len(selection.Selected) != 3 {
		t.Fatalf("selected = %+v", selection.Selected)
	}
}

func TestSelectForTargetUsesRHELFamilyAliasAndArchitecture(t *testing.T) {
	source := makePackageArchive(t, map[string]string{
		"kmod-veeamsnap-13.1.1.4-1.el8.ppc64le.rpm": "kmod",
		"veeamsnap-13.1.1.4-1.el8.ppc64le.rpm":      "wrong-snapshot-choice",
		"veeam-libs-13.1.1.4-1.ppc64le.rpm":         "libs",
		"veeam-13.1.1.4-1.el8.ppc64le.rpm":          "agent",
		"veeam-13.1.1.4-1.el7.ppc64le.rpm":          "wrong-major",
	})
	store, err := NewArtifactStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifact, selection, err := store.SelectForTarget(source, "Anolis 8 ppc64le - 13.1.1.4", probe.Result{
		PackageFormat: "rpm",
		Target:        probe.Target{Architecture: "ppc64le"},
		OS:            probe.OSInfo{ID: "anolis", VersionID: "8.8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(artifact.Path)
	if !selection.RequiresExplicitConfirmation {
		t.Fatalf("RHEL-family derivative must require confirmation: %+v", selection)
	}
	if selection.CompatibilityFamily != "rhel" {
		t.Fatalf("compatibility family = %q, want rhel", selection.CompatibilityFamily)
	}
	if got := payloadNames(selection.Selected); len(got) != 3 || got[0] != "kmod-veeamsnap-13.1.1.4-1.el8.ppc64le.rpm" || got[1] != "veeam-libs-13.1.1.4-1.ppc64le.rpm" || got[2] != "veeam-13.1.1.4-1.el8.ppc64le.rpm" {
		t.Fatalf("selected = %v", got)
	}
}

func TestSelectForTargetChoosesNosnapRoles(t *testing.T) {
	source := makePackageArchive(t, map[string]string{
		"veeam-libs-13.1.1.4-1.x86_64.rpm":         "libs",
		"veeam-nosnap-13.1.1.4-1.el8.x86_64.rpm":   "nosnap",
		"kmod-veeamsnap-13.1.1.4-1.el8.x86_64.rpm": "must-not-select",
	})
	store, err := NewArtifactStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifact, selection, err := store.SelectForTarget(source, "Red Hat 8 x64-nosnap - 13.1.1.4", probe.Result{
		PackageFormat: "rpm",
		Target:        probe.Target{Architecture: "x86_64"},
		OS:            probe.OSInfo{ID: "rhel", VersionID: "8.10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(artifact.Path)
	if got := payloadNames(selection.Selected); len(got) != 2 || got[0] != "veeam-libs-13.1.1.4-1.x86_64.rpm" || got[1] != "veeam-nosnap-13.1.1.4-1.el8.x86_64.rpm" {
		t.Fatalf("selected = %v", got)
	}
}

func TestSelectForTargetChoosesSUSEKernelModuleOverGenericSource(t *testing.T) {
	source := makePackageArchive(t, map[string]string{
		"blksnap-13.1.1.4-sle.noarch.rpm":                                     "generic-source",
		"blksnap-kmp-default-13.1.1.4_k5.14.21_150500.53-sles15.5.x86_64.rpm": "kmp",
		"veeam-libs-13.1.1.4-1.x86_64.rpm":                                    "libs",
		"veeam-13.1.1.4-1.sle15.x86_64.rpm":                                   "agent",
	})
	store, err := NewArtifactStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifact, selection, err := store.SelectForTarget(source, "SLES 15 x64 - 13.1.1.4", probe.Result{
		PackageFormat: "rpm",
		Target:        probe.Target{Architecture: "x86_64"},
		OS:            probe.OSInfo{ID: "sles", VersionID: "15.5"},
		Kernel:        "5.14.21-150500.53-default",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(artifact.Path)
	if got := payloadNames(selection.Selected); len(got) != 3 || got[0] != "blksnap-kmp-default-13.1.1.4_k5.14.21_150500.53-sles15.5.x86_64.rpm" {
		t.Fatalf("selected = %v", got)
	}
}

func TestSelectForTargetChoosesDebianSnapshotByMajor(t *testing.T) {
	for _, tc := range []struct {
		name string
		ver  string
		want string
	}{
		{name: "Debian 10 amd64 - 13.1.1.4", ver: "10.13", want: "veeamsnap_13.1.1.4_all.deb"},
		{name: "Debian 11 amd64 - 13.1.1.4", ver: "11.11", want: "blksnap_13.1.1.4_amd64.deb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := makePackageArchive(t, map[string]string{
				"veeamsnap_13.1.1.4_all.deb":    "old-snapshot",
				"blksnap_13.1.1.4_amd64.deb":    "new-snapshot",
				"veeam-libs_13.1.1.4_amd64.deb": "libs",
				"veeam_13.1.1.4_amd64.deb":      "agent",
			})
			store, err := NewArtifactStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			artifact, selection, err := store.SelectForTarget(source, tc.name, probe.Result{
				PackageFormat: "deb",
				Target:        probe.Target{Architecture: "x86_64"},
				OS:            probe.OSInfo{ID: "debian", VersionID: tc.ver},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(artifact.Path)
			if got := payloadNames(selection.Selected); len(got) != 3 || got[0] != tc.want {
				t.Fatalf("selected = %v, want snapshot %s", got, tc.want)
			}
		})
	}
}

func TestSelectForTargetFallsBackToPowerNosnapSet(t *testing.T) {
	source := makePackageArchive(t, map[string]string{
		"veeam-libs-13.1.1.4-1.ppc64le.rpm":       "libs",
		"veeam-nosnap-13.1.1.4-1.el8.ppc64le.rpm": "nosnap",
		"veeam-release-el8-13.0.2-1.noarch.rpm":   "release-only",
	})
	store, err := NewArtifactStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifact, selection, err := store.SelectForTarget(source, "Red Hat 8 ppc64le - 13.1.1.4", probe.Result{
		PackageFormat: "rpm",
		Target:        probe.Target{Architecture: "ppc64le"},
		OS:            probe.OSInfo{ID: "rhel", VersionID: "8.10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(artifact.Path)
	if selection.Mode != "nosnap" || !selection.RequiresExplicitConfirmation {
		t.Fatalf("selection = %+v", selection)
	}
	if got := payloadNames(selection.Selected); len(got) != 2 || got[0] != "veeam-libs-13.1.1.4-1.ppc64le.rpm" || got[1] != "veeam-nosnap-13.1.1.4-1.el8.ppc64le.rpm" {
		t.Fatalf("selected = %v", got)
	}
}

func makePackageArchive(t *testing.T, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/export.zip"
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func payloadNames(payloads []Payload) []string {
	result := make([]string, 0, len(payloads))
	for _, payload := range payloads {
		result = append(result, payload.FileName)
	}
	return result
}
