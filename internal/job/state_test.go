package job

import "testing"

func TestCanTransitionTo_CorePath(t *testing.T) {
	cases := []struct {
		from, to HostState
		want     bool
	}{
		{HostPending, HostConnecting, true},
		{HostConnecting, HostProbing, true},
		{HostProbing, HostProbed, true},
		{HostProbed, HostAwaitingPackageSelection, true},
		{HostAwaitingPackageSelection, HostPrivilegeChecking, true},
		{HostPrivilegeChecking, HostPreparingBundle, true},
		{HostPreparingBundle, HostUploading, true},
		{HostUploading, HostInstallingAgent, true},
		{HostInstallingAgent, HostVerifyingLocal, true},
		{HostVerifyingLocal, HostLocalInstallSucceeded, true},
		// Install success and discovery success are distinct layers (Principle IV).
		{HostLocalInstallSucceeded, HostCreatingRegistration, true},
		{HostCreatingRegistration, HostRescanning, true},
		{HostRescanning, HostDiscovered, true},
		{HostDiscovered, HostCompleted, true},
		// A jump skipping layers is illegal (must not collapse install->discovery).
		{HostLocalInstallSucceeded, HostDiscovered, false},
		{HostPending, HostCompleted, false},
		{HostPending, HostProbed, false},
	}
	for _, c := range cases {
		if got := c.from.CanTransitionTo(c.to); got != c.want {
			t.Errorf("%s -> %s = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}

func TestCanTransitionTo_RegistrationOnlyRetry(t *testing.T) {
	// FR-031: install-succeeded/registration-failed retries ONLY enrollment.
	// It MUST be legal to return to CreatingRegistration, but NOT to reinstall.
	if !HostInstalledRegistrationFailed.CanTransitionTo(HostCreatingRegistration) {
		t.Error("registration-failed -> CreatingRegistration must be legal (FR-031)")
	}
	if HostInstalledRegistrationFailed.CanTransitionTo(HostUploading) {
		t.Error("registration-failed -> Uploading (reinstall) must be ILLEGAL (FR-031)")
	}
	if HostInstalledRegistrationFailed.CanTransitionTo(HostInstallingAgent) {
		t.Error("registration-failed -> InstallingAgent (reinstall) must be ILLEGAL")
	}

	// FR-032: PG-created/rescan-failed retries ONLY rescan.
	if !HostDiscoveryFailed.CanTransitionTo(HostRescanning) {
		t.Error("discovery-failed -> Rescanning must be legal (FR-032)")
	}
	if HostDiscoveryFailed.CanTransitionTo(HostCreatingRegistration) {
		t.Error("discovery-failed -> CreatingRegistration must be ILLEGAL (rescan-only retry)")
	}
}

func TestCanTransitionTo_CancelAndSelf(t *testing.T) {
	// Self-transition (no-op) always legal.
	if !HostPending.CanTransitionTo(HostPending) {
		t.Error("self-transition must be legal")
	}
	// Any non-terminal state may be cancelled.
	if !HostProbing.CanTransitionTo(HostCancelled) {
		t.Error("non-terminal -> Cancelled must be legal")
	}
	// A terminal success cannot be "cancelled" away.
	if HostCompleted.CanTransitionTo(HostCancelled) {
		t.Error("Completed -> Cancelled must be illegal")
	}
}

func TestIsTerminal(t *testing.T) {
	terminal := []HostState{HostCompleted, HostCancelled, HostProbeFailed, HostDiscoveryFailed}
	for _, s := range terminal {
		if !s.IsTerminal() {
			t.Errorf("%s should be terminal", s)
		}
	}
	if HostPending.IsTerminal() || HostInstallingAgent.IsTerminal() {
		t.Error("in-flight states must not be terminal")
	}
}
