package job

// BatchState enumerates batch-level states (section 14.1).
type BatchState string

const (
	BatchCreated                   BatchState = "Created"
	BatchConnectingVBR             BatchState = "ConnectingVBR"
	BatchLoadingPackages           BatchState = "LoadingPackages"
	BatchPreparingDeploymentKit    BatchState = "PreparingDeploymentKit"
	BatchProbing                   BatchState = "Probing"
	BatchAwaitingUserConfirmation  BatchState = "AwaitingUserConfirmation"
	BatchPreparingArtifacts        BatchState = "PreparingArtifacts"
	BatchExecuting                 BatchState = "Executing"
	BatchCreatingProtectionGroup   BatchState = "CreatingProtectionGroup"
	BatchRescanningProtectionGroup BatchState = "RescanningProtectionGroup"
	BatchVerifyingDiscovery        BatchState = "VerifyingDiscovery"
	BatchCompleted                 BatchState = "Completed"
	BatchPartiallyCompleted        BatchState = "PartiallyCompleted"
	BatchFailed                    BatchState = "Failed"
	BatchCancelled                 BatchState = "Cancelled"
)

// HostState enumerates host-level states (section 14.2). Includes success,
// in-flight and failure states.
type HostState string

const (
	HostPending                   HostState = "Pending"
	HostConnecting                HostState = "Connecting"
	HostProbing                   HostState = "Probing"
	HostProbed                    HostState = "Probed"
	HostAwaitingPackageSelection  HostState = "AwaitingPackageSelection"
	HostPrivilegeChecking         HostState = "PrivilegeChecking"
	HostPreparingBundle           HostState = "PreparingBundle"
	HostWaitingForExternalInstall HostState = "WaitingForExternalInstall"
	HostUploading                 HostState = "Uploading"
	HostInstallingAgent           HostState = "InstallingAgent"
	HostInstallingDeploymentKit   HostState = "InstallingDeploymentKit"
	HostVerifyingLocal            HostState = "VerifyingLocal"
	HostLocalInstallSucceeded     HostState = "LocalInstallSucceeded"
	HostCreatingRegistration      HostState = "CreatingRegistration"
	HostRescanning                HostState = "Rescanning"
	HostDiscovered                HostState = "Discovered"
	HostCompleted                 HostState = "Completed"

	// Failure states (section 14.2).
	HostSSHConnectionFailed         HostState = "SSHConnectionFailed"
	HostHostKeyRejected             HostState = "HostKeyRejected"
	HostProbeFailed                 HostState = "ProbeFailed"
	HostPrivilegeUnavailable        HostState = "PrivilegeUnavailable"
	HostNoMatchingPackage           HostState = "NoMatchingPackage"
	HostPackageValidationFailed     HostState = "PackageValidationFailed"
	HostUploadFailed                HostState = "UploadFailed"
	HostAgentInstallFailed          HostState = "AgentInstallFailed"
	HostDeploymentKitInstallFailed  HostState = "DeploymentKitInstallFailed"
	HostLocalVerificationFailed     HostState = "LocalVerificationFailed"
	HostRebootRequired              HostState = "RebootRequired"
	HostInstalledRegistrationFailed HostState = "InstalledRegistrationFailed"
	HostDiscoveryFailed             HostState = "DiscoveryFailed"
	HostKitExpired                  HostState = "KitExpired"
	HostKitInvalidated              HostState = "KitInvalidated"
	HostCancelled                   HostState = "Cancelled"
)

// IsFailure reports whether s is a terminal failure state.
func (s HostState) IsFailure() bool {
	switch s {
	case HostSSHConnectionFailed, HostHostKeyRejected, HostProbeFailed,
		HostPrivilegeUnavailable, HostNoMatchingPackage, HostPackageValidationFailed,
		HostUploadFailed, HostAgentInstallFailed, HostDeploymentKitInstallFailed,
		HostLocalVerificationFailed, HostDiscoveryFailed, HostKitExpired,
		HostKitInvalidated:
		return true
	}
	return false
}

// legalHostTransitions encodes the host state machine (section 14, data-model.md).
// Install success and discovery success are DISTINCT layers (Principle IV); the
// registration-only and rescan-only retry edges honor Principle V (FR-031/032):
//   - InstalledRegistrationFailed -> CreatingRegistration   (no reinstall)
//   - DiscoveryFailed             -> Rescanning             (rescan only)
var legalHostTransitions = map[HostState][]HostState{
	HostPending:                  {HostConnecting},
	HostConnecting:               {HostProbing, HostSSHConnectionFailed, HostHostKeyRejected},
	HostProbing:                  {HostProbed, HostProbeFailed},
	HostProbed:                   {HostAwaitingPackageSelection},
	HostAwaitingPackageSelection: {HostPrivilegeChecking, HostNoMatchingPackage},
	HostPrivilegeChecking:        {HostPreparingBundle, HostPrivilegeUnavailable},
	HostPreparingBundle:          {HostUploading, HostWaitingForExternalInstall},
	HostUploading:                {HostInstallingAgent, HostUploadFailed},
	HostInstallingAgent:          {HostInstallingDeploymentKit, HostVerifyingLocal, HostAgentInstallFailed},
	HostInstallingDeploymentKit:  {HostVerifyingLocal, HostDeploymentKitInstallFailed},
	HostVerifyingLocal:           {HostLocalInstallSucceeded, HostLocalVerificationFailed, HostRebootRequired},
	HostLocalInstallSucceeded:    {HostCreatingRegistration},
	HostCreatingRegistration:     {HostRescanning, HostInstalledRegistrationFailed},
	HostRescanning:               {HostDiscovered, HostDiscoveryFailed},
	HostDiscovered:               {HostCompleted},
	// Retry edges: recovery WITHOUT reinstall / auto-uninstall (Principle V).
	HostInstalledRegistrationFailed: {HostCreatingRegistration},
	HostDiscoveryFailed:             {HostRescanning},
}

// IsTerminal reports whether s is a terminal state (no further transitions
// except cancellation or, for failures, an explicit retry edge).
func (s HostState) IsTerminal() bool {
	switch s {
	case HostCompleted, HostCancelled,
		HostSSHConnectionFailed, HostHostKeyRejected, HostProbeFailed,
		HostPrivilegeUnavailable, HostNoMatchingPackage, HostPackageValidationFailed,
		HostUploadFailed, HostAgentInstallFailed, HostDeploymentKitInstallFailed,
		HostLocalVerificationFailed, HostRebootRequired, HostDiscoveryFailed,
		HostKitExpired, HostKitInvalidated, HostInstalledRegistrationFailed:
		return true
	}
	return false
}

// CanTransitionTo reports whether moving from s to next is legal. Self-transitions
// (no-ops) are always allowed; any non-terminal state may transition to Cancelled.
func (s HostState) CanTransitionTo(next HostState) bool {
	if s == next {
		return true
	}
	if next == HostCancelled && !s.IsTerminal() {
		return true
	}
	for _, allowed := range legalHostTransitions[s] {
		if allowed == next {
			return true
		}
	}
	return false
}
