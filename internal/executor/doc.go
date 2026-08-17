// Package executor defines the BootstrapExecutor abstraction (section 9). The
// job orchestrator programs to this interface and never depends on a concrete
// transport (SSH, Local, External, Offline), so new delivery modes can be added
// without touching orchestration (AB-NFR-007).
//
// MVP ships three executors: SSH Push, Local Run and Offline Bundle. All of them
// follow the credential-minimization principle — secrets live only in the
// executing component and are destroyed on completion (section 5, section 17.1).
package executor
