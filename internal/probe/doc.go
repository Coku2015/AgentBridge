// Package probe gathers target-host compatibility facts without relying on
// Python, Ansible or any resident component on the target (AB-FR-081..083,
// AB-NFR-009).
//
// Two delivery modes share the same output schema (schema.go):
//   - SSH Probe: run POSIX shell facts over a pure-Go SSH session;
//   - Local Probe: a no-root script the Linux admin runs on the host, whose
//     JSON output is imported back into AgentBridge (Zero-Credential path).
//
// Probe output is versioned JSON (schemaVersion, AB-FR-084) and feeds the
// matcher. Probe results contain no secrets.
package probe
