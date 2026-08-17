// Package bundle builds the Local/Offline Bootstrap Bundle (section 9.2..9.4,
// section 13.8, Spike 5).
//
// A bundle contains the install files, a fixed install script, manifest.json
// and SHA256SUMS. It MUST NEVER contain a Linux login password, VBR password,
// bearer token or SSH private key (AB-FR-141). When a bundle carries a
// Deployment Kit, its temporary certificate expiry and sensitivity level are
// surfaced prominently (AB-FR-144). The local install script emits a structured
// result file that AgentBridge imports back, verifying Job ID, target identity
// and the selected deployment profile — "kit-only" or "agent-plus-kit" —
// before continuing to VBR enrollment (AB-FR-142..143). Every supported
// profile contains the Deployment Kit required for certificate enrollment.
package bundle
