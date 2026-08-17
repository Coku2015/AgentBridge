// Package vbr isolates AgentBridge from any specific Veeam Backup &
// Replication REST API revision.
//
// The VBRAdapter interface (adapter.go) is the only surface the rest of the
// product programs against (AB-NFR-007, section 20). Each supported API
// revision will ship its own implementation behind it. Capability detection
// runs up front and closes UI paths that the connected build cannot serve,
// rather than failing late (AB-FR-023, AB-FR-026 — never silently fall back to
// arbitrary PowerShell).
//
// Secrets (VBR password, bearer token) are kept in memory only and passed
// out-of-band; they never appear in ConnectionConfig or in persisted state
// (AB-FR-024, section 16.2).
package vbr
