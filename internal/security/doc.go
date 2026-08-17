// Package security centralizes secret handling, log redaction and TLS pinning
// (section 17).
//
// Secret discipline (section 17.1):
//   - secrets live only in the executing component and in memory;
//   - secrets never come from CLI args, never enter persisted state or logs;
//   - request-body logging is off by default or field-redacted;
//   - on task end, owned byte slices are best-effort zeroed (the runtime gives
//     no absolute zeroization guarantee — we minimize dwell time + isolate perms);
//   - temp files are 0600/0700 on Linux/macOS, restricted ACL on Windows.
//
// TLS pinning is mandatory for VBR; no global InsecureSkipVerify (section 17.3).
package security
