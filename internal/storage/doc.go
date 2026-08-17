// Package storage persists only non-secret state — the Job Journal and cache
// metadata (Constitution red line 1, AB-FR-024). It MUST never write secrets.
//
// # Allow / deny list
//
// Secrets are denied at the field-name level by security.IsSecretFieldName and
// by security.SanitizeMap, which every Journal.Append and Store.Put runs before
// writing. A field is treated as a SECRET (denied) when its name (case-folded)
// contains any of:
//
//	password, passwd, secret, token, passphrase, privatekey, private_key,
//	bearer, apikey, api_key
//
// Specifically DENIED (memory-only, never persisted/logged):
//
//   - Linux / sudo passwords
//   - SSH private keys + passphrases
//   - VBR password
//   - OAuth2 bearer / access token
//   - Certificate private keys
//   - One-shot package download tokens
//
// ALLOWED (non-secret, persisted):
//
//   - VBR server, port, username, product version, build, API revision
//   - Pinned TLS SHA-256 fingerprint, pinned SSH host key
//   - Capability flags
//   - Probe facts (OS, kernel, glibc, package format, RHEL macro, Secure Boot…)
//   - Match recommendation, chosen package ID, override reason, confirming user
//   - Protection Group name/description, session state/progress
//   - Discovered entity host/agent status/version
//   - Host/batch state, progress, events, exit codes, redacted errors
//
// Redaction is enforced by construction in Journal/Store, not by convention.
package storage
