// Package sshtransport implements a pure-Go SSH client for the SSH Push
// executor (section 9.1, Spike 4).
//
// Requirements baked in by design:
//   - no dependency on system OpenSSH client or on target-side SFTP: file
//     upload happens via SSH stdin / remote `cat`/`dd` (AB-FR-122);
//   - first-connection host key is shown, accepted and pinned; a later change
//     blocks by default (AB-FR-121, section 17.4);
//   - fixed command templates and strict shell quoting — user input is never
//     concatenated into a shell string (AB-FR-124, section 17.4);
//   - per-host unpredictable temp dir, tightened permissions, bounded
//     concurrency/timeouts/output size, context cancellation (AB-FR-123..126);
//   - private-key parse errors and passphrases never reach logs (section 17.4).
//
// Linux auth/elevation: password or private key (+ passphrase), direct root,
// NOPASSWD sudo, sudo with the account password, validated sudoers drop-in and
// explicitly selected su fallback. Elevation passwords travel only over a PTY
// with echo disabled and never appear in command strings (AB-FR-120/125).
package sshtransport
