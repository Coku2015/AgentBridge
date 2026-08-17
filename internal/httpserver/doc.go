// Package httpserver hosts the embedded Web UI and the HTTP API used by the
// browser wizard (section 8, section 19).
//
// Responsibilities (landed across M1):
//   - serve the Vue UI embedded via go:embed (see webembed.go);
//   - JSON API + Server-Sent Events for real-time per-host progress;
//   - localhost mode: random bootstrap token + secure session cookie;
//   - server mode: mandatory TLS + admin auth (AB-FR-003..006, section 17.2);
//   - strict web hardening: SameSite cookies, CSRF token, Origin check, CSP,
//     rate limiting, no cross-origin management API, no arbitrary command API.
//
// Secrets entered here live only in session memory and are never written to the
// Job Journal or logs (AB-FR-024, section 16.2).
package httpserver
