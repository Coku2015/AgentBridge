// Package job implements the two-level Batch/Host state machine, retry policy
// and event journaling (section 14, section 22).
//
// Design rules baked into the state model:
//   - a single host failure never aborts the batch (AB-NFR-004);
//   - install-success-but-registration-failure retries ONLY enrollment, never
//     reinstalls or auto-uninstalls (section 12.3, AB-FR-189);
//   - browser refresh and process restart recover non-sensitive state, but
//     never restore secrets from disk (AB-FR-201..202);
//   - retries are idempotent — no duplicate PG, no duplicate Kit Campaign, no
//     duplicate same-version install (AB-NFR-005).
package job
