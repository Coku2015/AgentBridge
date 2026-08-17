// Package kitzip extracts and validates VBR Deployment Kit archives.
//
// A Deployment Kit generated/downloaded from VBR is a ZIP archive — NOT a
// self-executing script. It carries the official installer
// (install-deployment-kit.sh), the deployment service packages
// (veeamdeployment + the openssl-fips redistributable, .rpm/.deb) and the
// per-campaign certificates (client/server pem). The Veeam Agent package
// itself is NOT inside the kit: the installer sets up the deployment service
// and pairs the certificate, and VBR later pushes the Agent through that
// service during Protection-Group discovery/rescan.
//
// AgentBridge extracts the archive with the Go stdlib (archive/zip) on the
// AgentBridge side, so the TARGET host needs no unzip binary: executors upload
// the extracted files and run the official installer with bash (it uses bash
// builtins: compgen, declare).
//
// Requirement sections: §12 (install payload), §21 module map. The kit archive
// holds the campaign's temporary certificate material by design — it is the
// deliverable that must reach the target; storage rules for it live in
// internal/storage/doc.go.
package kitzip
