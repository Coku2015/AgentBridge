// Package matcher recommends a Package Profile from a Probe result using
// embedded, versioned, testable data rules (AB-FR-105).
//
// Rules are explanatory, not authoritative: every recommendation carries its
// evidence, confidence, warnings and unmet conditions (AB-FR-101). Non-official
// OS matches MUST require explicit user confirmation (AB-FR-103). A user
// override is always allowed and is audited, but never re-labelled as
// VendorSupported or LabValidated (AB-FR-102, section 15.3). The
// CompatibilityInferred level records upstream-family inference separately
// from both official support and lab validation.
//
// MVP uses local static rules only; no cloud dependency (AB-FR-107).
package matcher
