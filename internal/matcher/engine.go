package matcher

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Coku2015/agentbridge/internal/linuxcompat"
)

// matrixFile is the embedded, versioned rule data (AB-FR-105). It lives inside
// the package so go:embed can reference it; the repo-root rules/ dir holds the
// human-facing validation records.
//
//go:embed data/matrix.json
var matrixFile []byte

// matrix is the parsed rule catalog.
type matrix struct {
	Version                 string   `json:"version"`
	Description             string   `json:"description"`
	SupportedArchitectures  []string `json:"supportedArchitectures"`
	SupportedPackageFormats []string `json:"supportedPackageFormats"`
	Rules                   []rule   `json:"rules"`
}

// rule is one explanatory, data-driven matching rule.
type rule struct {
	ID            string    `json:"id"`
	PackageID     string    `json:"packageId"`
	Level         RuleLevel `json:"level"`
	PackageFormat string    `json:"packageFormat"`
	Architecture  string    `json:"architecture"`
	VersionMajors []int     `json:"versionMajors"`
	MinGlibc      string    `json:"minGlibc"`
	OSIDs         []string  `json:"osIds"`
	Notes         string    `json:"notes"`
}

// Engine is the deterministic, embedded-rule matcher (MVP local rules only,
// AB-FR-107). It never infers VendorSupport (red line 11) and never re-labels a
// user override (AB-FR-102).
type Engine struct {
	m matrix
}

// NewEngine parses the embedded matrix. It fails fast on malformed data so a bad
// rule file is a build-time/test-time error, never a silent runtime miss.
func NewEngine() (*Engine, error) {
	var m matrix
	if err := json.Unmarshal(matrixFile, &m); err != nil {
		return nil, fmt.Errorf("matcher: parse embedded matrix: %w", err)
	}
	if len(m.Rules) == 0 {
		return nil, fmt.Errorf("matcher: embedded matrix has no rules")
	}
	return &Engine{m: m}, nil
}

// MatrixVersion exposes the embedded rule version (for audit/UI).
func (e *Engine) MatrixVersion() string { return e.m.Version }

// Match evaluates probe facts against the embedded rules deterministically and
// returns an explanatory recommendation + trust level. It is pure: same input
// always yields the same output (AB-NFR-008).
func (e *Engine) Match(input Input) (Recommendation, RuleLevel, error) {
	rec := Recommendation{}
	var evidence []string

	profile := linuxcompat.Resolve(input.ID, input.IDLike, input.PackageFormat)
	rec.CompatibilityFamily = string(profile.Family)
	rec.CompatibilityBasis = profile.Basis

	// --- Hard blocks first (red line 11: never lie about support). ---
	if !contains(e.m.SupportedArchitectures, input.Architecture) {
		return blocked(rec, evidence, fmt.Sprintf("architecture %q is not supported (supported: %s)", input.Architecture, joinOr(e.m.SupportedArchitectures)))
	}
	if !contains(e.m.SupportedPackageFormats, input.PackageFormat) {
		return blocked(rec, evidence, fmt.Sprintf("package format %q is not supported (supported: %s)", input.PackageFormat, joinOr(e.m.SupportedPackageFormats)))
	}
	evidence = append(evidence, fmt.Sprintf("architecture %s + package format %s are supported", input.Architecture, input.PackageFormat))
	if !repositorySupports(profile, input.PackageFormat, input.Architecture) {
		return blocked(rec, evidence, repositoryReason(profile, input.PackageFormat, input.Architecture))
	}
	if profile.Kind == linuxcompat.Blocked {
		return blocked(rec, evidence, profile.Reason)
	}
	if profile.Kind == linuxcompat.Unknown {
		evidence = append(evidence, "no known upstream distribution identity; package headers must be inspected")
	}
	if profile.Family != linuxcompat.Other && profile.Family != linuxcompat.UnknownRPM && profile.Family != linuxcompat.UnknownDEB {
		evidence = append(evidence, fmt.Sprintf("mapped %s to %s", profile.DisplayName, profile.Family))
	}

	// --- Find the best candidate rule (official before inferred). ---
	best, ok := e.bestRule(input)
	if !ok && profile.Kind != linuxcompat.Blocked && profile.Kind != linuxcompat.Unknown {
		best, ok = inferredRule(input, profile)
	}
	if !ok {
		return blocked(rec, evidence, fmt.Sprintf("no validated package profile for os id=%q like=%v — manual package selection required", input.ID, input.IDLike))
	}

	rec.RecommendedPackageID = best.PackageID
	if input.Architecture == "ppc64le" {
		rec.PackageMode = "nosnap"
		evidence = append(evidence, "Agent 13 repository exposes the Power path as veeam-libs + veeam-nosnap; no kernel-module payload is selected")
	} else {
		rec.PackageMode = "standard"
	}
	evidence = append(evidence, fmt.Sprintf("matched rule %q (%s) on os id=%q", best.ID, best.Level, osIdentity(input)))
	if best.MinGlibc != "" {
		if cmp, ok := compareVersions(input.Glibc, best.MinGlibc); ok && cmp < 0 {
			rec.Warnings = append(rec.Warnings, fmt.Sprintf("glibc %s is below the validated minimum %s", input.Glibc, best.MinGlibc))
		} else {
			evidence = append(evidence, fmt.Sprintf("glibc %s meets minimum %s", input.Glibc, best.MinGlibc))
		}
	}

	// Non-official matches and pre-existing installs require explicit confirmation
	// (AB-FR-103). VendorSupported alone does not force confirmation.
	rec.Confidence = confidenceFor(best.Level)
	rec.RequiresExplicitConfirmation = best.Level != VendorSupported || input.ExistingAgent

	if input.ExistingAgent {
		rec.Warnings = append(rec.Warnings, "a Veeam Agent appears already installed; reinstall is destructive and requires confirmation")
	}
	if best.Level == CompatibilityInferred {
		rec.Warnings = append(rec.Warnings, fmt.Sprintf("package %s is inferred from upstream compatibility — NOT a Veeam support claim", best.PackageID))
	} else if best.Level == LabValidated {
		rec.Warnings = append(rec.Warnings, fmt.Sprintf("package %s is validated in this project's lab only — NOT on the official Veeam matrix", best.PackageID))
	}

	rec.Evidence = evidence
	return rec, best.Level, nil
}

func repositorySupports(profile linuxcompat.Profile, format, arch string) bool {
	switch arch {
	case "x86_64":
		return format == "rpm" || format == "deb"
	case "ppc64le":
		return format == "rpm" && (profile.Family == linuxcompat.RHEL || profile.Family == linuxcompat.SUSE)
	default:
		return false
	}
}

func repositoryReason(profile linuxcompat.Profile, format, arch string) string {
	if arch == "ppc64le" && format == "deb" {
		return "the Agent 13 repository has no DEB/ppc64le payload; Power is provided through RPM veeam-nosnap packages"
	}
	if arch == "ppc64le" {
		return fmt.Sprintf("the Agent 13 repository has no Power package profile for %s; only RHEL-family and SLES RPM nosnap sets are available", profile.DisplayName)
	}
	return fmt.Sprintf("the Agent 13 repository has no package payload for architecture %q", arch)
}

// bestRule returns the highest-priority rule whose predicate matches. Priority
// order prevents support-lies (red line 11):
//  1. VendorSupported rule matching on the PRIMARY os id (never via ID_LIKE —
//     a derivative claiming "rhel" compatibility does not get official support).
//  2. Any rule matching on the primary os id.
//  3. Any rule matching via ID_LIKE only (always a lower trust level).
func (e *Engine) bestRule(input Input) (rule, bool) {
	// 1. Official matrix via primary identity.
	for i := range e.m.Rules {
		r := &e.m.Rules[i]
		if r.Level == VendorSupported && ruleMatchesPrimary(r, input) {
			return *r, true
		}
	}
	// 2. Any non-official level via primary identity. Official rules are only
	// trusted when the primary ID itself is in the official matrix.
	for i := range e.m.Rules {
		r := &e.m.Rules[i]
		if r.Level != VendorSupported && ruleMatchesPrimary(r, input) {
			return *r, true
		}
	}
	// 3. Fallback via ID_LIKE (derivatives — never VendorSupported).
	for i := range e.m.Rules {
		r := &e.m.Rules[i]
		if r.Level != VendorSupported && ruleMatchesIDLike(r, input) {
			return *r, true
		}
	}
	return rule{}, false
}

// inferredRule creates the recommendation for a known upstream family that is
// not represented by a specific official matrix row (for example CentOS 7,
// Linux Mint, or a ppc64le RHEL-compatible derivative). The result is always
// CompatibilityInferred and therefore requires confirmation.
func inferredRule(input Input, profile linuxcompat.Profile) (rule, bool) {
	if profile.Family == linuxcompat.Other || profile.Family == linuxcompat.UnknownRPM || profile.Family == linuxcompat.UnknownDEB {
		return rule{}, false
	}
	return rule{
		ID:            "inferred-" + profile.CanonicalID,
		PackageID:     linuxcompat.CanonicalPackageID(profile, input.VersionID, input.Architecture),
		Level:         CompatibilityInferred,
		PackageFormat: input.PackageFormat,
		Architecture:  input.Architecture,
		Notes:         profile.Basis,
	}, true
}

// ruleMatchesPrimary tests format + architecture + exact os id membership.
func ruleMatchesPrimary(r *rule, input Input) bool {
	if r.PackageFormat != input.PackageFormat || r.Architecture != input.Architecture {
		return false
	}
	return input.ID != "" && contains(r.OSIDs, input.ID) && versionMatches(r, input.VersionID)
}

// ruleMatchesIDLike tests format + architecture + any ID_LIKE membership. Used
// only as a fallback so derivatives never claim official vendor support.
func ruleMatchesIDLike(r *rule, input Input) bool {
	if r.PackageFormat != input.PackageFormat || r.Architecture != input.Architecture {
		return false
	}
	if !versionMatches(r, input.VersionID) {
		return false
	}
	for _, like := range input.IDLike {
		if contains(r.OSIDs, like) {
			return true
		}
	}
	return false
}

func versionMatches(r *rule, version string) bool {
	if len(r.VersionMajors) == 0 {
		return true
	}
	major := majorNumber(version)
	if major == 0 {
		return false
	}
	for _, allowed := range r.VersionMajors {
		if allowed == major {
			return true
		}
	}
	return false
}

func majorNumber(version string) int {
	start := 0
	for start < len(version) && (version[start] < '0' || version[start] > '9') {
		start++
	}
	end := start
	for end < len(version) && version[end] >= '0' && version[end] <= '9' {
		end++
	}
	if start == end {
		return 0
	}
	major := 0
	for i := start; i < end; i++ {
		major = major*10 + int(version[i]-'0')
	}
	return major
}

// blocked returns a Blocked recommendation that surfaces why and never lies about support.
func blocked(rec Recommendation, evidence []string, reason string) (Recommendation, RuleLevel, error) {
	rec.Evidence = append(evidence, "blocked: "+reason)
	rec.Warnings = append(rec.Warnings, reason)
	rec.Confidence = "low"
	rec.RequiresExplicitConfirmation = false
	return rec, Blocked, nil
}

func confidenceFor(level RuleLevel) string {
	switch level {
	case VendorSupported:
		return "high"
	case LabValidated, CompatibilityInferred:
		return "medium"
	default:
		return "low"
	}
}

func osIdentity(input Input) string {
	if input.ID != "" {
		return input.ID
	}
	if len(input.IDLike) > 0 {
		return input.IDLike[0]
	}
	return "unknown"
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

func joinOr(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ", ")
}

// compareVersions compares dotted numeric version strings (e.g. "2.28" vs "2.17").
// Returns (1 if a>b, 0 if equal, -1 if a<b) and ok=false if either is non-numeric.
func compareVersions(a, b string) (int, bool) {
	ai, ok1 := parseVersion(a)
	bi, ok2 := parseVersion(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	for i := 0; i < len(ai) || i < len(bi); i++ {
		var x, y int
		if i < len(ai) {
			x = ai[i]
		}
		if i < len(bi) {
			y = bi[i]
		}
		if x < y {
			return -1, true
		}
		if x > y {
			return 1, true
		}
	}
	return 0, true
}

// parseVersion splits "2.28.1" → [2,28,1]; ok=false on non-numeric components.
func parseVersion(s string) ([]int, bool) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n := 0
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return nil, false
			}
			n = n*10 + int(ch-'0')
		}
		out = append(out, n)
	}
	return out, true
}
