package packages

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Coku2015/agentbridge/internal/linuxcompat"
	"github.com/Coku2015/agentbridge/internal/probe"
)

// Selection is the auditable package decision made for one target. VBR may
// return a superset archive containing standard/nosnap variants, kernel module
// alternatives, or payloads for more than one package format. The installer
// must receive only the role-complete set matching the target facts.
type Selection struct {
	PackageName                  string    `json:"packageName"`
	TargetFormat                 string    `json:"targetFormat"`
	TargetArchitecture           string    `json:"targetArchitecture"`
	TargetOS                     string    `json:"targetOS"`
	TargetVersion                string    `json:"targetVersion"`
	CompatibilityFamily          string    `json:"compatibilityFamily"`
	CompatibilityBasis           string    `json:"compatibilityBasis"`
	Mode                         string    `json:"mode"` // "standard" or "nosnap"
	Selected                     []Payload `json:"selected"`
	Excluded                     []Payload `json:"excluded"`
	Warnings                     []string  `json:"warnings,omitempty"`
	RequiresExplicitConfirmation bool      `json:"requiresExplicitConfirmation"`
}

// SelectForTarget reads a cached VBR export, matches its payloads to a target
// probe, and writes a new artifact containing only the required Veeam roles.
// The source artifact is never modified. The returned artifact is temporary
// and should be removed after it has been uploaded or bundled.
func (s *ArtifactStore) SelectForTarget(sourcePath, packageName string, target probe.Result) (Artifact, Selection, error) {
	entries, err := readPackageEntries(sourcePath)
	if err != nil {
		return Artifact{}, Selection{}, fmt.Errorf("packages: inspect artifact: %w", err)
	}
	selection, selected, err := selectEntries(entries, packageName, target)
	if err != nil {
		return Artifact{}, selection, err
	}
	artifact, err := s.writePayloads(selected, packageName)
	if err != nil {
		return Artifact{}, selection, err
	}
	return artifact, selection, nil
}

func readPackageEntries(sourcePath string) ([]packageEntry, error) {
	raw, err := os.ReadFile(sourcePath)
	if err != nil {
		return nil, err
	}
	ext := strings.ToLower(filepath.Ext(sourcePath))
	if ext == ".rpm" || ext == ".deb" {
		return []packageEntry{{name: filepath.Base(sourcePath), data: raw}}, nil
	}
	return packageEntries(raw)
}

func selectEntries(entries []packageEntry, packageName string, target probe.Result) (Selection, []packageEntry, error) {
	selection := Selection{
		PackageName:        packageName,
		TargetFormat:       strings.ToLower(strings.TrimSpace(target.PackageFormat)),
		TargetArchitecture: normalizeArch(target.Target.Architecture),
		TargetOS:           strings.ToLower(strings.TrimSpace(target.OS.ID)),
		TargetVersion:      target.OS.VersionID,
		Mode:               "standard",
	}
	if strings.Contains(strings.ToLower(packageName), "nosnap") {
		selection.Mode = "nosnap"
	}
	if selection.TargetFormat != "rpm" && selection.TargetFormat != "deb" {
		return selection, nil, fmt.Errorf("packages: target package format %q is not supported", target.PackageFormat)
	}
	if selection.TargetArchitecture == "" {
		return selection, nil, fmt.Errorf("packages: target architecture is missing")
	}

	compat := linuxcompat.Resolve(target.OS.ID, target.OS.IDLike, selection.TargetFormat)
	selection.CompatibilityFamily = string(compat.Family)
	selection.CompatibilityBasis = compat.Basis
	if len(target.ExistingVeeamPackages) > 0 {
		selection.RequiresExplicitConfirmation = true
		selection.Warnings = append(selection.Warnings, "existing Veeam packages detected; automatic replacement is disabled")
	}
	if compat.Kind != linuxcompat.Official {
		selection.RequiresExplicitConfirmation = true
		if compat.Kind == linuxcompat.Blocked {
			selection.Warnings = append(selection.Warnings, "target uses a non-standard Linux package/libc model; only continue if the operator has validated this package path")
		} else if compat.Kind == linuxcompat.Unknown {
			selection.Warnings = append(selection.Warnings, "target distribution is unknown; package-header compatibility is being used and explicit confirmation is required")
		} else {
			selection.Warnings = append(selection.Warnings, fmt.Sprintf("target is inferred as %s from %s; this is not a Veeam support claim and requires confirmation", compat.Family, compat.Basis))
		}
	}

	candidates := map[string][]candidate{}
	for _, entry := range entries {
		payload := payloadForEntry(entry)
		selection.Excluded = append(selection.Excluded, payload)
		if !payloadMatchesTarget(entry.name, target, selection.TargetFormat, selection.TargetArchitecture) {
			continue
		}
		if payload.Role == "deployment" || payload.Role == "release" || payload.Role == "unknown" {
			continue
		}
		candidates[payload.Role] = append(candidates[payload.Role], candidate{entry: entry, payload: payload, score: candidateScore(entry.name, payload.Role, target)})
	}

	if selection.Mode == "standard" && canUsePowerNosnapFallback(selection, candidates) {
		selection.Mode = "nosnap"
		selection.RequiresExplicitConfirmation = true
		selection.Warnings = append(selection.Warnings, "this architecture has no standard Veeam kernel-module payload in the export; selecting the Power/no-snapshot package set")
	}

	roles := []string{"libs", "nosnap"}
	if selection.Mode == "standard" {
		roles = []string{"snapshot", "libs", "agent"}
	}
	selected := make([]packageEntry, 0, len(roles)+1)
	for _, role := range roles {
		chosen, ok := bestCandidate(candidates[role])
		if !ok {
			return selection, nil, fmt.Errorf("packages: target %s %s requires a %s payload, but the VBR export did not contain a matching file", target.OS.ID, target.OS.VersionID, role)
		}
		selected = append(selected, chosen.entry)
		selection.Selected = append(selection.Selected, chosen.payload)
	}
	if strings.EqualFold(target.SecureBoot, "enabled") {
		if chosen, ok := bestCandidate(candidates["uefi-cert"]); ok {
			selected = append(selected, chosen.entry)
			selection.Selected = append(selection.Selected, chosen.payload)
		} else {
			selection.Warnings = append(selection.Warnings, "Secure Boot is enabled but the export has no veeam-ueficert payload")
		}
	}

	selectedNames := make(map[string]struct{}, len(selected))
	for _, entry := range selected {
		selectedNames[filepath.Base(entry.name)] = struct{}{}
	}
	filtered := selection.Excluded[:0]
	for _, payload := range selection.Excluded {
		if _, ok := selectedNames[payload.FileName]; ok {
			continue
		}
		filtered = append(filtered, payload)
	}
	selection.Excluded = filtered
	sort.SliceStable(selection.Selected, func(i, j int) bool {
		return roleRank(selection.Selected[i].Role) < roleRank(selection.Selected[j].Role)
	})
	return selection, selected, nil
}

type candidate struct {
	entry   packageEntry
	payload Payload
	score   int
}

func bestCandidate(items []candidate) (candidate, bool) {
	if len(items) == 0 {
		return candidate{}, false
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].score != items[j].score {
			return items[i].score > items[j].score
		}
		return items[i].entry.name < items[j].entry.name
	})
	return items[0], true
}

func payloadForEntry(entry packageEntry) Payload {
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(entry.name)), ".")
	sum := sha256Bytes(entry.data)
	return Payload{
		FileName: filepath.Base(entry.name),
		Format:   ext,
		Role:     packageRole(entry.name),
		Size:     int64(len(entry.data)),
		SHA256:   sum,
	}
}

func sha256Bytes(data []byte) string {
	// Keep this helper local to selection so the decision result can be built
	// without exposing packageEntry or changing the artifact writer contract.
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func payloadMatchesTarget(name string, target probe.Result, format, arch string) bool {
	base := strings.ToLower(filepath.Base(name))
	if strings.ToLower(strings.TrimPrefix(filepath.Ext(base), ".")) != format {
		return false
	}
	if !archHintMatches(base, arch) {
		return false
	}
	if major := filenameOSMajor(base); major != 0 && targetMajor(target.OS.VersionID) != 0 && major != targetMajor(target.OS.VersionID) {
		return false
	}
	compat := linuxcompat.Resolve(target.OS.ID, target.OS.IDLike, format)
	if strings.Contains(base, ".sle") || strings.Contains(base, "-sle") {
		if compat.Family != linuxcompat.SUSE && compat.Family != linuxcompat.UnknownRPM {
			return false
		}
		if major := filenameSLEMajor(base); major != 0 {
			targetMajor := targetMajor(target.OS.VersionID)
			// SLES 16 intentionally reuses the .sle15 Agent RPM; the
			// kernel-module payload carries the SLE16-specific ABI marker.
			if major == 12 {
				return targetMajor == 12
			}
			return targetMajor == 15 || targetMajor == 16
		}
		return true
	}
	if strings.Contains(base, ".el") || strings.Contains(base, "-el") {
		return compat.Family == linuxcompat.RHEL || compat.Family == linuxcompat.RPM || compat.Family == linuxcompat.UnknownRPM
	}
	return true
}

func candidateScore(name, role string, target probe.Result) int {
	base := strings.ToLower(filepath.Base(name))
	compat := linuxcompat.Resolve(target.OS.ID, target.OS.IDLike, target.PackageFormat)
	score := 0
	if major := filenameOSMajor(base); major != 0 && major == targetMajor(target.OS.VersionID) {
		score += 10
	}
	if role == "snapshot" {
		major := targetMajor(target.OS.VersionID)
		switch {
		case compat.Family == linuxcompat.SUSE:
			// SLES's pre-built module is the kernel-flavor-specific KMP.
			// The generic noarch blksnap/veeamsnap source package is not
			// the generated setup-file choice.
			if strings.Contains(base, "-kmp-") {
				score += 40
				kernel := strings.ToLower(target.Kernel)
				if strings.Contains(base, "kmp-preempt") {
					if strings.Contains(kernel, "preempt") {
						score += 20
					} else {
						score -= 10
					}
				} else if strings.Contains(base, "kmp-default") {
					if strings.Contains(kernel, "preempt") {
						score -= 10
					} else {
						score += 20
					}
				}
			} else {
				score -= 20
			}
		case target.PackageFormat == "deb":
			// Veeam's Debian/Ubuntu split is Debian 10 and older:
			// veeamsnap; Debian 11+ and Ubuntu 22+: blksnap.
			if major >= 11 && strings.Contains(base, "blksnap") {
				score += 30
			}
			if major > 0 && major < 11 && strings.Contains(base, "veeamsnap") {
				score += 30
			}
		default:
			if major >= 9 && strings.Contains(base, "blksnap") {
				score += 30
			}
			if major > 0 && major < 9 && strings.Contains(base, "veeamsnap") {
				score += 30
			}
			if !hasOSLike(target, "ol", "oracle") && strings.Contains(base, "kmod-") {
				score += 5
			}
		}
	}
	return score
}

func packageRole(name string) string {
	base := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(base, "veeam-ueficert"):
		return "uefi-cert"
	case strings.Contains(base, "veeam-release"):
		return "release"
	case strings.Contains(base, "veeam-libs"):
		return "libs"
	case strings.Contains(base, "veeam-nosnap"):
		return "nosnap"
	case strings.Contains(base, "kmod-veeamsnap"), strings.Contains(base, "veeamsnap"), strings.Contains(base, "kmod-blksnap"), strings.Contains(base, "blksnap"):
		return "snapshot"
	case strings.Contains(base, "veeamdeployment"), strings.Contains(base, "veeam-deployment"):
		return "deployment"
	case strings.HasPrefix(base, "veeam-") || strings.HasPrefix(base, "veeam_"):
		return "agent"
	default:
		return "unknown"
	}
}

func roleRank(role string) int {
	switch role {
	case "snapshot":
		return 0
	case "libs":
		return 1
	case "agent", "nosnap":
		return 2
	case "uefi-cert":
		return 3
	default:
		return 9
	}
}

func archHintMatches(name, targetArch string) bool {
	targetArch = normalizeArch(targetArch)
	if strings.Contains(name, ".noarch.") || strings.Contains(name, "_all.") {
		return true
	}
	for _, hint := range archHints(targetArch) {
		if strings.Contains(name, "."+hint+".") || strings.Contains(name, "_"+hint+".") || strings.Contains(name, "-"+hint+".") {
			return true
		}
	}
	return false
}

func archHints(arch string) []string {
	switch normalizeArch(arch) {
	case "x86_64":
		return []string{"x86_64", "amd64"}
	case "aarch64":
		return []string{"aarch64", "arm64"}
	case "ppc64le":
		return []string{"ppc64le"}
	case "s390x":
		return []string{"s390x"}
	default:
		return []string{arch}
	}
}

func normalizeArch(arch string) string {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "amd64", "x86-64", "x86_64":
		return "x86_64"
	case "arm64", "aarch64":
		return "aarch64"
	case "ppc64el", "ppc64le":
		return "ppc64le"
	default:
		return strings.ToLower(strings.TrimSpace(arch))
	}
}

func targetMajor(version string) int {
	version = strings.TrimSpace(version)
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
	major, _ := strconv.Atoi(version[start:end])
	return major
}

func filenameOSMajor(name string) int {
	for i := 0; i+3 < len(name); i++ {
		if name[i:i+3] != ".el" && name[i:i+3] != "-el" {
			continue
		}
		start := i + 3
		end := start
		for end < len(name) && name[end] >= '0' && name[end] <= '9' {
			end++
		}
		if end > start {
			major, _ := strconv.Atoi(name[start:end])
			return major
		}
	}
	return 0
}

func filenameSLEMajor(name string) int {
	for i := 0; i+4 < len(name); i++ {
		start := 0
		switch {
		case strings.HasPrefix(name[i:], ".sle"):
			start = i + 4
		case strings.HasPrefix(name[i:], "-sle"), strings.HasPrefix(name[i:], "sles"):
			start = i + 4
		default:
			continue
		}
		end := start
		for end < len(name) && name[end] >= '0' && name[end] <= '9' {
			end++
		}
		if end > start {
			major, _ := strconv.Atoi(name[start:end])
			return major
		}
	}
	return 0
}

func canUsePowerNosnapFallback(selection Selection, candidates map[string][]candidate) bool {
	if selection.TargetFormat != "rpm" || selection.TargetArchitecture != "ppc64le" {
		return false
	}
	if selection.CompatibilityFamily != string(linuxcompat.RHEL) && selection.CompatibilityFamily != string(linuxcompat.SUSE) {
		return false
	}
	return len(candidates["libs"]) > 0 && len(candidates["nosnap"]) > 0 &&
		len(candidates["snapshot"]) == 0 && len(candidates["agent"]) == 0
}

func hasOSLike(target probe.Result, values ...string) bool {
	for _, candidate := range append([]string{target.OS.ID}, target.OS.IDLike...) {
		candidate = strings.ToLower(candidate)
		for _, value := range values {
			if candidate == value {
				return true
			}
		}
	}
	return false
}
