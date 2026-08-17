// Package linuxcompat contains AgentBridge's deliberately pragmatic Linux
// compatibility map. It describes upstream relationships, not vendor support
// claims: an inferred RHEL/Debian/SUSE family is a package-selection hint and
// always remains visibly confirmation-required unless the primary ID is in the
// official Veeam rule set.
package linuxcompat

import (
	"fmt"
	"strconv"
	"strings"
)

// Kind is the trust category of an OS-family inference.
type Kind string

const (
	Official Kind = "official"
	Inferred Kind = "inferred"
	Unknown  Kind = "unknown"
	Blocked  Kind = "blocked"
)

// Family is the upstream package/ABI family used for package selection.
type Family string

const (
	RHEL       Family = "rhel"
	Debian     Family = "debian"
	SUSE       Family = "suse"
	RPM        Family = "rpm"
	UnknownRPM Family = "unknown-rpm"
	UnknownDEB Family = "unknown-deb"
	Other      Family = "other"
)

// Profile is the result of resolving /etc/os-release identity to an upstream
// package family. It contains no claim that Veeam supports the OS.
type Profile struct {
	Kind        Kind   `json:"kind"`
	Family      Family `json:"family"`
	DisplayName string `json:"displayName"`
	CanonicalID string `json:"canonicalId"`
	Basis       string `json:"basis"`
	Reason      string `json:"reason,omitempty"`
}

type familyEntry struct {
	family      Family
	displayName string
	kind        Kind
	basis       string
}

// The primary ID takes precedence over ID_LIKE. This prevents a Fedora or
// Arch derivative from inheriting an RHEL rule merely because its metadata
// advertises a broad compatibility token. ID_LIKE is only used when the ID is
// unknown or is a vendor/product alias without a family entry.
var primary = map[string]familyEntry{
	// RHEL and compatible enterprise Linux.
	"rhel":            {RHEL, "Red Hat Enterprise Linux", Official, "primary RHEL identity"},
	"rocky":           {RHEL, "Rocky Linux", Official, "RHEL-compatible enterprise Linux"},
	"almalinux":       {RHEL, "AlmaLinux", Official, "RHEL-compatible enterprise Linux"},
	"oracle":          {RHEL, "Oracle Linux", Official, "RHEL-compatible enterprise Linux"},
	"ol":              {RHEL, "Oracle Linux", Official, "RHEL-compatible enterprise Linux"},
	"centos":          {RHEL, "CentOS Linux", Inferred, "community rebuild of the RHEL source stream"},
	"centoslinux":     {RHEL, "CentOS Linux", Inferred, "community rebuild of the RHEL source stream"},
	"centos-stream":   {RHEL, "CentOS Stream", Inferred, "RHEL development stream; major-version package family"},
	"scientific":      {RHEL, "Scientific Linux", Inferred, "RHEL-compatible community distribution"},
	"scientificlinux": {RHEL, "Scientific Linux", Inferred, "RHEL-compatible community distribution"},
	"springdale":      {RHEL, "Springdale Linux", Inferred, "RHEL-compatible community distribution"},
	"eurolinux":       {RHEL, "EuroLinux", Inferred, "RHEL-compatible enterprise distribution"},
	"euro":            {RHEL, "EuroLinux", Inferred, "RHEL-compatible enterprise distribution"},
	"cloudlinux":      {RHEL, "CloudLinux", Inferred, "RHEL-compatible enterprise distribution"},
	"miraclelinux":    {RHEL, "MIRACLE LINUX", Inferred, "RHEL-compatible enterprise distribution"},
	"miracle":         {RHEL, "MIRACLE LINUX", Inferred, "RHEL-compatible enterprise distribution"},
	"vzlinux":         {RHEL, "Virtuozzo Linux", Inferred, "RHEL-compatible enterprise distribution"},
	"virtuozzolinux":  {RHEL, "Virtuozzo Linux", Inferred, "RHEL-compatible enterprise distribution"},
	"euleros":         {RHEL, "EulerOS", Inferred, "enterprise RPM distribution with RHEL-family compatibility"},
	"openeuler":       {RHEL, "openEuler", Inferred, "enterprise RPM distribution; package family must be verified on target"},
	"anolis":          {RHEL, "Anolis OS", Inferred, "RHEL/CentOS-compatible enterprise distribution"},
	"alinux":          {RHEL, "Alibaba Cloud Linux", Inferred, "RHEL/CentOS-compatible enterprise distribution"},
	"alinux3":         {RHEL, "Alibaba Cloud Linux", Inferred, "RHEL/CentOS-compatible enterprise distribution"},
	"tencentos":       {RHEL, "TencentOS Server", Inferred, "RHEL/CentOS-compatible enterprise distribution"},
	"opencloudos":     {RHEL, "OpenCloudOS", Inferred, "RHEL/CentOS-compatible enterprise distribution"},
	"kylin":           {RHEL, "Kylin Linux", Inferred, "RHEL-family server variant; verify kernel ABI"},
	"neokylin":        {RHEL, "NeoKylin", Inferred, "RHEL-family server variant; verify kernel ABI"},
	"asianux":         {RHEL, "Asianux", Inferred, "RHEL-compatible enterprise distribution"},
	"fusionos":        {RHEL, "FusionOS", Inferred, "RHEL-family enterprise distribution"},
	"h3linux":         {RHEL, "H3Linux", Inferred, "RHEL-family enterprise distribution"},

	// Debian and Ubuntu families.
	"debian":     {Debian, "Debian", Official, "primary Debian identity"},
	"ubuntu":     {Debian, "Ubuntu", Official, "Debian-derived distribution"},
	"linuxmint":  {Debian, "Linux Mint", Inferred, "Ubuntu/Debian-derived distribution"},
	"lmde":       {Debian, "Linux Mint Debian Edition", Inferred, "Debian-derived distribution"},
	"kali":       {Debian, "Kali Linux", Inferred, "Debian-derived distribution"},
	"devuan":     {Debian, "Devuan", Inferred, "Debian-derived distribution"},
	"raspbian":   {Debian, "Raspberry Pi OS", Inferred, "Debian-derived distribution"},
	"deepin":     {Debian, "Deepin", Inferred, "Debian-derived distribution"},
	"uos":        {Debian, "UnionTech OS", Inferred, "Debian-derived variant when ID_LIKE says debian"},
	"uniontech":  {Debian, "UnionTech OS", Inferred, "Debian-derived variant"},
	"neon":       {Debian, "KDE neon", Inferred, "Ubuntu-derived distribution"},
	"pop":        {Debian, "Pop!_OS", Inferred, "Ubuntu-derived distribution"},
	"pop_os":     {Debian, "Pop!_OS", Inferred, "Ubuntu-derived distribution"},
	"elementary": {Debian, "elementary OS", Inferred, "Ubuntu-derived distribution"},
	"zorin":      {Debian, "Zorin OS", Inferred, "Ubuntu-derived distribution"},
	"mx":         {Debian, "MX Linux", Inferred, "Debian-derived distribution"},
	"antix":      {Debian, "antiX", Inferred, "Debian-derived distribution"},
	"parrot":     {Debian, "Parrot OS", Inferred, "Debian-derived distribution"},
	"proxmox":    {Debian, "Proxmox VE", Inferred, "Debian-derived server distribution; kernel must be verified"},
	"pardus":     {Debian, "Pardus", Inferred, "Debian-derived distribution"},
	"bunsenlabs": {Debian, "BunsenLabs", Inferred, "Debian-derived distribution"},
	"kubuntu":    {Debian, "Kubuntu", Inferred, "Ubuntu-derived distribution"},
	"xubuntu":    {Debian, "Xubuntu", Inferred, "Ubuntu-derived distribution"},
	"lubuntu":    {Debian, "Lubuntu", Inferred, "Ubuntu-derived distribution"},

	// RPM-based but not safely interchangeable with the RHEL ABI. These are
	// deliberately not mapped to RHEL; an operator can still use a user-selected
	// package path after validating it, but the automatic EL filename filter will
	// not pretend it is a clone.
	"fedora":       {RPM, "Fedora", Inferred, "RPM-based but not a RHEL binary-compatible release"},
	"amazon":       {RPM, "Amazon Linux", Inferred, "RPM-based cloud distribution with its own ABI/repositories"},
	"amzn":         {RPM, "Amazon Linux", Inferred, "RPM-based cloud distribution with its own ABI/repositories"},
	"mageia":       {RPM, "Mageia", Inferred, "RPM-based but not a RHEL binary-compatible release"},
	"openmandriva": {RPM, "OpenMandriva", Inferred, "RPM-based but not a RHEL binary-compatible release"},
	"rosa":         {RPM, "ROSA Linux", Inferred, "RPM-based but not a RHEL binary-compatible release"},
	"pclinuxos":    {RPM, "PCLinuxOS", Inferred, "RPM-based but not a RHEL binary-compatible release"},

	// SUSE/openSUSE family.
	"sles":                {SUSE, "SUSE Linux Enterprise Server", Official, "primary SLES identity"},
	"sles_sap":            {SUSE, "SLES for SAP", Official, "SLES family"},
	"opensuse":            {SUSE, "openSUSE", Inferred, "SUSE-family distribution"},
	"opensuse-leap":       {SUSE, "openSUSE Leap", Inferred, "SUSE-family distribution"},
	"opensuse-tumbleweed": {SUSE, "openSUSE Tumbleweed", Inferred, "rolling SUSE-family distribution; kernel risk is high"},

	// These systems use a different libc/package model. Do not silently feed
	// them an RHEL or Debian Agent package.
	"alpine":         {Other, "Alpine Linux", Blocked, "musl libc and APK package model are not RPM/DEB compatible"},
	"arch":           {Other, "Arch Linux", Blocked, "pacman/rolling package model is not an RHEL/Debian package target"},
	"manjaro":        {Other, "Manjaro", Blocked, "Arch-derived rolling package model"},
	"endeavouros":    {Other, "EndeavourOS", Blocked, "Arch-derived rolling package model"},
	"gentoo":         {Other, "Gentoo", Blocked, "source-oriented package model"},
	"nixos":          {Other, "NixOS", Blocked, "Nix package/store model is not an RPM/DEB target"},
	"void":           {Other, "Void Linux", Blocked, "XBPS/musl-or-glibc package model is not an RPM/DEB target"},
	"clear-linux-os": {Other, "Clear Linux", Blocked, "non-RPM/DEB package model"},
}

var likeFamily = map[string]familyEntry{
	"rhel":     {RHEL, "RHEL-compatible Linux", Inferred, "ID_LIKE contains rhel"},
	"fedora":   {RHEL, "Fedora/RHEL-family RPM Linux", Inferred, "ID_LIKE contains fedora; package ABI still requires confirmation"},
	"debian":   {Debian, "Debian-derived Linux", Inferred, "ID_LIKE contains debian"},
	"ubuntu":   {Debian, "Ubuntu-derived Linux", Inferred, "ID_LIKE contains ubuntu"},
	"suse":     {SUSE, "SUSE-derived Linux", Inferred, "ID_LIKE contains suse"},
	"opensuse": {SUSE, "SUSE-derived Linux", Inferred, "ID_LIKE contains opensuse"},
}

// Resolve maps an os-release ID and ID_LIKE list to an upstream package family.
// packageFormat is used only to choose the generic unknown profile; the caller
// still must match the actual RPM/DEB payload and target architecture.
func Resolve(id string, idLike []string, packageFormat string) Profile {
	normalizedID := normalize(id)
	if entry, ok := primary[normalizedID]; ok {
		return profile(entry, normalizedID, idLike)
	}
	for _, like := range idLike {
		if entry, ok := likeFamily[normalize(like)]; ok {
			return profile(entry, normalizedID, idLike)
		}
	}
	format := strings.ToLower(strings.TrimSpace(packageFormat))
	switch format {
	case "rpm":
		return Profile{Kind: Unknown, Family: UnknownRPM, DisplayName: "Unknown RPM Linux", CanonicalID: "rpm", Basis: "package format is RPM", Reason: "no known upstream family; inspect RPM headers and require confirmation"}
	case "deb":
		return Profile{Kind: Unknown, Family: UnknownDEB, DisplayName: "Unknown DEB Linux", CanonicalID: "deb", Basis: "package format is DEB", Reason: "no known upstream family; inspect DEB metadata and require confirmation"}
	default:
		return Profile{Kind: Blocked, Family: Other, DisplayName: "Unknown Linux", CanonicalID: "unknown", Basis: "no RPM/DEB package format", Reason: "target package format is not RPM or DEB"}
	}
}

func profile(entry familyEntry, id string, idLike []string) Profile {
	// A vendor ID can be a generic product label whose ID_LIKE gives the more
	// accurate family. UOS is the notable example: prefer explicit Debian-like
	// metadata when it is present.
	if id == "uos" || id == "uniontech" {
		for _, like := range idLike {
			if normalize(like) == "rhel" || normalize(like) == "centos" {
				return Profile{Kind: Inferred, Family: RHEL, DisplayName: "UnionTech OS (RHEL-like)", CanonicalID: "rhel", Basis: "primary UOS identity + ID_LIKE rhel", Reason: "vendor variant; verify its server base before selecting RPMs"}
			}
		}
	}
	canonical := string(entry.family)
	switch id {
	case "rhel", "debian", "ubuntu", "sles", "sles_sap", "oracle", "ol":
		canonical = id
	}
	return Profile{Kind: entry.kind, Family: entry.family, DisplayName: entry.displayName, CanonicalID: canonical, Basis: entry.basis}
}

// CanonicalPackageID returns the profile name shown in recommendations. It is
// intentionally a hint, not required to equal a VBR catalog display string.
func CanonicalPackageID(p Profile, major, arch string) string {
	major = majorNumber(major)
	arch = normalizeArch(arch)
	if major == "" {
		major = "generic"
	}
	if arch == "" {
		arch = "unknown"
	}
	switch p.Family {
	case RHEL, RPM:
		if p.CanonicalID == "oracle" || p.CanonicalID == "ol" {
			return fmt.Sprintf("oracle%s-%s", major, arch)
		}
		return fmt.Sprintf("rhel%s-%s", major, arch)
	case Debian:
		if p.CanonicalID == "ubuntu" {
			return fmt.Sprintf("ubuntu%s-%s", major, arch)
		}
		return fmt.Sprintf("debian%s-%s", major, arch)
	case SUSE:
		return fmt.Sprintf("sles%s-%s", major, arch)
	default:
		return fmt.Sprintf("%s-%s", string(p.Family), arch)
	}
}

func normalize(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.Trim(value, "\"")
	return strings.ReplaceAll(value, " ", "-")
}

func majorNumber(value string) string {
	value = strings.TrimSpace(value)
	start := 0
	for start < len(value) && (value[start] < '0' || value[start] > '9') {
		start++
	}
	end := start
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	if start == end {
		return ""
	}
	major, _ := strconv.Atoi(value[start:end])
	return strconv.Itoa(major)
}

func normalizeArch(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "amd64", "x86-64", "x86_64":
		return "x86_64"
	case "arm64", "aarch64":
		return "aarch64"
	case "ppc64el", "ppc64le":
		return "ppc64le"
	case "s390x":
		return "s390x"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}
