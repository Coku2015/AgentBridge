// Package templates holds the fixed, strictly-quoted shell command builders and
// the probe script used by every BootstrapExecutor.
//
// Red line 5 (no shell injection) is enforced HERE, by construction:
//   - ShellQuote is the single chokepoint that wraps every interpolated value
//     in single quotes and neutralizes embedded single quotes;
//   - no command builder ever concatenates a raw caller string into a shell
//     string without going through ShellQuote;
//   - the probe script is fully static (no interpolation at all).
//
// These builders are transport-agnostic strings; they never dial anything.
package templates

import (
	"fmt"
	"strings"
)

// ShellQuote wraps s in single quotes so the result is a single POSIX shell
// argument with no metacharacter interpretation. Embedded single quotes are
// escaped with the standard '\” sequence. It never returns the input unquoted.
//
// This is the ONLY place user/target-derived strings may become part of a
// shell command (red line 5, AB-FR-124).
func ShellQuote(s string) string {
	// Replace every ' with '\'': closes the quote, inserts an escaped literal
	// single quote, reopens the quote.
	escaped := strings.ReplaceAll(s, "'", `'\''`)
	return "'" + escaped + "'"
}

// PrivilegeMode selects the already-validated elevation mechanism used for
// install/verify commands (AB-FR-120). Passwords are never embedded in these
// strings: the executor supplies them through the SSH channel's stdin.
type PrivilegeMode string

const (
	PrivRoot         PrivilegeMode = "root"          // connected account is root
	PrivSudoNOP      PrivilegeMode = "sudo-nopasswd" // sudo -n succeeds
	PrivSudoPassword PrivilegeMode = "sudo-password" // sudo reads account password from stdin
	PrivSu           PrivilegeMode = "su"            // su reads root password from stdin
)

// ApplyPrivilege wraps a fixed command with one of the known privilege
// mechanisms. The command must itself come from this templates package. The
// su case quotes the entire command as a single -c argument.
func ApplyPrivilege(cmd string, mode PrivilegeMode) string {
	switch mode {
	case PrivSudoNOP:
		return "sudo -n -- " + cmd
	case PrivSudoPassword:
		return "sudo -S -p '' -- " + cmd
	case PrivSu:
		return "su - root -c " + ShellQuote(cmd)
	default:
		return cmd
	}
}

// UploadOpenCmd is the remote decoder command whose stdin receives the streamed
// package bytes over the SSH exec channel (no SFTP, AB-FR-122). remotePath is
// quoted. The stream is written atomically to a temp file then renamed so a
// partial upload is never installable.
func UploadOpenCmd(remotePath string) string {
	dir := ShellQuote(posixDir(remotePath))
	tmp := ShellQuote(remotePath + ".part")
	final := ShellQuote(remotePath)
	// cat > tmp; then mv tmp final; mkdir -p dir is the caller's responsibility.
	return fmt.Sprintf("mkdir -p %s && cat > %s && mv %s %s", dir, tmp, tmp, final)
}

// posixDir returns the directory portion of a POSIX path.
func posixDir(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		if i == 0 {
			return "/"
		}
		return p[:i]
	}
	return "."
}

// InstallKitCmd builds the fixed Deployment Kit install command: run the kit's
// OFFICIAL installer (install-deployment-kit.sh) with bash from its extraction
// directory. The kit archive is a ZIP and is NEVER executed directly (that is
// the exit-126 bug: sh reading binary garbage). The installer takes no
// arguments and auto-locates the sibling packages and certificates shipped
// next to it. bash is required — the official script uses bash builtins
// (compgen, declare). scriptPath is the only interpolated value and is quoted.
func InstallKitCmd(scriptPath string, mode PrivilegeMode) string {
	return ApplyPrivilege("bash "+ShellQuote(scriptPath), mode)
}

// InstallAgentCmd installs a target-matched Agent artifact. The server has
// already reduced a VBR superset export to one compatible role set; this fixed
// command only handles the transport format and never asks a package manager
// to reach an unconfigured public repository.
func InstallAgentCmd(packagePath string, mode PrivilegeMode) string {
	pathArg := ShellQuote(packagePath)
	script := `set -eu
p=` + pathArg + `
case "$p" in
  *.rpm) rpm -Uvh "$p" ;;
  *.deb) dpkg -i "$p" ;;
  *.tar.gz|*.tgz)
    d=$(mktemp -d /tmp/agentbridge-agent-set.XXXXXX)
    trap 'rm -rf "$d"' EXIT
    tar -xzf "$p" -C "$d"
    if find "$d" -type f -name '*.rpm' -print -quit | grep -q .; then
      find "$d" -type f -name '*.rpm' -exec rpm -Uvh {} +
    elif find "$d" -type f -name '*.deb' -print -quit | grep -q .; then
      find "$d" -type f -name '*.deb' -exec dpkg -i {} +
    else
      echo 'selected Agent package set contains no RPM/DEB payloads' >&2
      exit 1
    fi
    ;;
  *) echo 'unsupported selected Agent package format' >&2; exit 1 ;;
esac`
	return ApplyPrivilege("sh -c "+ShellQuote(script), mode)
}

// VerifyCmd builds the post-install verification command (AB-FR-164). It emits
// a fixed set of package/service facts as plain text the executor parses; it
// takes NO caller-supplied arguments at all. Unit/package names are fixed
// constants. Each fact stays an independent layer (Principle IV), whether the
// Agent was installed in this run or will be enrolled later through VBR.
func VerifyCmd(mode PrivilegeMode) string {
	return ApplyPrivilege("sh -c "+ShellQuote(
		`package_version() {
  package=$1
  if command -v rpm >/dev/null 2>&1 && rpm -q "$package" >/dev/null 2>&1; then
    rpm -q --qf '%{VERSION}-%{RELEASE}' "$package" 2>/dev/null
    return
  fi
  if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W "$package" >/dev/null 2>&1; then
    dpkg-query -W -f='${Version}' "$package" 2>/dev/null
    return
  fi
  return 1
}
agent_ver=$(package_version veeam || true)
kit_ver=$(package_version veeamdeployment || true)
deployer=unknown
agent_service=unknown
if command -v systemctl >/dev/null 2>&1; then
  for unit in veeamdeployment veeamdeploymentsvc; do
    state=$(systemctl is-active "$unit" 2>/dev/null || true)
    if [ "$state" = active ]; then deployer=active; break; fi
    if [ -n "$state" ] && [ "$state" != unknown ]; then deployer=$state; fi
  done
  state=$(systemctl is-active veeam.service 2>/dev/null || true)
  if [ -n "$state" ]; then agent_service=$state; fi
fi
[ -n "$agent_ver" ] || agent_ver=none
[ -n "$kit_ver" ] || kit_ver=none
echo "pkg:veeam"
echo "ver:$agent_ver"
echo "kitver:$kit_ver"
echo "deployer:$deployer"
echo "agent:$agent_service"`,
	), mode)
}

// KitInstalledCmd confirms the deployment-service package is present in the
// local RPM database. Install uses it to tell yum/dnf's "Nothing to do"
// refusal (same version already installed — the idempotent success case,
// red line 6) apart from a real installer failure. It interpolates nothing;
// rpm -q needs no privileges.
func KitInstalledCmd() string {
	return "rpm -q veeamdeployment"
}

// CleanupCmd removes the whole staging dir holding the extracted kit files
// (plus any leftover .part upload). dir is quoted.
func CleanupCmd(dir string) string {
	return "rm -rf " + ShellQuote(dir)
}

// ProbeScript is the fully static POSIX shell fact-gathering script. It takes NO
// arguments and interpolates nothing — it is a constant. Output is versioned
// JSON (schema 1.0) consumed by the matcher via probe.Result.
//
// It uses only POSIX sh + uname + standard /etc/os-release parsing; it needs no
// Python/Ansible and no root (AB-NFR-009, AB-FR-081..083).
const ProbeScript = `set -u
emit() { printf '%s' "$1"; }
os_id=""; os_ver=""; os_like=""
if [ -f /etc/os-release ]; then
  while IFS='=' read -r k v; do
    case "$k" in
      ID) os_id=${v//\"/} ;;
      VERSION_ID) os_ver=${v//\"/} ;;
      ID_LIKE) os_like=${v//\"/} ;;
    esac
  done < /etc/os-release
fi
arch=$(uname -m 2>/dev/null || echo "")
kernel=$(uname -r 2>/dev/null || echo "")
glibc=""
if command -v ldd >/dev/null 2>&1; then
  glibc=$(ldd --version 2>/dev/null | head -n1 | sed -n 's/.* \([0-9][0-9.]*\)$/\1/p')
fi
pf="unknown"; pm="unknown"
if command -v rpm >/dev/null 2>&1; then pf="rpm"; pm="rpm"; fi
if command -v dnf >/dev/null 2>&1; then pm="dnf"; elif command -v yum >/dev/null 2>&1; then pm="yum"; fi
if [ "$pf" = "unknown" ] && command -v dpkg >/dev/null 2>&1; then pf="deb"; fi
if command -v apt-get >/dev/null 2>&1; then pm="apt"; fi
[ "$pm" = "rpm" ] && pm="yum"
rhel_macro=""
if [ -f /etc/rpm/macros ]; then rhel_macro=$(grep -i '%_arch' /etc/rpm/macros 2>/dev/null | head -n1); fi
sb="unknown"
if command -v mokutil >/dev/null 2>&1; then
  if mokutil --sb-state 2>/dev/null | grep -qi 'secureboot enabled'; then
    sb="enabled"
  elif mokutil --sb-state 2>/dev/null | grep -qi 'secureboot disabled'; then
    sb="disabled"
  fi
elif [ -d /sys/firmware/efi/efivars ]; then
  for sb_file in /sys/firmware/efi/efivars/SecureBoot-*; do
    [ -f "$sb_file" ] || continue
    sb_byte=$(od -An -t u1 "$sb_file" 2>/dev/null | awk '{last=$NF} END{print last}')
    [ "$sb_byte" = "1" ] && sb="enabled"
    [ "$sb_byte" = "0" ] && sb="disabled"
    break
  done
fi
veeam_pkgs=""
if command -v rpm >/dev/null 2>&1; then veeam_pkgs=$(rpm -qa 'veeam*' 2>/dev/null | tr '\n' ','); fi
tmp_bytes=0
tmp_bytes=$(df -P /tmp 2>/dev/null | awk 'NR==2{print $4}')
host=$(hostname 2>/dev/null || echo "")
printf '{"schemaVersion":"1.0","target":{"hostName":"%s","architecture":"%s"},"os":{"id":"%s","versionId":"%s","idLike":"%s"},"kernel":"%s","glibc":"%s","packageFormat":"%s","packageManager":"%s","rhelMacro":"%s","secureBoot":"%s","existingVeeamPackages":"%s","availableTempBytes":%s}' \
  "$host" "$arch" "$os_id" "$os_ver" "$os_like" "$kernel" "$glibc" "$pf" "$pm" "$rhel_macro" "$sb" "$veeam_pkgs" "${tmp_bytes:-0}"`
