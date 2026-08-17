package executor

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Coku2015/agentbridge/internal/executor/templates"
)

const privilegeCommandTimeout = 15 * time.Second

// PrivilegeRequest is the memory-only privilege policy selected for one Linux
// host. SudoPassword belongs to the connected account. RootPassword is used
// only for an explicitly selected sudoers update or su fallback.
type PrivilegeRequest struct {
	Elevate       bool
	SudoPassword  []byte
	AddToSudoers  bool
	UseSuFallback bool
	RootPassword  []byte
}

// PrivilegeResult records only non-secret facts that the UI may display and
// the install executor may reuse. It does not prove VBR certificate trust.
type PrivilegeResult struct {
	Mode              templates.PrivilegeMode `json:"mode"`
	ConfiguredSudoers bool                    `json:"configuredSudoers"`
	UsedSuFallback    bool                    `json:"usedSuFallback"`
}

// PrivilegeError carries a stable public classification while retaining the
// technical cause for server logs. Error never includes a password.
type PrivilegeError struct {
	Code  string
	Cause error
}

func (e *PrivilegeError) Error() string {
	if e == nil {
		return ""
	}
	if e.Cause == nil {
		return "privilege: " + e.Code
	}
	return "privilege: " + e.Code + ": " + e.Cause.Error()
}

func (e *PrivilegeError) Unwrap() error { return e.Cause }

// PrivilegeErrorCode returns the stable classification for HTTP presentation.
func PrivilegeErrorCode(err error) string {
	var target *PrivilegeError
	if errors.As(err, &target) {
		return target.Code
	}
	return ""
}

func privilegeFailure(code string, cause error) error {
	return &PrivilegeError{Code: code, Cause: cause}
}

// ResolvePrivilege verifies the connected account and selects an elevation
// mechanism before package work begins. It may update /etc/sudoers.d only when
// AddToSudoers is explicitly true.
func ResolvePrivilege(ctx context.Context, sess RemoteSession, req PrivilegeRequest) (PrivilegeResult, error) {
	out, err := sess.Run(ctx, "id -u")
	if err != nil {
		return PrivilegeResult{}, privilegeFailure("privilege_identity_failed", err)
	}
	uidText := strings.TrimSpace(string(out))
	uid, err := strconv.Atoi(uidText)
	if err != nil || uid < 0 {
		return PrivilegeResult{}, privilegeFailure("privilege_identity_failed", fmt.Errorf("unexpected numeric uid response"))
	}
	if uid == 0 {
		return PrivilegeResult{Mode: templates.PrivRoot}, nil
	}
	if !req.Elevate {
		return PrivilegeResult{}, privilegeFailure("privilege_required", nil)
	}

	if req.AddToSudoers {
		if len(req.RootPassword) == 0 {
			return PrivilegeResult{}, privilegeFailure("root_password_required", nil)
		}
		rootOut, rootErr := runPrivilegeSecret(ctx, sess, templates.ApplyPrivilege("printf AB_ROOT_OK", templates.PrivSu), req.RootPassword, true)
		if rootErr != nil || !strings.Contains(string(rootOut), "AB_ROOT_OK") {
			return PrivilegeResult{}, classifySuFailure(rootOut, rootErr)
		}
		cmd := templates.ApplyPrivilege(sudoersInstallCommand(uid), templates.PrivSu)
		setupOut, setupErr := runPrivilegeSecret(ctx, sess, cmd, req.RootPassword, true)
		if setupErr != nil {
			return PrivilegeResult{}, classifySudoersFailure(setupOut, setupErr)
		}
		if ok, testErr := testNOPASSWD(ctx, sess); !ok {
			return PrivilegeResult{}, privilegeFailure("sudoers_update_failed", testErr)
		}
		return PrivilegeResult{Mode: templates.PrivSudoNOP, ConfiguredSudoers: true}, nil
	}

	if ok, _ := testNOPASSWD(ctx, sess); ok {
		return PrivilegeResult{Mode: templates.PrivSudoNOP}, nil
	}

	if len(req.SudoPassword) > 0 {
		out, sudoErr := runSudoPassword(ctx, sess, templates.ApplyPrivilege("id -u", templates.PrivSudoPassword), req.SudoPassword)
		if sudoErr == nil && reportsRoot(out) {
			return PrivilegeResult{Mode: templates.PrivSudoPassword}, nil
		}
		if !req.UseSuFallback {
			return PrivilegeResult{}, classifySudoFailure(out, sudoErr)
		}
	} else if !req.UseSuFallback {
		return PrivilegeResult{}, privilegeFailure("sudo_password_required", nil)
	}

	if req.UseSuFallback {
		if len(req.RootPassword) == 0 {
			return PrivilegeResult{}, privilegeFailure("root_password_required", nil)
		}
		out, suErr := runPrivilegeSecret(ctx, sess, templates.ApplyPrivilege("id -u", templates.PrivSu), req.RootPassword, true)
		if suErr != nil || !reportsRoot(out) {
			return PrivilegeResult{}, classifySuFailure(out, suErr)
		}
		return PrivilegeResult{Mode: templates.PrivSu, UsedSuFallback: true}, nil
	}

	return PrivilegeResult{}, privilegeFailure("privilege_escalation_failed", nil)
}

func runPrivilegeSecret(ctx context.Context, sess RemoteSession, cmd string, secret []byte, requestPTY bool) ([]byte, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, privilegeCommandTimeout)
	defer cancel()
	return sess.RunWithSecret(attemptCtx, cmd, secret, requestPTY)
}

func runSudoPassword(ctx context.Context, sess RemoteSession, cmd string, secret []byte) ([]byte, error) {
	// sudo -S reads the password from stdin. Without a PTY, an incorrect
	// password consumes EOF and fails immediately instead of waiting for more
	// terminal prompts. Legacy sudoers policies may require a TTY, so retry with
	// a protected PTY only for that explicit policy error.
	out, err := runPrivilegeSecret(ctx, sess, cmd, secret, false)
	if !sudoRequiresTTY(out, err) {
		return out, err
	}
	return runPrivilegeSecret(ctx, sess, cmd, secret, true)
}

func sudoRequiresTTY(out []byte, err error) bool {
	text := strings.ToLower(string(out))
	if err != nil {
		text += " " + strings.ToLower(err.Error())
	}
	return strings.Contains(text, "must have a tty") ||
		strings.Contains(text, "no tty present") ||
		strings.Contains(text, "terminal is required")
}

func testNOPASSWD(ctx context.Context, sess RemoteSession) (bool, error) {
	out, err := sess.Run(ctx, templates.ApplyPrivilege("id -u", templates.PrivSudoNOP))
	return err == nil && reportsRoot(out), err
}

func reportsRoot(out []byte) bool {
	for _, field := range strings.Fields(string(out)) {
		if field == "0" {
			return true
		}
	}
	return false
}

func classifySudoFailure(out []byte, err error) error {
	text := strings.ToLower(string(out))
	if err != nil {
		text += " " + strings.ToLower(err.Error())
	}
	switch {
	case strings.Contains(text, "sudo: command not found"), strings.Contains(text, "sudo: not found"):
		return privilegeFailure("sudo_unavailable", err)
	case strings.Contains(text, "not in the sudoers"), strings.Contains(text, "not allowed to execute"):
		return privilegeFailure("sudo_not_authorized", err)
	default:
		return privilegeFailure("sudo_password_invalid", err)
	}
}

func classifySuFailure(out []byte, err error) error {
	text := strings.ToLower(string(out))
	if err != nil {
		text += " " + strings.ToLower(err.Error())
	}
	if strings.Contains(text, "su: command not found") || strings.Contains(text, "su: not found") {
		return privilegeFailure("su_unavailable", err)
	}
	return privilegeFailure("root_password_invalid", err)
}

func classifySudoersFailure(out []byte, err error) error {
	text := string(out)
	if err != nil {
		text += " " + err.Error()
	}
	switch {
	case strings.Contains(text, "AB_ERR_SUDOERS_DIRECTORY_MISSING"):
		return privilegeFailure("sudoers_directory_missing", err)
	case strings.Contains(text, "AB_ERR_SUDOERS_VALIDATOR_MISSING"):
		return privilegeFailure("sudoers_validator_missing", err)
	case strings.Contains(text, "AB_ERR_SUDOERS_ACCOUNT_MISSING"):
		return privilegeFailure("sudoers_account_missing", err)
	default:
		return privilegeFailure("sudoers_update_failed", err)
	}
}

// sudoersInstallCommand is a bounded root script. uid came from `id -u` and
// is converted back from an int, so no caller string reaches the shell. The
// drop-in is validated and atomically renamed into place.
func sudoersInstallCommand(uid int) string {
	uidText := strconv.Itoa(uid)
	return `set -eu
[ -d /etc/sudoers.d ] || { echo AB_ERR_SUDOERS_DIRECTORY_MISSING >&2; exit 21; }
command -v visudo >/dev/null 2>&1 || { echo AB_ERR_SUDOERS_VALIDATOR_MISSING >&2; exit 22; }
uid=` + templates.ShellQuote(uidText) + `
account=$(id -nu "$uid" 2>/dev/null || true)
[ -n "$account" ] || { echo AB_ERR_SUDOERS_ACCOUNT_MISSING >&2; exit 23; }
tmp=$(mktemp "/etc/sudoers.d/.agentbridge-${uid}.XXXXXX")
trap 'rm -f "$tmp"' EXIT HUP INT TERM
printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$account" > "$tmp"
chmod 0440 "$tmp"
visudo -cf "$tmp" >/dev/null
mv -f "$tmp" "/etc/sudoers.d/agentbridge-${uid}"
trap - EXIT HUP INT TERM`
}
