package httpserver

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/Coku2015/agentbridge/internal/executor"
)

// sshPublicError reduces transport and probe failures to stable categories for
// the UI. The underlying library error is intentionally kept out of the HTTP
// response; it is recorded by writeSSHRemoteFailure for server-side diagnosis.
func sshPublicError(err error) string {
	if err == nil {
		return "remote_probe_failed"
	}
	if code := executor.PrivilegeErrorCode(err); code != "" {
		return code
	}
	lower := strings.ToLower(err.Error())
	for _, code := range []string{
		"privilege_identity_failed",
		"privilege_required",
		"sudo_password_required",
		"sudo_password_invalid",
		"sudo_not_authorized",
		"sudo_unavailable",
		"root_password_required",
		"root_password_invalid",
		"su_unavailable",
		"sudoers_directory_missing",
		"sudoers_validator_missing",
		"sudoers_account_missing",
		"sudoers_update_failed",
		"privilege_escalation_failed",
	} {
		if strings.Contains(lower, "privilege: "+code) {
			return code
		}
	}
	switch {
	case strings.Contains(lower, "host key changed"),
		strings.Contains(lower, "host key mismatch"),
		strings.Contains(lower, "pin mismatch"):
		return "host_key_changed"
	case strings.Contains(lower, "private key invalid"),
		strings.Contains(lower, "cannot decode encrypted private keys"),
		strings.Contains(lower, "private key passphrase"):
		return "private_key_invalid"
	case strings.Contains(lower, "no auth method provided"):
		return "credential_missing"
	case strings.Contains(lower, "authentication failed"),
		strings.Contains(lower, "unable to authenticate"),
		strings.Contains(lower, "no supported methods remain"):
		return "authentication_failed"
	case strings.Contains(lower, "no such host"),
		strings.Contains(lower, "host not found"),
		strings.Contains(lower, "server misbehaving"),
		strings.Contains(lower, "temporary failure in name resolution"):
		return "host_not_found"
	case strings.Contains(lower, "i/o timeout"),
		strings.Contains(lower, "network timeout"),
		strings.Contains(lower, "deadline exceeded"):
		return "network_timeout"
	case strings.Contains(lower, "connection refused"):
		return "connection_refused"
	case strings.Contains(lower, "no route to host"),
		strings.Contains(lower, "network is unreachable"),
		strings.Contains(lower, "host is down"),
		strings.Contains(lower, "network unreachable"):
		return "network_unreachable"
	case strings.Contains(lower, "host key not observed"),
		strings.Contains(lower, "ssh handshake failed"),
		strings.Contains(lower, "handshake failed"),
		strings.Contains(lower, "connection reset by peer"),
		strings.HasSuffix(lower, ": eof"):
		return "ssh_handshake_failed"
	case strings.Contains(lower, "permission denied"):
		return "remote_permission_denied"
	case strings.Contains(lower, "probe: decode facts"):
		return "probe_response_invalid"
	case strings.Contains(lower, "probe: schema mismatch"):
		return "probe_response_unsupported"
	default:
		return "remote_probe_failed"
	}
}

func writeSSHRemoteFailure(w http.ResponseWriter, log *slog.Logger, operation, host string, port int, err error) {
	code := sshPublicError(err)
	if log != nil {
		log.Warn("linux remote operation failed",
			"operation", operation,
			"host", host,
			"port", port,
			"error", code,
			"technical_detail", err,
		)
	}
	writeJSON(w, http.StatusBadGateway, map[string]any{"error": code})
}
