package httpserver

import (
	"log/slog"
	"net/http"
	"strings"
)

// vbrPublicError reduces VBR discovery and connection failures to stable codes
// the UI can localize. The technical error stays in the server log so transport,
// TLS, and OAuth implementation details are never presented to the operator.
func vbrPublicError(stage string, err error) string {
	if err == nil {
		return "vbr_connection_failed"
	}
	lower := strings.ToLower(err.Error())

	switch {
	case strings.Contains(lower, "no such host"),
		strings.Contains(lower, "host not found"),
		strings.Contains(lower, "server misbehaving"),
		strings.Contains(lower, "temporary failure in name resolution"),
		strings.Contains(lower, "name resolution"):
		return "vbr_host_not_found"
	case strings.Contains(lower, "i/o timeout"),
		strings.Contains(lower, "network timeout"),
		strings.Contains(lower, "deadline exceeded"),
		strings.Contains(lower, "client.timeout exceeded"),
		strings.Contains(lower, "timeout awaiting response headers"):
		return "vbr_connection_timeout"
	case strings.Contains(lower, "connection refused"):
		return "vbr_connection_refused"
	case strings.Contains(lower, "no route to host"),
		strings.Contains(lower, "network is unreachable"),
		strings.Contains(lower, "host is down"),
		strings.Contains(lower, "network unreachable"):
		return "vbr_network_unreachable"
	case strings.Contains(lower, "fingerprint does not match"),
		strings.Contains(lower, "fingerprint mismatch"):
		return "vbr_tls_fingerprint_changed"
	case strings.Contains(lower, "server presented no certificate"),
		strings.Contains(lower, "tls handshake"),
		strings.Contains(lower, "first record does not look like a tls handshake"),
		strings.Contains(lower, "server gave http response to https client"),
		strings.Contains(lower, "remote error: tls"),
		strings.Contains(lower, "protocol version"),
		strings.Contains(lower, "x509:"),
		strings.Contains(lower, "connection reset by peer"),
		strings.Contains(lower, "unexpected eof"),
		strings.HasSuffix(lower, ": eof"):
		return "vbr_tls_handshake_failed"
	case strings.Contains(lower, "invalid_grant"),
		strings.Contains(lower, "invalid credentials"),
		strings.Contains(lower, "authentication failed"),
		strings.Contains(lower, "username or password"),
		strings.Contains(lower, "oauth2 token grant returned 400"),
		strings.Contains(lower, "oauth2 token grant returned 401"):
		return "vbr_authentication_failed"
	case strings.Contains(lower, "oauth2 token grant returned 403"),
		strings.Contains(lower, "403 forbidden"),
		strings.Contains(lower, "access denied"):
		return "vbr_access_forbidden"
	case strings.Contains(lower, "oauth2 token grant returned 404"),
		strings.Contains(lower, "404 not found"):
		return "vbr_api_not_found"
	case strings.Contains(lower, "oauth2 token grant returned 429"),
		strings.Contains(lower, "oauth2 token grant returned 500"),
		strings.Contains(lower, "oauth2 token grant returned 502"),
		strings.Contains(lower, "oauth2 token grant returned 503"),
		strings.Contains(lower, "oauth2 token grant returned 504"),
		strings.Contains(lower, "service unavailable"),
		strings.Contains(lower, "too many requests"):
		return "vbr_service_unavailable"
	case strings.Contains(lower, "decode token"),
		strings.Contains(lower, "empty access token"),
		strings.Contains(lower, "invalid character"),
		strings.Contains(lower, "unexpected end of json input"):
		return "vbr_response_invalid"
	}

	switch stage {
	case "server_info":
		return "vbr_server_info_unavailable"
	case "capabilities":
		return "vbr_capability_probe_failed"
	default:
		return "vbr_connection_failed"
	}
}

func writeVBRConnectionFailure(w http.ResponseWriter, log *slog.Logger, stage, server string, port int, err error) {
	code := vbrPublicError(stage, err)
	if log != nil {
		log.Warn(
			"vbr connection probe failed",
			"stage", stage,
			"server", server,
			"port", port,
			"error", code,
			"technical_detail", err,
		)
	}
	writeJSON(w, http.StatusBadGateway, map[string]any{"error": code})
}
