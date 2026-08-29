package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVBRPublicError(t *testing.T) {
	tests := []struct {
		name   string
		stage  string
		detail string
		want   string
	}{
		{name: "dns", stage: "capture", detail: "dial tcp: lookup vbr.example: no such host", want: "vbr_host_not_found"},
		{name: "timeout", stage: "capture", detail: "vbr tls: dial 170.30.0.50:9419: dial tcp 170.30.0.50:9419: i/o timeout", want: "vbr_connection_timeout"},
		{name: "refused", stage: "capture", detail: "dial tcp 170.30.0.50:9419: connect: connection refused", want: "vbr_connection_refused"},
		{name: "unreachable", stage: "capture", detail: "dial tcp 170.30.0.50:9419: no route to host", want: "vbr_network_unreachable"},
		{name: "fingerprint", stage: "connect", detail: "vbr tls: certificate fingerprint does not match the pinned value", want: "vbr_tls_fingerprint_changed"},
		{name: "wrong protocol", stage: "capture", detail: "tls: first record does not look like a TLS handshake", want: "vbr_tls_handshake_failed"},
		{name: "bad credentials", stage: "connect", detail: `vbr connect: oauth2 token grant returned 400 Bad Request: {"error":"invalid_grant"}`, want: "vbr_authentication_failed"},
		{name: "forbidden", stage: "connect", detail: "vbr connect: oauth2 token grant returned 403 Forbidden", want: "vbr_access_forbidden"},
		{name: "api missing", stage: "connect", detail: "vbr connect: oauth2 token grant returned 404 Not Found", want: "vbr_api_not_found"},
		{name: "service unavailable", stage: "connect", detail: "vbr connect: oauth2 token grant returned 503 Service Unavailable", want: "vbr_service_unavailable"},
		{name: "bad response", stage: "connect", detail: "vbr connect: decode token: invalid character '<'", want: "vbr_response_invalid"},
		{name: "server info fallback", stage: "server_info", detail: "unexpected VBR response", want: "vbr_server_info_unavailable"},
		{name: "capability fallback", stage: "capabilities", detail: "unexpected VBR response", want: "vbr_capability_probe_failed"},
		{name: "generic fallback", stage: "connect", detail: "unexpected connection error", want: "vbr_connection_failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := vbrPublicError(tt.stage, errors.New(tt.detail)); got != tt.want {
				t.Fatalf("vbrPublicError(%q, %q) = %q, want %q", tt.stage, tt.detail, got, tt.want)
			}
		})
	}
}

func TestWriteVBRConnectionFailureKeepsTechnicalDetailOutOfResponse(t *testing.T) {
	w := httptest.NewRecorder()
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(io.MultiWriter(&logs), nil))
	detail := "vbr tls: dial 170.30.0.50:9419: dial tcp 170.30.0.50:9419: i/o timeout"

	writeVBRConnectionFailure(w, logger, "capture", "170.30.0.50", 9419, errors.New(detail))

	var body map[string]any
	if err := json.NewDecoder(w.Result().Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "vbr_connection_timeout" {
		t.Fatalf("error = %v, want vbr_connection_timeout", body["error"])
	}
	if strings.Contains(w.Body.String(), "dial tcp") {
		t.Fatalf("public response leaked technical detail: %s", w.Body.String())
	}
	if !strings.Contains(logs.String(), "dial tcp") {
		t.Fatalf("server log omitted technical detail: %s", logs.String())
	}
}
