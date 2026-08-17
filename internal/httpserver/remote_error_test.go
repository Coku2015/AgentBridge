package httpserver

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
)

func TestSSHPublicError(t *testing.T) {
	tests := []struct {
		name string
		err  string
		want string
	}{
		{"timeout", "sshtransport: network timeout", "network_timeout"},
		{"refused", "sshtransport: connection refused", "connection_refused"},
		{"route", "sshtransport: network unreachable", "network_unreachable"},
		{"dns", "sshtransport: host not found: no such host", "host_not_found"},
		{"redacted dns", "sshtransport: host not found", "host_not_found"},
		{"password", "sshtransport: authentication failed", "authentication_failed"},
		{"key", "sshtransport: private key invalid (parse error redacted)", "private_key_invalid"},
		{"host key", "sshtransport: host key changed — connection blocked (pin mismatch)", "host_key_changed"},
		{"handshake", "sshtransport: ssh handshake failed", "ssh_handshake_failed"},
		{"permission", "probe: run facts: permission denied", "remote_permission_denied"},
		{"sudo password", "privilege: sudo_password_invalid", "sudo_password_invalid"},
		{"sudoers", "privilege: sudoers_update_failed", "sudoers_update_failed"},
		{"root password", "privilege: root_password_required", "root_password_required"},
		{"decode", "probe: decode facts: invalid character", "probe_response_invalid"},
		{"schema", "probe: schema mismatch: got 2 want 1", "probe_response_unsupported"},
		{"other", "unexpected session failure", "remote_probe_failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sshPublicError(errors.New(tt.err)); got != tt.want {
				t.Fatalf("sshPublicError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWriteSSHRemoteFailureDoesNotExposeLibraryError(t *testing.T) {
	rec := httptest.NewRecorder()
	raw := "sshtransport: dial 10.10.1.204:22: dial tcp 10.10.1.204:22: i/o timeout"
	writeSSHRemoteFailure(rec, nil, "system_probe", "10.10.1.204", 22, errors.New(raw))

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["error"] != "network_timeout" {
		t.Fatalf("error = %#v, want network_timeout", payload["error"])
	}
	if _, exists := payload["detail"]; exists {
		t.Fatalf("technical detail leaked into public response: %s", rec.Body.String())
	}
}
