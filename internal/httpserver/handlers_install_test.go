package httpserver

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Coku2015/agentbridge/internal/executor"
	"github.com/Coku2015/agentbridge/internal/sshtransport"
)

// Red line 4: install MUST refuse without a confirmed (non-empty) host key.
func TestInstallRequiresConfirmedHostKey(t *testing.T) {
	mux := http.NewServeMux()
	registerInstall(mux, nil, "")

	req := httptest.NewRequest(http.MethodPost, "/api/install",
		strings.NewReader(`{"host":"h","port":22,"user":"root","password":"x","packagePath":"/tmp/p.rpm"}`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusPreconditionRequired {
		t.Fatalf("status = %d, want 428 (host-key confirmation required)", w.Code)
	}
}

// A malformed host key must be rejected (no silent acceptance).
func TestInstallRejectsMalformedHostKey(t *testing.T) {
	mux := http.NewServeMux()
	registerInstall(mux, nil, "")

	req := httptest.NewRequest(http.MethodPost, "/api/install",
		strings.NewReader(`{"host":"h","port":22,"user":"root","hostKey":"not-a-key"}`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for malformed host key", w.Code)
	}
}

// The capture endpoint returns a FINGERPRINT for display; install pins the
// authorized-keys line. Sending the fingerprint form (the UI regression) must
// stay a 400, and a real key line must get PAST host-key validation (it fails
// later at dial, not at parse).
func TestInstallHostKeyFormat(t *testing.T) {
	mux := http.NewServeMux()
	registerInstall(mux, nil, "")

	// Fingerprint form must be rejected as invalid (it is not a key line).
	req := httptest.NewRequest(http.MethodPost, "/api/install",
		strings.NewReader(`{"host":"h","port":22,"user":"root","hostKey":"SHA256:abcdef0123456789"}`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("fingerprint-as-hostKey: status = %d, want 400", w.Code)
	}

	// A genuine authorized-keys line parses and proceeds to dial (502, not 400).
	pub, _, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := sshtransport.AuthorizedKeyLine(k)
	body, _ := json.Marshal(map[string]any{
		"host": "h", "port": 22, "user": "root", "hostKey": line, "kitPath": "/tmp/kit.bin",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/install", bytes.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code == http.StatusBadRequest {
		t.Fatalf("valid key line rejected as invalid host key: %s", w.Body.String())
	}

	// The removed Agent-only product path must also be rejected at the public
	// API boundary, even when the host key and artifact fields are otherwise
	// well formed.
	body, _ = json.Marshal(map[string]any{
		"host": "h", "port": 22, "user": "root", "hostKey": line,
		"kitPath": "/tmp/kit.bin", "packagePath": "/tmp/agent.rpm", "deploymentProfile": "agent-only",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/install", bytes.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "unsupported_deployment_profile") {
		t.Fatalf("Agent-only profile was not rejected: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestLinuxDeploymentKitReadyRequiresPackageAndActiveService(t *testing.T) {
	tests := []struct {
		name   string
		verify executor.LocalVerifyResult
		want   bool
	}{
		{"ready", executor.LocalVerifyResult{DeploymentKitVersion: "13.1.1.18-1", DeployerStatus: "active"}, true},
		{"package missing", executor.LocalVerifyResult{DeployerStatus: "active"}, false},
		{"service inactive", executor.LocalVerifyResult{DeploymentKitVersion: "13.1.1.18-1", DeployerStatus: "inactive"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := linuxDeploymentKitReady(tt.verify); got != tt.want {
				t.Fatalf("linuxDeploymentKitReady(%+v) = %v, want %v", tt.verify, got, tt.want)
			}
		})
	}
}

func TestSSHCredentialTypesKeepPasswordsSeparate(t *testing.T) {
	passwordAuth := sshAuthForCredential("login-secret", nil, "")
	if passwordAuth.Password != "login-secret" || len(passwordAuth.PrivateKeyPEM) != 0 || passwordAuth.Passphrase != "" {
		t.Fatalf("password credential mapped incorrectly: %+v", passwordAuth)
	}

	key := []byte("private-key-material")
	keyAuth := sshAuthForCredential("account-sudo-secret", key, "key-passphrase")
	if keyAuth.Password != "" {
		t.Fatal("private-key credential leaked the account sudo password into SSH password authentication")
	}
	if !bytes.Equal(keyAuth.PrivateKeyPEM, key) || keyAuth.Passphrase != "key-passphrase" {
		t.Fatalf("private-key credential mapped incorrectly: %+v", keyAuth)
	}
}

func TestLinuxInstallStageFailureLogsRealCause(t *testing.T) {
	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuffer, nil))
	logLinuxInstallStageFailure(logger, "install", "172.30.0.2", 22, errors.New("rpm transaction failed: dependency missing"))

	logged := logBuffer.String()
	for _, expected := range []string{
		`"msg":"linux remote installation failed"`,
		`"stage":"install"`,
		`"host":"172.30.0.2"`,
		`"port":22`,
		`"error":"install_failed"`,
		`"technical_detail":"rpm transaction failed: dependency missing"`,
	} {
		if !strings.Contains(logged, expected) {
			t.Fatalf("log %q does not contain %q", logged, expected)
		}
	}
}
