package sshtransport

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// ErrHostKeyMismatch is returned when a presented host key does not match the
// pinned key. Connection is blocked by default on any change (red line 4,
// AB-FR-121).
var ErrHostKeyMismatch = errors.New("sshtransport: host key changed — connection blocked (pin mismatch)")

// FingerprintSHA256 returns the canonical OpenSSH SHA-256 fingerprint
// ("SHA256:base64...") of a host key, for display + pin confirmation.
func FingerprintSHA256(key ssh.PublicKey) string {
	return ssh.FingerprintSHA256(key)
}

// KeySHA256Hex returns the lowercase hex SHA-256 of the host key's wire bytes,
// matching the TLS-pin style used elsewhere in AgentBridge.
func KeySHA256Hex(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return base64.StdEncoding.EncodeToString(sum[:]) // kept base64 to mirror OpenSSH form
}

// pinnedCallback returns an ssh.HostKeyCallback that accepts ONLY the pinned key
// (byte-for-byte) and rejects any change — built on ssh.FixedHostKey so the
// invariant is enforced by the library, not by us (red line 4).
func pinnedCallback(pinned ssh.PublicKey) ssh.HostKeyCallback {
	return ssh.FixedHostKey(pinned)
}

// AuthorizedKeyLine renders a captured host key in authorized_keys/known_hosts
// form ("<type> <base64 wire>") — the exact format ParseHostKey parses back.
// The capture endpoint returns it alongside the fingerprint so the UI can show
// the fingerprint for operator confirmation (TOFU) and hand the SAME key to
// install for pinning. Non-secret: it is the server's public host key.
func AuthorizedKeyLine(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// ParseHostKey parses an authorized-keys / known_hosts line into a PublicKey
// for pinning. Parse failures are wrapped so a malformed key never leaks raw
// bytes into logs.
func ParseHostKey(line string) (ssh.PublicKey, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("sshtransport: parse host key: invalid (details redacted)")
	}
	return key, nil
}

// CaptureHostKey dials addr and captures the server host key WITHOUT trusting
// it and WITHOUT authenticating. This is the TOFU "show the operator" step
// (AB-FR-121): the returned key is presented for confirmation and is NOT used
// until the operator confirms and the client reconnects with a pinned callback.
//
// It performs no authenticated action. The callback returns nil solely to
// complete the key-exchange so the key can be observed; the lack of any auth
// method means the handshake terminates before any session is possible.
func CaptureHostKey(ctx context.Context, addr string, timeout time.Duration) (ssh.PublicKey, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, redactDialErr(err)
	}
	defer conn.Close()

	var captured ssh.PublicKey
	cfg := &ssh.ClientConfig{
		// Capture-only callback: record the key, accept it for THIS non-trusting,
		// non-authenticating handshake. Never reused for a real session.
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			captured = key
			return nil
		},
		Timeout: timeout,
		Config:  ssh.Config{},
		// Intentionally NO AuthMethods: KEX completes (key observed) then auth fails.
	}
	// NewClientConn performs the transport + KEX handshake, firing the callback,
	// then fails at auth — which is expected. We only care about `captured`.
	_, _, _, _ = ssh.NewClientConn(conn, addr, cfg)
	if captured == nil {
		return nil, errors.New("sshtransport: host key not observed during capture (handshake failed)")
	}
	return captured, nil
}
