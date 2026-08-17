package sshtransport

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func mustPubKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Red line 4: the pinned callback MUST accept the pinned key and reject any
// change (block-by-default).
func TestPinnedCallbackAcceptsPinnedRejectsChange(t *testing.T) {
	pinned := mustPubKey(t)
	other := mustPubKey(t)
	if pinned.Marshal()[0] == other.Marshal()[0] && string(pinned.Marshal()) == string(other.Marshal()) {
		t.Fatal("test keys collided")
	}
	cb := pinnedCallback(pinned)
	dummy := &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4)}
	if err := cb("h", dummy, pinned); err != nil {
		t.Fatalf("pinned key rejected: %v", err)
	}
	if err := cb("h", dummy, other); err == nil {
		t.Fatal("changed host key must be rejected (red line 4)")
	}
}

func TestParseHostKeyRoundTrip(t *testing.T) {
	k := mustPubKey(t)
	authorized := AuthorizedKeyLine(k)
	parsed, err := ParseHostKey(authorized)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if string(parsed.Marshal()) != string(k.Marshal()) {
		t.Fatal("parsed key bytes differ from source")
	}
	if FingerprintSHA256(parsed) != FingerprintSHA256(k) {
		t.Fatal("parsed key fingerprint differs from source")
	}
}

// AB-FR-024 / red line 1: a malformed key must NOT leak raw bytes into the error.
func TestParseHostKeyMalformedRedacted(t *testing.T) {
	_, err := ParseHostKey("not-a-real-key garbage")
	if err == nil {
		t.Fatal("expected error for malformed key")
	}
	if strings.Contains(err.Error(), "garbage") || strings.Contains(err.Error(), "ssh:") {
		t.Fatalf("error leaked detail: %v", err)
	}
}

func TestFingerprintStable(t *testing.T) {
	k := mustPubKey(t)
	a := FingerprintSHA256(k)
	b := FingerprintSHA256(k)
	if a == "" || a != b {
		t.Fatalf("fingerprint not stable: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "SHA256:") {
		t.Fatalf("fingerprint not OpenSSH form: %s", a)
	}
}
