package security

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"
)

// Fingerprint returns the SHA-256 fingerprint of raw DER certificate bytes as
// a colon-separated, uppercase hex string (the format Veeam/VBR displays and
// the operator confirms, AB-FR-022).
func Fingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return groupHex(hex.EncodeToString(sum[:]))
}

// FingerprintCert is a convenience for *x509.Certificate.
func FingerprintCert(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	return Fingerprint(c.Raw)
}

// groupHex turns "ABCD..." into "AB:CD:...".
func groupHex(hexed string) string {
	if len(hexed) == 0 {
		return ""
	}
	out := make([]byte, 0, len(hexed)+(len(hexed)/2))
	for i := 0; i < len(hexed); i += 2 {
		if i > 0 {
			out = append(out, ':')
		}
		end := i + 2
		if end > len(hexed) {
			end = len(hexed)
		}
		out = append(out, hexed[i:end]...)
	}
	return string(out)
}

// ErrFingerprintMismatch is returned when a presented certificate does not match
// the pinned fingerprint.
var ErrFingerprintMismatch = errors.New("vbr tls: certificate fingerprint does not match the pinned value")

// PinnedPeerVerifier returns a tls.Config.VerifyPeerCertificate callback that
// hard-rejects the handshake unless the leaf certificate's SHA-256 fingerprint
// equals pinned (colon-separated uppercase hex). This REPLACES CA-based
// verification with mandatory fingerprint pinning (Constitution Principle II,
// red line 3): verification is not skipped, it is made stricter.
//
// The returned config sets InsecureSkipVerify=true ONLY so Go delegates chain
// validation entirely to this callback (required for self-signed VBR lab certs
// that are not in any system trust store). A blind InsecureSkipVerify with no
// callback is forbidden; this helper never returns a config without a verifier.
func PinnedPeerVerifier(pinned string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("vbr tls: server presented no certificate")
		}
		got := Fingerprint(rawCerts[0])
		if !equalFoldHex(got, pinned) {
			return fmt.Errorf("%w: got %s", ErrFingerprintMismatch, got)
		}
		return nil
	}
}

// PinnedTLSConfig returns a *tls.Config that enforces fingerprint pinning for
// the given server name. Pinned may be empty for the first-connect capture
// flow (see CaptureLeaf), in which case no verifier is set.
func PinnedTLSConfig(serverName, pinned string) *tls.Config {
	cfg := &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: pinned != "", // delegate to the explicit verifier below
	}
	if pinned != "" {
		cfg.VerifyPeerCertificate = PinnedPeerVerifier(pinned)
	}
	return cfg
}

// LeafCapture captures a server leaf certificate (and its fingerprint) without
// trusting it. This is the explicit "show the fingerprint to the operator" step
// of trust-on-first-use (AB-FR-022); it is the only place an untrusted cert is
// read, and it never auto-pins — the operator must confirm before pinning.
type LeafCapture struct {
	Fingerprint string
	Cert        *x509.Certificate
}

// CaptureLeaf dials addr (host:port), retrieves the leaf certificate, and
// returns its fingerprint + parsed form. It performs NO verification of chain
// or hostname: its sole purpose is to present identity to the operator. The
// caller MUST require explicit confirmation before trusting the result.
func CaptureLeaf(addr string, timeout time.Duration) (LeafCapture, error) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // capture-only; never used for real traffic
	})
	if err != nil {
		return LeafCapture{}, fmt.Errorf("vbr tls: dial %s: %w", addr, err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return LeafCapture{}, errors.New("vbr tls: server presented no certificate")
	}
	cert := state.PeerCertificates[0]
	return LeafCapture{Fingerprint: Fingerprint(cert.Raw), Cert: cert}, nil
}

// equalFoldHex compares two hex fingerprint strings ignoring case and colon
// separators.
func equalFoldHex(a, b string) bool {
	ra := stripNonHex(a)
	rb := stripNonHex(b)
	if len(ra) != len(rb) {
		return false
	}
	for i := 0; i < len(ra); i++ {
		ca, cb := ra[i], rb[i]
		if 'A' <= ca && ca <= 'F' {
			ca += 32
		}
		if 'A' <= cb && cb <= 'F' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func stripNonHex(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') {
			out = append(out, c)
		}
	}
	return string(out)
}
