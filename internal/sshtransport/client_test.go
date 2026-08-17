package sshtransport

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

// TestTailKeepsEnd ensures failed-command errors keep the END of the output —
// that is where installers print their actual error line.
func TestTailKeepsEnd(t *testing.T) {
	if got := tail("short", 2048); got != "short" {
		t.Fatalf("short input altered: %q", got)
	}
	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'x'
	}
	copy(long[len(long)-len("THE-ERROR"):], "THE-ERROR")
	got := tail(string(long), 2048)
	if runes := len([]rune(got)); runes != 2049 { // ellipsis + 2048 runes
		t.Fatalf("rune len = %d, want 2049", runes)
	}
	if !endsWith(got, "THE-ERROR") {
		t.Fatalf("tail lost the trailing error line: %q", got[len(got)-40:])
	}
}

func TestDelayedReaderHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &delayedReader{ctx: ctx, delay: time.Hour, reader: bytes.NewReader([]byte("secret\n"))}
	buf := make([]byte, 16)
	if _, err := r.Read(buf); !errors.Is(err, context.Canceled) {
		t.Fatalf("Read error = %v, want context.Canceled", err)
	}
}

func TestRedactOutputSecret(t *testing.T) {
	got := string(redactOutputSecret([]byte("prefix account-secret suffix"), []byte("account-secret")))
	if got != "prefix [REDACTED] suffix" {
		t.Fatalf("redacted output = %q", got)
	}
}

func endsWith(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func TestRedactDialErrKeepsOnlyStableFailureClass(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"dial tcp 10.10.1.204:22: i/o timeout", "sshtransport: network timeout"},
		{"dial tcp 10.10.1.204:22: connect: connection refused", "sshtransport: connection refused"},
		{"dial tcp: lookup host.invalid: no such host", "sshtransport: host not found"},
		{"ssh: handshake failed: unable to authenticate, attempted methods [none password], no supported methods remain", "sshtransport: authentication failed (credentials held in memory only)"},
		{"ssh: handshake failed: host key mismatch", ErrHostKeyMismatch.Error()},
	}
	for _, tt := range tests {
		if got := redactDialErr(errors.New(tt.raw)).Error(); got != tt.want {
			t.Fatalf("redactDialErr(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}
