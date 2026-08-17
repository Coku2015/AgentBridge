// Package logging provides a secret-scrubbing structured logger built on log/slog.
// Every log line passes through a security.Scrubber so registered secret values
// (VBR password, bearer token, SSH keys, …) never reach output (red line 1).
package logging

import (
	"io"
	"log/slog"

	"github.com/Coku2015/agentbridge/internal/security"
)

// New returns a *slog.Logger whose text output is scrubbed of every secret
// registered on scrubber. Level defaults to Info; callers may adjust via
// slog.Logger methods.
func New(scrubber *security.Scrubber, w io.Writer) *slog.Logger {
	sw := scrubWriter{w: w, s: scrubber}
	return slog.New(slog.NewTextHandler(sw, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// scrubWriter wraps an io.Writer, redacting secret literals before they are
// written. This guarantees logs cannot leak registered secrets.
type scrubWriter struct {
	w io.Writer
	s *security.Scrubber
}

func (sw scrubWriter) Write(p []byte) (int, error) {
	cleaned := sw.s.Scrub(string(p))
	n, err := sw.w.Write([]byte(cleaned))
	if n > len(p) {
		n = len(p) // report original length on success regardless of redaction
	}
	return n, err
}
