package probe

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/Coku2015/agentbridge/internal/executor/templates"
)

// LocalProbe runs the static POSIX fact script directly on this host (the
// Zero-Credential / Local Run path, section 9.2). It needs no root and no SSH,
// and shares the exact same static script + Result schema as the SSH probe, so
// the matcher consumes both identically (AB-FR-081..083).
type LocalProbe struct{}

// NewLocalProbe returns a LocalProbe.
func NewLocalProbe() *LocalProbe { return &LocalProbe{} }

// Run executes the static script via /bin/sh and decodes its JSON. The script is
// a fixed constant (no caller interpolation — red line 5); it never concatenates
// a raw caller string, so exec.Command is safe here.
func (LocalProbe) Run(ctx context.Context) (Result, error) {
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", templates.ProbeScript) //nolint:gosec // fixed constant script
	out, err := cmd.Output()
	if err != nil {
		return Result{}, fmt.Errorf("probe: local run: %w", err)
	}
	return decodeResult(out)
}
