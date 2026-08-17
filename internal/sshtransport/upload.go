package sshtransport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/Coku2015/agentbridge/internal/executor/templates"
)

// Upload streams r to remotePath over the SSH exec channel stdin — no SFTP,
// no target-side agent (AB-FR-122). The remote command is the fixed, strictly-
// quoted templates.UploadOpenCmd (red line 5). It returns the SHA-256 of the
// uploaded bytes so the caller can confirm integrity.
//
// remotePath must be an absolute path chosen by the caller under a per-host
// unpredictable temp dir (AB-FR-123).
func (c *Client) Upload(ctx context.Context, r io.Reader, remotePath string) (string, error) {
	hasher := sha256.New()
	tee := io.TeeReader(r, hasher)

	// The remote command reads stdin into a .part file then atomically renames,
	// so a partial/aborted upload is never installable (AB-FR-126).
	cmd := templates.UploadOpenCmd(remotePath)
	if err := c.RunStdin(ctx, cmd, tee); err != nil {
		return "", fmt.Errorf("sshtransport: upload %s: %w", remotePath, err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
