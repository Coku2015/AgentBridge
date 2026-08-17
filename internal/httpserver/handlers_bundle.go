package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Coku2015/agentbridge/internal/bundle"
)

// Bundle generation is a pure local operation on already-cached artifacts, so it
// does NOT require an active VBR connection — this is what makes the air-gap /
// locked-down path work (FR-034). Output lives under the server data dir.
var (
	bundleBuilder     *bundle.Builder
	bundleBuilderOnce sync.Once
	bundleBuilderErr  error
)

func initBundleBuilder(dataDir string) {
	bundleBuilderOnce.Do(func() {
		b, err := bundle.NewBuilder(filepath.Join(dataDir, "bundles"))
		if err != nil {
			bundleBuilderErr = err
			return
		}
		bundleBuilder = b
	})
}

// registerBundle wires the zero-credential bundle endpoints (US6, FR-034..036).
// Neither endpoint needs VBR connectivity: generation works offline on cached
// artifacts, and import verifies the result locally before the wizard continues
// to PG/discovery (FR-036).
func registerBundle(mux *http.ServeMux, dataDir string, manualDownloads *manualDownloadServer) {
	// POST /api/manual-install/generate builds a self-contained archive and
	// publishes one short-lived HTTP download URL. The target host pulls
	// the archive; AgentBridge never opens an SSH connection to it.
	generateManualInstall := func(w http.ResponseWriter, r *http.Request) {
		initBundleBuilder(dataDir)
		if bundleBuilderErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "bundle builder init failed", "detail": bundleBuilderErr.Error()})
			return
		}
		var body struct {
			PackagePath       string   `json:"packagePath"`
			PackageID         string   `json:"packageId"`
			PackageSHA256     string   `json:"packageSha256"`
			PackagePaths      []string `json:"packagePaths"`
			PackageIDs        []string `json:"packageIds"`
			PackageSHA256s    []string `json:"packageSha256s"`
			KitPath           string   `json:"kitPath"`
			DeploymentProfile string   `json:"deploymentProfile"`
			JobID             string   `json:"jobId"`
			Platform          string   `json:"platform"`
			CampaignID        string   `json:"campaignId"`
			KitSHA256         string   `json:"kitSha256"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		platform := strings.ToLower(strings.TrimSpace(body.Platform))
		if platform == "" {
			platform = "linux"
		}
		if platform != "linux" && platform != "windows" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported platform", "platform": body.Platform})
			return
		}
		if platform == "windows" {
			if body.DeploymentProfile != "" && body.DeploymentProfile != "kit-only" {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Windows manual install supports Deployment Kit only"})
				return
			}
			kitPath, digest, kitErr := activeKit(dataDir, body.CampaignID, body.KitPath, body.KitSHA256)
			if kitErr != nil {
				writeJSON(w, http.StatusConflict, map[string]any{"error": "deployment_kit_campaign_invalid", "detail": kitErr.Error()})
				return
			}
			if manualDownloads == nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "manual install download service unavailable"})
				return
			}
			downloadURL, expiresAt, publishErr := manualDownloads.publishForPlatform(kitPath, platform, digest)
			if publishErr != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "manual install download service unavailable", "detail": publishErr.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"path": kitPath, "sha256": digest, "platform": platform,
				"downloadUrl": downloadURL, "command": manualInstallCommandFor(platform, downloadURL),
				"expiresAt": expiresAt.Format(time.RFC3339),
			})
			return
		}
		b, err := bundleBuilder.Generate(bundle.GenerateRequest{
			PackagePath:       body.PackagePath,
			PackageID:         body.PackageID,
			PackageSHA256:     body.PackageSHA256,
			PackagePaths:      body.PackagePaths,
			PackageIDs:        body.PackageIDs,
			PackageSHA256s:    body.PackageSHA256s,
			KitPath:           body.KitPath,
			DeploymentProfile: body.DeploymentProfile,
			JobID:             body.JobID,
		})
		if err != nil {
			// Generate errors are input problems (missing/unreadable payload for
			// the selected profile) — surface as 400 with the actionable detail.
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bundle generate failed", "detail": err.Error()})
			return
		}
		if manualDownloads == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "manual install download service unavailable"})
			return
		}
		downloadURL, expiresAt, err := manualDownloads.publishForPlatform(b.Path, platform, b.SHA256)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "manual install download service unavailable", "detail": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"path":        b.Path,
			"sha256":      b.SHA256,
			"jobId":       b.JobID,
			"manifest":    b.Manifest,
			"downloadUrl": downloadURL,
			"platform":    platform,
			"command":     manualInstallCommandFor(platform, downloadURL),
			"expiresAt":   expiresAt.Format(time.RFC3339),
		})
	}
	mux.HandleFunc("POST /api/manual-install/generate", generateManualInstall)
	// Keep the old route as a compatibility alias while the UI migrates. It now
	// returns the same pull-based manual-install response.
	mux.HandleFunc("POST /api/bundle/generate", generateManualInstall)

	// POST /api/bundle/import: decode + verify an offline result (AB-FR-142/143),
	// returning the layered install/verify status. Discovery remains pending —
	// the wizard continues to PG/discovery via the existing enroll endpoint
	// (FR-036). The result carries no credential.
	mux.HandleFunc("POST /api/bundle/import", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Result  string `json:"result"`
			JobID   string `json:"jobId"`
			Profile string `json:"profile"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if body.Result == "" {
			http.Error(w, "result required", http.StatusBadRequest)
			return
		}
		res, err := bundle.Import([]byte(body.Result), bundle.ImportOptions{
			ExpectedJobID:   body.JobID,
			ExpectedProfile: body.Profile,
		})
		if err != nil {
			code := http.StatusUnprocessableEntity
			writeJSON(w, code, map[string]any{"error": err.Error(), "result": res})
			return
		}
		// Import already rejected ok=false results, so reaching here means the
		// profile-required steps succeeded. packageInstalled is deliberately NOT
		// the success signal: a kit-only bundle legitimately installs via the Kit
		// (packageInstalled=false, deploymentKitReady=true).
		writeJSON(w, http.StatusOK, map[string]any{
			"installLayer":   "succeeded",
			"discoveryLayer": "pending", // continue via /api/pg/enroll (FR-036)
			"result":         res,
			"target":         res.Target,
		})
	})
}

func manualInstallCommand(bootstrapURL string) string {
	return fmt.Sprintf("curl -fsSL %s | sudo bash", shellQuote(bootstrapURL))
}

func manualInstallCommandFor(platform, bootstrapURL string) string {
	if strings.EqualFold(platform, "windows") {
		return manualWindowsInstallCommand(bootstrapURL)
	}
	return manualInstallCommand(bootstrapURL)
}

// manualWindowsInstallCommand is a single paste-and-run PowerShell command.
// The short-lived HTTP token keeps the operator-facing path as simple as the
// Linux curl command; the downloaded kit is still checked by SHA-256.
func manualWindowsInstallCommand(bootstrapURL string) string {
	return fmt.Sprintf("Invoke-Expression ((Invoke-WebRequest -UseBasicParsing -Uri %s).Content)", powerShellSingleQuote(bootstrapURL))
}

func powerShellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
