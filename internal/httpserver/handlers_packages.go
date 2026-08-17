package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Coku2015/agentbridge/internal/deploymentkit"
	"github.com/Coku2015/agentbridge/internal/packages"
	"github.com/Coku2015/agentbridge/internal/vbr"
)

// The Deployment Kit campaign manager and Agent package store are process-wide
// singletons rooted under the server data dir and created lazily on first use.
var (
	kitManager       *deploymentkit.Manager
	kitManagerOnce   sync.Once
	kitManagerErr    error
	packageStore     *packages.ArtifactStore
	packageStoreOnce sync.Once
	packageStoreErr  error
)

func initKitManager(dataDir string) {
	kitManagerOnce.Do(func() {
		m, err := deploymentkit.NewManager(nil, filepath.Join(dataDir, "kit"))
		if err != nil {
			kitManagerErr = err
			return
		}
		kitManager = m
	})
}

func initPackageStore(dataDir string) {
	packageStoreOnce.Do(func() {
		m, err := packages.NewArtifactStore(filepath.Join(dataDir, "packages"))
		if err != nil {
			packageStoreErr = err
			return
		}
		packageStore = m
	})
}

// registerPackages wires the package catalog/export + Deployment Kit endpoints
// (US2, FR-007..013). Kit generate requires deploymentKit; Kit import is
// local-only (no VBR needed — it is the fallback path for when VBR Kit
// generation is unavailable).
func registerPackages(mux *http.ServeMux, log *slog.Logger, dataDir string) {
	// GET /api/packages/linux: list the Linux Agent package catalog from the
	// connected VBR (FR-007).
	mux.HandleFunc("GET /api/packages/linux", func(w http.ResponseWriter, r *http.Request) {
		adapter, _, ok := requireVBR(w, "agentPackages")
		if !ok {
			return
		}
		pkgs, err := packages.NewCatalog(adapter).List(r.Context())
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "list packages failed", "detail": err.Error()})
			log.Error("agent package catalog failed", "error", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"packages": pkgs})
		log.Info("agent package catalog loaded", "package_count", len(pkgs))
	})

	// POST /api/packages/download: ask VBR to export the selected Linux packages.
	// Each catalog selection is exported independently: VBR may return several
	// RPM/DEB payloads for one selection, but different selections must never be
	// combined into one install set. Every temporary PreInstalledAgents PG is
	// deleted when its response stream closes.
	mux.HandleFunc("POST /api/packages/download", func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		adapter, _, ok := requireVBR(w, "agentPackages")
		if !ok {
			log.Warn("agent package download rejected", "reason", "vbr unavailable")
			return
		}
		var body struct {
			PackageName  string   `json:"packageName"` // backwards-compatible single selection
			PackageNames []string `json:"packageNames"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		names := make([]string, 0, len(body.PackageNames)+1)
		for _, name := range body.PackageNames {
			if strings.TrimSpace(name) != "" {
				names = append(names, name)
			}
		}
		if len(names) == 0 && strings.TrimSpace(body.PackageName) != "" {
			names = append(names, body.PackageName)
		}
		if len(names) == 0 {
			http.Error(w, "packageNames required", http.StatusBadRequest)
			log.Warn("agent package download rejected", "reason", "packageNames required")
			return
		}
		log.Info("agent package download started", "package_count", len(names), "packages", names)
		initPackageStore(dataDir)
		if packageStoreErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "package store init failed", "detail": packageStoreErr.Error()})
			log.Error("agent package download failed", "stage", "package_store_init", "packages", names, "error", packageStoreErr, "duration_ms", time.Since(started).Milliseconds())
			return
		}
		// Bound the whole VBR workflow, including a slow or disconnected
		// response body. Without this, fetch() can remain in "拉取中" forever
		// when the VBR connection disappears mid-export.
		downloadCtx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
		defer cancel()
		artifacts, err := packageStore.DownloadMany(downloadCtx, adapter, names)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "agent package download failed", "detail": err.Error()})
			log.Error("agent package download failed", "stage", "vbr_export_or_artifact", "packages", names, "error", err, "duration_ms", time.Since(started).Milliseconds())
			return
		}
		for _, artifact := range artifacts {
			payloadNames := []string{artifact.FileName}
			if len(artifact.Payloads) > 0 {
				payloadNames = make([]string, 0, len(artifact.Payloads))
				for _, payload := range artifact.Payloads {
					payloadNames = append(payloadNames, payload.FileName)
				}
			}
			log.Info("agent package artifact ready", "package", artifact.PackageName, "artifact", artifact.FileName, "format", artifact.Format, "size", artifact.Size, "payload_count", len(payloadNames), "payloads", payloadNames)
		}
		writeJSON(w, http.StatusOK, map[string]any{"artifacts": artifacts})
		log.Info("agent package download completed", "packages", names, "artifact_count", len(artifacts), "duration_ms", time.Since(started).Milliseconds())
	})

	// GET /api/kit: read-only view of the active campaign (the step-一 kit
	// drawer): archive file list, sizes and the certificate-derived expiry.
	// Local-only — no VBR round-trip, no capability needed.
	mux.HandleFunc("GET /api/kit", func(w http.ResponseWriter, _ *http.Request) {
		initKitManager(dataDir)
		if kitManagerErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "kit manager init failed", "detail": kitManagerErr.Error()})
			return
		}
		camp := kitManager.Active()
		if camp == nil {
			writeJSON(w, http.StatusOK, map[string]any{"kit": nil})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"kit": camp.Info()})
	})

	// POST /api/kit/generate: generate a Deployment Kit (capability-gated). A new
	// Kit invalidates any prior unpaired campaign (R8/R9); the response warns.
	mux.HandleFunc("POST /api/kit/generate", func(w http.ResponseWriter, r *http.Request) {
		adapter, _, ok := requireVBR(w, "deploymentKit")
		if !ok {
			return
		}
		initKitManager(dataDir)
		if kitManagerErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "kit manager init failed", "detail": kitManagerErr.Error()})
			return
		}
		var body struct {
			Platforms     []string `json:"platforms"`
			ValidityHours int      `json:"validityHours"`
		}
		if r.Body != nil {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid body", "detail": err.Error()})
				return
			}
		}
		validityHours := body.ValidityHours
		if validityHours <= 0 {
			validityHours = 720
		}
		req := vbr.KitRequest{ValidityHours: validityHours}
		if len(body.Platforms) == 0 {
			req.IncludeWindowsPackages = true
			req.IncludeLinuxPackages = true
		} else {
			for _, platform := range body.Platforms {
				switch strings.ToLower(strings.TrimSpace(platform)) {
				case "windows":
					req.IncludeWindowsPackages = true
				case "linux":
					req.IncludeLinuxPackages = true
				case "unix":
					req.IncludeUnixPackages = true
				default:
					writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported platform", "platform": platform})
					return
				}
			}
		}
		kitManager.SetGenerator(adapter)
		camp, invalidated, err := kitManager.Generate(r.Context(), req)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "kit generate failed", "detail": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, kitResponse(camp, invalidated))
	})

	// POST /api/kit/import: admin-supplied Kit. A purely LOCAL staging operation:
	// no VBR connection and no capability is required — this is the fallback that
	// must work exactly when VBR/generateKit is unavailable (red line 8 governs
	// silent REST fallbacks, not local file imports). Multipart upload; no
	// credential involved.
	mux.HandleFunc("POST /api/kit/import", func(w http.ResponseWriter, r *http.Request) {
		initKitManager(dataDir)
		if kitManagerErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "kit manager init failed", "detail": kitManagerErr.Error()})
			return
		}
		if err := r.ParseMultipartForm(256 << 20); err != nil { // max 256 MiB
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid upload", "detail": err.Error()})
			return
		}
		f, _, err := r.FormFile("kit")
		if err != nil {
			http.Error(w, "kit file required", http.StatusBadRequest)
			return
		}
		defer f.Close()
		camp, invalidated, err := kitManager.Import(f)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "kit import failed", "detail": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, kitResponse(camp, invalidated))
	})
}

// kitResponse shapes the generate/import reply, surfacing the invalidation warning.
func kitResponse(camp *deploymentkit.Campaign, invalidated bool) map[string]any {
	info := camp.Info()
	resp := map[string]any{
		"campaignId": camp.ID(), "source": camp.Source(), "platforms": info.Platforms,
		"createdAt": info.CreatedAt, "expiresAt": info.ExpiresAt, "sha256": info.SHA256,
		"previousCampaignInvalidated": invalidated,
		// Keep id/path for existing local clients during the migration. New
		// callers must use campaignId and never submit path values back.
		"id": camp.ID(), "path": camp.Path(), "warning": "",
	}
	if invalidated {
		resp["warning"] = "a previous Deployment Kit campaign was invalidated: its unpaired temporary certificates are no longer valid"
	}
	return resp
}
