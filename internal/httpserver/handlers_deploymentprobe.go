package httpserver

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Coku2015/agentbridge/internal/deploymentprobe"
)

// registerDeploymentKitProbe exposes the post-manual-install readiness check.
// It never accepts a caller-supplied port: the Deployment Kit contract uses
// the Veeam default 6160. The active campaign check prevents a stale command
// from being accepted after a newer kit invalidates the previous campaign.
func registerDeploymentKitProbe(mux *http.ServeMux, log *slog.Logger, dataDir string) {
	mux.HandleFunc("POST /api/deployment-kit/probe", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Host     string `json:"host"`
			Platform string `json:"platform"`
			Campaign string `json:"campaignId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			log.WarnContext(r.Context(), "deployment kit readiness probe rejected", "reason", "request_invalid", "technical_detail", err.Error())
			writeJSON(w, http.StatusBadRequest, map[string]any{"status": deploymentprobe.StatusFailed, "reason": "request_invalid"})
			return
		}
		body.Host = strings.TrimSpace(body.Host)
		body.Platform = strings.ToLower(strings.TrimSpace(body.Platform))
		body.Campaign = strings.TrimSpace(body.Campaign)
		if body.Host == "" || (body.Platform != "windows" && body.Platform != "linux") || body.Campaign == "" {
			log.WarnContext(r.Context(), "deployment kit readiness probe rejected",
				"host", body.Host, "platform", body.Platform, "campaign_id", body.Campaign,
				"reason", "request_invalid",
			)
			writeJSON(w, http.StatusBadRequest, map[string]any{"status": deploymentprobe.StatusFailed, "reason": "request_invalid"})
			return
		}

		if _, _, err := activeKit(dataDir, body.Campaign, "", ""); err != nil {
			log.WarnContext(r.Context(), "deployment kit readiness probe rejected",
				"host", body.Host, "platform", body.Platform, "campaign_id", body.Campaign,
				"reason", "deployment_kit_campaign_invalid", "technical_detail", err.Error(),
			)
			writeJSON(w, http.StatusConflict, map[string]any{"status": deploymentprobe.StatusFailed, "reason": "deployment_kit_campaign_invalid"})
			return
		}

		started := time.Now()
		log.InfoContext(r.Context(), "deployment kit readiness probe started",
			"host", body.Host, "platform", body.Platform, "campaign_id", body.Campaign,
			"port", deploymentprobe.DefaultPort,
		)
		result := deploymentprobe.Check(r.Context(), body.Host, deploymentprobe.DefaultPort)
		attrs := []any{
			"host", body.Host, "platform", body.Platform, "campaign_id", body.Campaign,
			"port", deploymentprobe.DefaultPort, "status", result.Status,
			"reason", result.Reason, "duration_ms", time.Since(started).Milliseconds(),
		}
		if result.Status == deploymentprobe.StatusReady {
			log.InfoContext(r.Context(), "deployment kit readiness probe completed", attrs...)
			writeJSON(w, http.StatusOK, map[string]any{
				"status": result.Status, "host": body.Host, "platform": body.Platform,
				"campaignId": body.Campaign, "checkedAt": time.Now().UTC(),
				"durationMs": result.Duration.Milliseconds(),
			})
			return
		}
		attrs = append(attrs, "technical_detail", result.Detail)
		log.WarnContext(r.Context(), "deployment kit readiness probe failed", attrs...)
		writeJSON(w, http.StatusOK, map[string]any{
			"status": result.Status, "host": body.Host, "platform": body.Platform,
			"campaignId": body.Campaign, "reason": result.Reason,
			"checkedAt": time.Now().UTC(), "durationMs": result.Duration.Milliseconds(),
		})
	})
}
