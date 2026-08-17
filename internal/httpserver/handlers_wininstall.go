package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Coku2015/agentbridge/internal/windowsdeploy"
)

// registerWindowsInstall exposes the Windows SMB/RPC workflow. Passwords are
// read only into the request handler and cleared before it returns; no durable
// credential record is created.
func registerWindowsInstall(mux *http.ServeMux, log *slog.Logger, dataDir string) {
	mux.HandleFunc("POST /api/windows/preflight", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Host     string `json:"host"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			log.Warn("invalid windows preflight request", "technical_detail", err.Error())
			writeJSON(w, http.StatusBadRequest, map[string]any{"status": windowsdeploy.StatusAuthFailed, "error": "windows_request_invalid", "failureStage": "request_validation", "detail": "The Windows preflight request is not valid."})
			return
		}
		defer func() { body.Password = "" }()
		if strings.TrimSpace(body.Host) == "" || strings.TrimSpace(body.Username) == "" || body.Password == "" {
			log.Warn("windows remote install preflight request rejected",
				"host", strings.TrimSpace(body.Host),
				"failure_stage", "request_validation",
				"error", "windows_request_invalid",
			)
			writeJSON(w, http.StatusBadRequest, map[string]any{"status": windowsdeploy.StatusAuthFailed, "error": "windows_request_invalid", "failureStage": "request_validation", "detail": "The Windows host and administrator credentials are incomplete."})
			return
		}
		started := time.Now()
		log.InfoContext(r.Context(), "windows remote install preflight started", "host", body.Host)
		res := (windowsdeploy.Client{}).Preflight(r.Context(), windowsdeploy.Request{
			Host: body.Host, Username: body.Username, Password: body.Password,
		})
		logWindowsPreflightResult(r.Context(), log, body.Host, body.Password, res, time.Since(started))
		// Preflight status is part of the public response so the UI can offer the
		// local one-click fallback for Remote UAC without changing target policy.
		writeJSON(w, http.StatusOK, res)
	})

	mux.HandleFunc("POST /api/windows/install", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Host      string `json:"host"`
			Username  string `json:"username"`
			Password  string `json:"password"`
			Campaign  string `json:"campaignId"`
			KitPath   string `json:"kitPath"`   // legacy local client field
			KitSHA256 string `json:"kitSha256"` // verified against active campaign
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			log.Warn("invalid windows install request", "technical_detail", err.Error())
			writeJSON(w, http.StatusBadRequest, map[string]any{"status": windowsdeploy.StatusInstallFailed, "error": "windows_request_invalid", "failureStage": "request_validation", "detail": "The Windows install request is not valid."})
			return
		}
		defer func() { body.Password = "" }()
		if strings.TrimSpace(body.Host) == "" || strings.TrimSpace(body.Username) == "" || body.Password == "" {
			log.Warn("windows deployment kit install request rejected",
				"host", strings.TrimSpace(body.Host),
				"campaign_id", body.Campaign,
				"failure_stage", "request_validation",
				"error", "windows_request_invalid",
			)
			writeJSON(w, http.StatusBadRequest, map[string]any{"status": windowsdeploy.StatusInstallFailed, "error": "windows_request_invalid", "failureStage": "request_validation", "detail": "The Windows host and administrator credentials are incomplete."})
			return
		}
		path, digest, err := activeKit(dataDir, body.Campaign, body.KitPath, body.KitSHA256)
		if err != nil {
			log.Warn("windows install deployment kit campaign rejected",
				"host", body.Host,
				"campaign_id", body.Campaign,
				"failure_stage", "kit_validation",
				"error", "deployment_kit_campaign_invalid",
				"technical_detail", redactWindowsSecret(err.Error(), body.Password),
			)
			writeJSON(w, http.StatusConflict, map[string]any{"status": windowsdeploy.StatusInstallFailed, "error": "deployment_kit_campaign_invalid", "failureStage": "kit_validation", "detail": "The requested Deployment Kit campaign is no longer active."})
			return
		}
		started := time.Now()
		log.InfoContext(r.Context(), "windows deployment kit install started",
			"host", body.Host,
			"campaign_id", body.Campaign,
		)
		res := (windowsdeploy.Client{}).Install(r.Context(), windowsdeploy.Request{
			Host: body.Host, Username: body.Username, Password: body.Password,
			KitPath: path, KitSHA256: digest,
		})
		logWindowsInstallResult(r.Context(), log, body.Host, body.Campaign, body.Password, res, time.Since(started))
		if res.Status != windowsdeploy.StatusInstalled {
			code := http.StatusUnprocessableEntity
			if res.Status == windowsdeploy.StatusAuthFailed || res.Status == windowsdeploy.StatusRemoteUACBlocked {
				code = http.StatusUnauthorized
			}
			if res.Status == windowsdeploy.StatusTaskSchedulerDenied {
				code = http.StatusForbidden
			}
			writeJSON(w, code, res)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
}

func logWindowsPreflightResult(ctx context.Context, log *slog.Logger, host, password string, res windowsdeploy.Result, elapsed time.Duration) {
	attrs := windowsResultAttrs(host, res, elapsed)
	if res.Status == windowsdeploy.StatusReady {
		log.LogAttrs(ctx, slog.LevelInfo, "windows remote install preflight completed", attrs...)
		return
	}
	attrs = append(attrs, windowsFailureAttrs(password, res)...)
	log.LogAttrs(ctx, slog.LevelWarn, "windows remote install preflight failed", attrs...)
}

func logWindowsInstallResult(ctx context.Context, log *slog.Logger, host, campaignID, password string, res windowsdeploy.Result, elapsed time.Duration) {
	attrs := windowsResultAttrs(host, res, elapsed)
	attrs = append(attrs, slog.String("campaign_id", campaignID))
	if res.Status == windowsdeploy.StatusInstalled {
		log.LogAttrs(ctx, slog.LevelInfo, "windows deployment kit install completed", attrs...)
		return
	}
	attrs = append(attrs, windowsFailureAttrs(password, res)...)
	log.LogAttrs(ctx, slog.LevelWarn, "windows deployment kit install failed", attrs...)
}

func windowsResultAttrs(host string, res windowsdeploy.Result, elapsed time.Duration) []slog.Attr {
	return []slog.Attr{
		slog.String("host", host),
		slog.String("status", res.Status),
		slog.String("authentication", res.Authentication),
		slog.String("admin_share", res.AdminShare),
		slog.String("task_scheduler_rpc", res.TaskSchedulerRPC),
		slog.String("rpc_auth_level", res.RPCAuthLevel),
		slog.Bool("service_ready", res.ServiceReady),
		slog.Int64("duration_ms", elapsed.Milliseconds()),
	}
}

func windowsFailureAttrs(password string, res windowsdeploy.Result) []slog.Attr {
	return []slog.Attr{
		slog.String("error", res.ErrorKey),
		slog.String("error_code", res.ErrorCode),
		slog.String("error_field", res.ErrorField),
		slog.String("error_value", res.ErrorValue),
		slog.Uint64("error_line", uint64(res.ErrorLine)),
		slog.Uint64("error_column", uint64(res.ErrorColumn)),
		slog.String("failure_stage", res.FailureStage),
		slog.String("detail", redactWindowsSecret(res.Detail, password)),
		slog.String("technical_detail", redactWindowsSecret(res.TechnicalDetail, password)),
	}
}

func redactWindowsSecret(value, password string) string {
	if password == "" {
		return value
	}
	return strings.ReplaceAll(value, password, "[REDACTED]")
}

func activeKit(dataDir, campaignID, legacyPath, requestedSHA string) (string, string, error) {
	initKitManager(dataDir)
	if kitManagerErr != nil || kitManager == nil {
		if kitManagerErr != nil {
			return "", "", kitManagerErr
		}
		return "", "", fmt.Errorf("kit manager unavailable")
	}
	camp := kitManager.Active()
	if camp == nil {
		return "", "", fmt.Errorf("no active Deployment Kit campaign")
	}
	if campaignID != "" && campaignID != camp.ID() {
		return "", "", fmt.Errorf("campaign %q is no longer active", campaignID)
	}
	if campaignID == "" && legacyPath != "" && legacyPath != camp.Path() {
		return "", "", fmt.Errorf("kit path is not the active campaign")
	}
	digest := camp.SHA256()
	if requestedSHA != "" && !strings.EqualFold(requestedSHA, digest) {
		return "", "", fmt.Errorf("kit SHA-256 does not match the active campaign")
	}
	return camp.Path(), digest, nil
}
