package httpserver

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"

	"github.com/Coku2015/agentbridge/internal/security"
	"github.com/Coku2015/agentbridge/internal/vbr"
)

// vbrSession holds the single active VBR connection for localhost single-user
// mode. The adapter carries only in-memory secrets; nothing here is persisted.
type vbrSession struct {
	mu          sync.Mutex
	adapter     *vbr.RESTAdapter
	caps        vbr.Capabilities
	server      vbr.ServerInfo
	fingerprint string // confirmed TLS pin (non-secret) used to scope cache keys
	scrubber    *security.Scrubber
	log         *slog.Logger
}

var activeVBR = &vbrSession{}

// registerVBR wires the VBR connection + capability endpoints (US1, FR-001..006).
func registerVBR(mux *http.ServeMux, log *slog.Logger, scrubber *security.Scrubber) {
	activeVBR.scrubber = scrubber
	activeVBR.log = log

	// POST /api/vbr/capture: retrieve the VBR TLS fingerprint WITHOUT trusting it
	// (AB-FR-022). The operator MUST confirm before /api/vbr/connect.
	mux.HandleFunc("POST /api/vbr/capture", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Server string `json:"server"`
			Port   int    `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		a := vbr.NewRESTAdapter(vbr.Credentials{}, scrubber, log)
		fp, err := a.CaptureFingerprint(r.Context(), body.Server, body.Port)
		if err != nil {
			writeVBRConnectionFailure(w, log, "capture", body.Server, body.Port, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"fingerprint": fp})
	})

	// POST /api/vbr/connect: confirm fingerprint + authenticate. The password is
	// read from the body, held only in memory, and registered with the scrubber.
	mux.HandleFunc("POST /api/vbr/connect", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Server      string `json:"server"`
			Port        int    `json:"port"`
			Username    string `json:"username"`
			Password    string `json:"password"` // memory-only; never logged
			Fingerprint string `json:"fingerprint"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if body.Fingerprint == "" {
			http.Error(w, "fingerprint confirmation required (AB-FR-022)", http.StatusPreconditionRequired)
			return
		}
		adapter := vbr.NewRESTAdapter(vbr.Credentials{Password: body.Password}, scrubber, log)
		cfg := vbr.ConnectionConfig{
			Server:          body.Server,
			Port:            body.Port,
			Username:        body.Username,
			PinnedTLSSHA256: body.Fingerprint,
		}
		if err := adapter.Connect(r.Context(), cfg); err != nil {
			writeVBRConnectionFailure(w, log, "connect", body.Server, body.Port, err)
			return
		}
		info, err := adapter.ServerInfo(r.Context())
		if err != nil {
			writeVBRConnectionFailure(w, log, "server_info", body.Server, body.Port, err)
			return
		}
		caps, err := adapter.Capabilities(r.Context())
		if err != nil {
			writeVBRConnectionFailure(w, log, "capabilities", body.Server, body.Port, err)
			return
		}
		activeVBR.mu.Lock()
		activeVBR.adapter = adapter
		activeVBR.server = info
		activeVBR.caps = caps
		activeVBR.fingerprint = body.Fingerprint
		activeVBR.mu.Unlock()

		// Clear the password from the request body buffer explicitly (memory-only).
		body.Password = ""
		writeJSON(w, http.StatusOK, map[string]any{"serverInfo": info, "capabilities": caps})
	})

	// GET /api/vbr/capabilities: the UI disables paths up front from this
	// (Principle III, AB-FR-023).
	mux.HandleFunc("GET /api/vbr/capabilities", func(w http.ResponseWriter, r *http.Request) {
		activeVBR.mu.Lock()
		caps, connected := activeVBR.caps, activeVBR.adapter != nil
		activeVBR.mu.Unlock()
		if !connected {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "not connected", "actionable": "Connect to VBR first (POST /api/vbr/connect)"})
			return
		}
		writeJSON(w, http.StatusOK, caps)
	})
}

// requireVBR returns the active adapter + capabilities, or writes an actionable
// error and returns false when not connected / capability missing (Principle III:
// no silent fallback). Downstream handlers use this as their capability gate.
// An empty capability skips the capability check (connected-only).
func requireVBR(w http.ResponseWriter, capability string) (*vbr.RESTAdapter, vbr.Capabilities, bool) {
	activeVBR.mu.Lock()
	defer activeVBR.mu.Unlock()
	if activeVBR.adapter == nil {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":      "vbr not connected",
			"actionable": "Connect to VBR first; this workflow is disabled until then",
		})
		return nil, vbr.Capabilities{}, false
	}
	if capability != "" && !capabilityEnabled(activeVBR.caps, capability) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":      "capability not available on this VBR build",
			"capability": capability,
			"actionable": "The connected VBR build does not expose this REST capability; the workflow is disabled (no silent fallback)",
		})
		return nil, vbr.Capabilities{}, false
	}
	return activeVBR.adapter, activeVBR.caps, true
}

// capabilityEnabled maps a capability name to its Capabilities flag.
func capabilityEnabled(c vbr.Capabilities, name string) bool {
	switch name {
	case "agentPackages":
		return c.AgentPackages
	case "deploymentKit":
		return c.DeploymentKit
	case "protectionGroup":
		return c.ProtectionGroup
	case "rescan":
		return c.Rescan
	case "session":
		return c.Session
	case "discoveredEntities":
		return c.DiscoveredEntities
	}
	return false
}

// errVBRNotConnected is returned by helpers when callers bypass the HTTP gate.
var errVBRNotConnected = errors.New("vbr: not connected")
