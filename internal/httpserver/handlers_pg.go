package httpserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Coku2015/agentbridge/internal/pg"
	"github.com/Coku2015/agentbridge/internal/vbr"
)

func writePGCreateError(w http.ResponseWriter, err error) {
	var conflict *pg.ErrNameConflict
	if errors.As(err, &conflict) || strings.Contains(strings.ToLower(err.Error()), "already exists") || strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(strings.ToLower(err.Error()), "name conflict") {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":  "protection_group_name_conflict",
			"code":   "protection_group_name_conflict",
			"detail": conflict.Error(),
			"name":   conflict.Name,
		})
		return
	}
	writeJSON(w, http.StatusBadGateway, map[string]any{"error": "pg create failed", "detail": err.Error()})
}

const pgDiscoveryDetailUnavailable = "VBR did not return detailed discovery information. Open VBR to view the Protection Group details."

// pgDiscoveryErrorPayload never exposes PG/session UUIDs or Go error chains to
// the browser. A failed rescan uses VBR's SessionResultModel.message verbatim
// when present; otherwise the UI receives an explicit source marker so it can
// localize the VBR fallback notice.
func pgDiscoveryErrorPayload(err error) map[string]any {
	detail, fromVBR := pg.RescanErrorDetail(err)
	if fromVBR {
		payload := map[string]any{
			"error":        "protection_group_rescan_failed",
			"detail":       detail,
			"detailSource": "vbr",
		}
		var rescanErr *pg.ErrRescan
		if errors.As(err, &rescanErr) && len(rescanErr.Failures) > 0 {
			payload["failures"] = rescanErr.Failures
		}
		return payload
	}
	var rescanErr *pg.ErrRescan
	if errors.As(err, &rescanErr) {
		return map[string]any{
			"error":        "protection_group_rescan_failed",
			"detail":       pg.RescanDetailUnavailable,
			"detailSource": "unavailable",
		}
	}
	return map[string]any{
		"error":        "protection_group_discovery_failed",
		"detail":       pgDiscoveryDetailUnavailable,
		"detailSource": "unavailable",
	}
}

// pgPoll is the default async-session polling budget for PG operations.
func pgPoll() pg.PollOptions {
	return pg.PollOptions{Interval: 2 * time.Second, Timeout: 5 * time.Minute}
}

// computersOf converts operator-supplied host names to the certificate-enrolled
// computer list (identifiers only — never credentials).
func computersOf(hosts []string) []vbr.IndividualComputer {
	out := make([]vbr.IndividualComputer, 0, len(hosts))
	for _, h := range hosts {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, vbr.IndividualComputer{HostName: h})
		}
	}
	return out
}

// registerPG wires the Protection Group + discovery endpoints (US5). Every endpoint
// is gated on the active VBR connection + the relevant capability (Principle III:
// no silent fallback).
func registerPG(mux *http.ServeMux) {
	// POST /api/pg/create: certificate-based PG create. Existing names are
	// rejected so VBR-side edits are never overwritten.
	mux.HandleFunc("POST /api/pg/create", func(w http.ResponseWriter, r *http.Request) {
		adapter, _, ok := requireVBR(w, "protectionGroup")
		if !ok {
			return
		}
		var body struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Hosts       []string `json:"hosts"` // targets enrolled via the kit certificate
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		body.Name = strings.TrimSpace(body.Name)
		if body.Name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		spec := vbr.ProtectionGroupSpec{Name: body.Name, Description: body.Description, Computers: computersOf(body.Hosts)}
		id, created, err := pg.Create(r.Context(), adapter, spec, pgPoll())
		if err != nil {
			writePGCreateError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"pgId": id, "created": created})
	})

	// POST /api/pg/{id}/rescan: trigger a rescan + await its session (FR-030).
	mux.HandleFunc("POST /api/pg/{id}/rescan", func(w http.ResponseWriter, r *http.Request) {
		adapter, _, ok := requireVBR(w, "rescan")
		if !ok {
			return
		}
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "pg id required", http.StatusBadRequest)
			return
		}
		if err := pg.Rescan(r.Context(), adapter, id, pgPoll()); err != nil {
			writeJSON(w, http.StatusBadGateway, pgDiscoveryErrorPayload(err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	// GET /api/pg/{id}/discovered: rescan + read discovered entities, layered.
	mux.HandleFunc("GET /api/pg/{id}/discovered", func(w http.ResponseWriter, r *http.Request) {
		adapter, _, ok := requireVBR(w, "discoveredEntities")
		if !ok {
			return
		}
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "pg id required", http.StatusBadRequest)
			return
		}
		d, err := pg.Discover(r.Context(), adapter, id, pgPoll())
		if err != nil {
			writeJSON(w, http.StatusBadGateway, pgDiscoveryErrorPayload(err))
			return
		}
		writeJSON(w, http.StatusOK, d)
	})

	// POST /api/pg/enroll: create + discovery for one or more hosts. Returns
	// the PG id, whether it was newly created, and the layered discovery view. This
	// is the single-shot enrollment the wizard drives after a successful install.
	mux.HandleFunc("POST /api/pg/enroll", func(w http.ResponseWriter, r *http.Request) {
		adapter, _, ok := requireVBR(w, "protectionGroup")
		if !ok {
			return
		}
		var body struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Hosts       []string `json:"hosts"` // targets enrolled via the kit certificate
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		body.Name = strings.TrimSpace(body.Name)
		if body.Name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		spec := vbr.ProtectionGroupSpec{Name: body.Name, Description: body.Description, Computers: computersOf(body.Hosts)}
		id, created, err := pg.Create(r.Context(), adapter, spec, pgPoll())
		if err != nil {
			writePGCreateError(w, err)
			return
		}
		disc, derr := pg.Discover(r.Context(), adapter, id, pgPoll())
		if derr != nil {
			// Create succeeded but discovery failed: surface both layers distinctly.
			failure := pgDiscoveryErrorPayload(derr)
			writeJSON(w, http.StatusOK, map[string]any{
				"pgId":           id,
				"created":        created,
				"installLayer":   "succeeded",
				"discoveryLayer": "failed",
				"discoveryError": failure["error"],
				"detail":         failure["detail"],
				"detailSource":   failure["detailSource"],
				"failures":       failure["failures"],
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"pgId":           id,
			"created":        created,
			"installLayer":   "succeeded",
			"discoveryLayer": "succeeded",
			"entities":       disc.Entities,
			"found":          disc.Found,
		})
	})
}
