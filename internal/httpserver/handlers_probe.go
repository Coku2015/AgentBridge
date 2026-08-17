package httpserver

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/Coku2015/agentbridge/internal/matcher"
	"github.com/Coku2015/agentbridge/internal/probe"
)

// matcherEngine is the shared, lazily-initialized embedded-rule matcher. It is
// deterministic and stateless, so a process-wide singleton is safe.
var (
	matcherOnce sync.Once
	matcherEng  *matcher.Engine
	matcherErr  error
)

func sharedMatcher() (*matcher.Engine, error) {
	matcherOnce.Do(func() {
		matcherEng, matcherErr = matcher.NewEngine()
	})
	return matcherEng, matcherErr
}

// matchResponse is the JSON contract for /api/match and /api/match/override.
type matchResponse struct {
	Recommendation matcher.Recommendation `json:"recommendation"`
	Level          matcher.RuleLevel      `json:"level"`
}

// registerProbe wires the probe + match endpoints (US3, FR-014..022). The matcher
// consumes pure probe facts; no credential crosses these endpoints.
func registerProbe(mux *http.ServeMux) {
	// POST /api/match: turn probe facts into an explanatory recommendation. Accepts
	// a probe.Result (the natural output of a probe) and converts it locally.
	mux.HandleFunc("POST /api/match", func(w http.ResponseWriter, r *http.Request) {
		var res probe.Result
		if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		eng, err := sharedMatcher()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "matcher unavailable", "detail": err.Error()})
			return
		}
		rec, level, err := eng.Match(matcherInput(res))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "match failed", "detail": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, matchResponse{Recommendation: rec, Level: level})
	})

	// POST /api/match/override: record an operator's manual package choice. The
	// result is always UserSelected — never re-labelled (red line 11, AB-FR-102).
	mux.HandleFunc("POST /api/match/override", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			PackageID string `json:"packageId"`
			Reason    string `json:"reason"`
			User      string `json:"user"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if body.PackageID == "" {
			http.Error(w, "packageId required", http.StatusBadRequest)
			return
		}
		rec, level := matcher.ApplyOverride(matcher.Override{
			PackageID: body.PackageID,
			Reason:    body.Reason,
			User:      body.User,
		}, nil)
		writeJSON(w, http.StatusOK, matchResponse{Recommendation: rec, Level: level})
	})

	// POST /api/probe/local: run the static POSIX fact script on THIS host (the
	// Zero-Credential / Local path). No SSH, no root, no credential.
	mux.HandleFunc("POST /api/probe/local", func(w http.ResponseWriter, r *http.Request) {
		res, err := probe.NewLocalProbe().Run(r.Context())
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "local probe failed", "detail": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})

	// POST /api/probe/import: accept an offline-supplied probe result and validate
	// its schema (FR-017). Lets a locked-down host's facts enter the flow without a
	// credential ever being held by AgentBridge.
	mux.HandleFunc("POST /api/probe/import", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Result json.RawMessage `json:"result"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		res, err := probe.Import(body.Result)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "probe import failed", "detail": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
}

// matcherInput projects a probe.Result into the matcher's local Input type. The
// matcher deliberately does not import probe (it stays a leaf rule engine), so the
// composition root maps between them.
func matcherInput(r probe.Result) matcher.Input {
	return matcher.Input{
		PackageFormat: r.PackageFormat,
		Architecture:  r.Target.Architecture,
		ID:            r.OS.ID,
		IDLike:        r.OS.IDLike,
		VersionID:     r.OS.VersionID,
		RHELMacro:     r.RHELMacro,
		Glibc:         r.Glibc,
		Kernel:        r.Kernel,
		SecureBoot:    r.SecureBoot,
		ExistingAgent: len(r.ExistingVeeamPackages) > 0,
	}
}
