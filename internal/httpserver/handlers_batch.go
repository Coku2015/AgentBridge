package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/Coku2015/agentbridge/internal/job"
	"github.com/Coku2015/agentbridge/internal/pg"
	"github.com/Coku2015/agentbridge/internal/vbr"
)

// batches holds active batch runs keyed by id, for progress polling + retry
// (FR-038/039). Per-host state is non-secret; nothing credential-bearing is
// stored here.
var (
	batchesMu sync.Mutex
	batches   = map[string]*job.Batch{}
)

// registerBatch wires the batch orchestration endpoints (US7, FR-037..039). The
// MVP batch runs the VBR enrollment phase across many hosts against one shared
// idempotent Protection Group: each host is checked for discovery independently,
// so one host's failure never blocks the others (AB-NFR-004). It needs only the
// VBR connection — no SSH credentials — so it is credential-light (red line 1).
func registerBatch(mux *http.ServeMux, bus *Bus) {
	publish := func(batchID string) func(job.BatchEvent) {
		return func(e job.BatchEvent) {
			ev := Event{Type: e.Type, BatchID: batchID, HostID: e.HostID, Message: e.Message}
			if e.Type == "host" {
				ev.State = string(e.State)
			} else {
				ev.State = string(e.BatchState)
			}
			bus.Publish(ev)
		}
	}

	// POST /api/batch: import hosts (text/CSV), create one PG, and run the
	// per-host enrollment batch asynchronously with live SSE progress.
	mux.HandleFunc("POST /api/batch", func(w http.ResponseWriter, r *http.Request) {
		adapter, _, ok := requireVBR(w, "protectionGroup")
		if !ok {
			return
		}
		var body struct {
			Hosts       string `json:"hosts"`
			PgName      string `json:"pgName"`
			Description string `json:"description"`
			Port        int    `json:"port"`
			Concurrency int    `json:"concurrency"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		body.PgName = strings.TrimSpace(body.PgName)
		if body.PgName == "" {
			http.Error(w, "pgName required", http.StatusBadRequest)
			return
		}
		hosts, err := job.ImportHosts([]byte(body.Hosts), job.HostDefaults{Port: body.Port})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "host import failed", "detail": err.Error()})
			return
		}
		if len(hosts) == 0 {
			http.Error(w, "no hosts parsed", http.StatusBadRequest)
			return
		}

		// Shared exclusive PG create (a name conflict aborts the batch before any
		// per-host work — no existing PG is reused, AB-NFR-005).
		// Every imported host is enrolled via the kit certificate (connectionType
		// "Certificate" — no VBR credential is ever attached).
		computers := make([]vbr.IndividualComputer, 0, len(hosts))
		for _, h := range hosts {
			computers = append(computers, vbr.IndividualComputer{HostName: h.Host})
		}
		spec := vbr.ProtectionGroupSpec{Name: body.PgName, Description: body.Description, Computers: computers}
		pgID, _, err := pg.Create(r.Context(), adapter, spec, pgPoll())
		if err != nil {
			var conflict *pg.ErrNameConflict
			if errors.As(err, &conflict) || strings.Contains(strings.ToLower(err.Error()), "already exists") || strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(strings.ToLower(err.Error()), "name conflict") {
				writeJSON(w, http.StatusConflict, map[string]any{"error": "protection_group_name_conflict", "code": "protection_group_name_conflict", "detail": conflict.Error(), "name": conflict.Name})
			} else {
				writeJSON(w, http.StatusBadGateway, map[string]any{"error": "pg create failed", "detail": err.Error()})
			}
			return
		}

		// Per-host action: enroll (discover) each host independently. A host that is
		// not discovered lands in DiscoveryFailed without affecting the others.
		taskByHost := map[string]string{}
		for _, h := range hosts {
			taskByHost[h.ID] = h.Host
		}
		action := func(ctx context.Context, hostID string, sink job.HostSink) error {
			sink(job.HostLocalInstallSucceeded, job.HostCreatingRegistration, "")
			sink(job.HostCreatingRegistration, job.HostRescanning, "")
			disc, derr := pg.Discover(ctx, adapter, pgID, pgPoll())
			if derr != nil {
				sink(job.HostRescanning, job.HostDiscoveryFailed, derr.Error())
				return nil
			}
			if disc.Contains(taskByHost[hostID]) {
				sink(job.HostRescanning, job.HostDiscovered, "discovered")
				sink(job.HostDiscovered, job.HostCompleted, "enrolled")
			} else {
				sink(job.HostRescanning, job.HostDiscoveryFailed, "host not discovered by VBR")
			}
			return nil
		}

		batchID, err := randomToken(8)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "id gen failed"})
			return
		}
		b := job.NewBatch(job.BatchConfig{
			ID:           batchID,
			Concurrency:  body.Concurrency,
			Hosts:        hosts,
			InitialState: job.HostLocalInstallSucceeded,
			Action:       action,
			Publish:      publish(batchID),
		})
		batchesMu.Lock()
		batches[batchID] = b
		batchesMu.Unlock()

		// Detached context: the batch outlives the request so progress continues
		// and is observable after the response returns (FR-038).
		go b.Run(context.Background())

		writeJSON(w, http.StatusOK, map[string]any{
			"batchId": batchID, "pgId": pgID, "state": string(b.State()), "hosts": b.Snapshot(),
		})
	})

	// GET /api/batch/{id}: current batch state + per-host snapshot (refresh-safe:
	// the SSE stream replays recent events too, FR-038/039).
	mux.HandleFunc("GET /api/batch/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		batchesMu.Lock()
		b, ok := batches[id]
		batchesMu.Unlock()
		if !ok {
			http.Error(w, "batch not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "state": string(b.State()), "hosts": b.Snapshot()})
	})

	// POST /api/batch/{id}/retry: re-run one host's failed enrollment phase
	// (idempotent — no reinstall, no PG recreate; FR-031/032).
	mux.HandleFunc("POST /api/batch/{id}/retry", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		batchesMu.Lock()
		b, ok := batches[id]
		batchesMu.Unlock()
		if !ok {
			http.Error(w, "batch not found", http.StatusNotFound)
			return
		}
		var body struct {
			HostID string `json:"hostId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if err := b.Retry(context.Background(), body.HostID); err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "state": string(b.State()), "hosts": b.Snapshot()})
	})
}
