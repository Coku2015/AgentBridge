package httpserver

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Coku2015/agentbridge/internal/security"
	"github.com/Coku2015/agentbridge/internal/vbr"
)

// resetActiveVBR clears package-level session state between tests.
func resetActiveVBR() {
	activeVBR.mu.Lock()
	activeVBR.adapter = nil
	activeVBR.caps = vbr.Capabilities{}
	activeVBR.server = vbr.ServerInfo{}
	activeVBR.mu.Unlock()
}

// TestCapabilityFlagMapping ensures the gate maps every supported capability name
// to its flag (red line 8: capability-driven UI must be exact).
func TestCapabilityFlagMapping(t *testing.T) {
	c := vbr.Capabilities{
		AgentPackages:      true,
		DeploymentKit:      true,
		ProtectionGroup:    true,
		Rescan:             true,
		Session:            true,
		DiscoveredEntities: true,
	}
	for _, name := range []string{"agentPackages", "deploymentKit", "protectionGroup", "rescan", "session", "discoveredEntities"} {
		if !capabilityEnabled(c, name) {
			t.Fatalf("capability %q should be enabled", name)
		}
	}
	if capabilityEnabled(c, "unknown") {
		t.Fatal("unknown capability must be disabled (no silent enable)")
	}
}

// TestRequireVBRNotConnected verifies the gate rejects requests when no VBR
// connection exists, with an actionable error — never a silent fallback.
func TestRequireVBRNotConnected(t *testing.T) {
	resetActiveVBR()
	w := httptest.NewRecorder()
	if _, _, ok := requireVBR(w, "agentPackages"); ok {
		t.Fatal("expected gate to block when not connected")
	}
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(w.Result().Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if _, has := body["actionable"]; !has {
		t.Fatal("error must be actionable")
	}
}

// TestRequireVBRCapabilityMissing verifies the gate blocks when the connected
// build lacks a capability (AB-FR-023: disable, do not silently fall back).
func TestRequireVBRCapabilityMissing(t *testing.T) {
	resetActiveVBR()
	defer resetActiveVBR()
	activeVBR.mu.Lock()
	activeVBR.adapter = &vbr.RESTAdapter{} // connected but inert; gate never calls it
	activeVBR.caps = vbr.Capabilities{AgentPackages: false}
	activeVBR.mu.Unlock()

	w := httptest.NewRecorder()
	if _, _, ok := requireVBR(w, "agentPackages"); ok {
		t.Fatal("expected gate to block when capability missing")
	}
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
}

// TestCapabilitiesEndpointNotConnected verifies GET /api/vbr/capabilities reports
// the disconnected state actionably (UI disables all paths up front).
func TestCapabilitiesEndpointNotConnected(t *testing.T) {
	resetActiveVBR()
	mux := http.NewServeMux()
	registerVBR(mux, slog.Default(), security.NewScrubber())

	req := httptest.NewRequest(http.MethodGet, "/api/vbr/capabilities", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
}
