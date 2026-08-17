package httpserver

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeploymentKitProbeRequiresCurrentCampaign(t *testing.T) {
	mux := http.NewServeMux()
	registerDeploymentKitProbe(mux, slog.Default(), t.TempDir())
	req := httptest.NewRequest(http.MethodPost, "/api/deployment-kit/probe", strings.NewReader(`{"host":"127.0.0.1","platform":"windows","campaignId":"missing"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "no active Deployment Kit campaign") {
		t.Fatal("campaign implementation detail must not be exposed to the UI")
	}
}

func TestDeploymentKitProbeRejectsCallerPortAndInvalidPlatform(t *testing.T) {
	mux := http.NewServeMux()
	registerDeploymentKitProbe(mux, slog.Default(), t.TempDir())
	req := httptest.NewRequest(http.MethodPost, "/api/deployment-kit/probe", strings.NewReader(`{"host":"127.0.0.1","platform":"darwin","campaignId":"x","port":1}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"port"`) {
		t.Fatal("probe response must not expose or accept a caller-selected port")
	}
}
