package httpserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func doPost(t *testing.T, mux *http.ServeMux, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestMatchEndpointVendorSupported(t *testing.T) {
	mux := http.NewServeMux()
	registerProbe(mux)

	res := map[string]any{
		"schemaVersion": "1.0",
		"target":        map[string]any{"hostName": "node-1", "architecture": "x86_64"},
		"os":            map[string]any{"id": "rocky", "versionId": "8.6", "idLike": []string{"rhel"}},
		"glibc":         "2.28", "packageFormat": "rpm",
	}
	rec := doPost(t, mux, "/api/match", res)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var out matchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Level != "VendorSupported" {
		t.Fatalf("level = %s, want VendorSupported", out.Level)
	}
	if out.Recommendation.RecommendedPackageID != "rhel8-x86_64" {
		t.Fatalf("package = %s", out.Recommendation.RecommendedPackageID)
	}
}

func TestMatchOverrideEndpointIsUserSelected(t *testing.T) {
	mux := http.NewServeMux()
	registerProbe(mux)

	rec := doPost(t, mux, "/api/match/override", map[string]any{
		"packageId": "rhel8-x86_64", "reason": "lab host", "user": "ops",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var out matchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Level != "UserSelected" {
		t.Fatalf("level = %s, want UserSelected", out.Level)
	}
	if out.Recommendation.RecommendedPackageID != "rhel8-x86_64" {
		t.Fatalf("package = %s", out.Recommendation.RecommendedPackageID)
	}
}

func TestMatchOverrideRequiresPackageID(t *testing.T) {
	mux := http.NewServeMux()
	registerProbe(mux)
	rec := doPost(t, mux, "/api/match/override", map[string]any{"user": "ops"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestProbeImportEndpointSchemaMismatch(t *testing.T) {
	mux := http.NewServeMux()
	registerProbe(mux)
	rec := doPost(t, mux, "/api/probe/import", map[string]any{
		"result": map[string]any{"schemaVersion": "9.9"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
