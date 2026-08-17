package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Coku2015/agentbridge/internal/windowsdeploy"
)

func TestWindowsPreflightSuccessLogIsHostCorrelated(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	logWindowsPreflightResult(context.Background(), logger, "10.10.1.53", "unused-secret", windowsdeploy.Result{
		Status:           windowsdeploy.StatusReady,
		Authentication:   "SPNEGO (NTLMv2 for local/workgroup account)",
		AdminShare:       "available",
		TaskSchedulerRPC: "available",
		RPCAuthLevel:     "packet_privacy",
		ServiceReady:     true,
	}, 2750*time.Millisecond)

	record := decodeWindowsLogRecord(t, output.Bytes())
	assertWindowsLogField(t, record, "msg", "windows remote install preflight completed")
	assertWindowsLogField(t, record, "host", "10.10.1.53")
	assertWindowsLogField(t, record, "status", windowsdeploy.StatusReady)
	assertWindowsLogField(t, record, "service_ready", true)
	assertWindowsLogField(t, record, "duration_ms", float64(2750))
	if _, exists := record["technical_detail"]; exists {
		t.Fatal("successful preflight log must not include technical failure detail")
	}
}

func TestWindowsInstallSuccessLogIncludesCampaignAndReadiness(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	logWindowsInstallResult(context.Background(), logger, "win2016.example.test", "campaign-123", "unused-secret", windowsdeploy.Result{
		Status:           windowsdeploy.StatusInstalled,
		Authentication:   "SPNEGO (Kerberos preferred, NTLMv2 fallback)",
		AdminShare:       "available",
		TaskSchedulerRPC: "available",
		ServiceReady:     true,
	}, 12*time.Second)

	record := decodeWindowsLogRecord(t, output.Bytes())
	assertWindowsLogField(t, record, "msg", "windows deployment kit install completed")
	assertWindowsLogField(t, record, "host", "win2016.example.test")
	assertWindowsLogField(t, record, "campaign_id", "campaign-123")
	assertWindowsLogField(t, record, "service_ready", true)
	assertWindowsLogField(t, record, "duration_ms", float64(12000))
}

func TestWindowsFailureLogRedactsRequestPassword(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	password := "private-Windows-password"
	logWindowsPreflightResult(context.Background(), logger, "10.10.1.53", password, windowsdeploy.Result{
		Status:          windowsdeploy.StatusAuthFailed,
		ErrorKey:        "windows_authentication_failed",
		FailureStage:    "smb_authentication",
		Detail:          "Authentication failed for " + password,
		TechnicalDetail: "provider rejected password " + password,
	}, time.Second)

	raw := output.String()
	if strings.Contains(raw, password) {
		t.Fatalf("Windows password leaked into log: %s", raw)
	}
	record := decodeWindowsLogRecord(t, output.Bytes())
	assertWindowsLogField(t, record, "level", "WARN")
	assertWindowsLogField(t, record, "detail", "Authentication failed for [REDACTED]")
	assertWindowsLogField(t, record, "technical_detail", "provider rejected password [REDACTED]")
	if _, exists := record["username"]; exists {
		t.Fatal("Windows result logs must not contain usernames")
	}
}

func decodeWindowsLogRecord(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatalf("decode structured Windows log: %v\n%s", err, raw)
	}
	return record
}

func assertWindowsLogField(t *testing.T, record map[string]any, key string, want any) {
	t.Helper()
	if got := record[key]; got != want {
		t.Fatalf("log field %q = %#v, want %#v; record=%#v", key, got, want, record)
	}
}
