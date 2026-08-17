package vbr

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Coku2015/agentbridge/internal/security"
)

// newFakeVBR starts a fake VBR REST server. It answers the PG-create session
// poll with the 1.3-rev2 SessionModel and records the raw create request so the
// wire contract can be asserted against the OpenAPI spec (the 400-regression
// guard: never again send invented keys like containerType/connectionMode).
func newFakeVBR(t *testing.T) (*httptest.Server, *map[string]any) {
	t.Helper()
	var createBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/api/v1/agents/protectionGroups"):
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				t.Errorf("decode create body: %v", err)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"session-1"}`))
		case strings.Contains(r.URL.Path, "/api/v1/automation/sessions/"):
			t.Errorf("Infrastructure session was queried through Automation endpoint: %s", r.URL.Path)
			http.Error(w, "wrong session endpoint", http.StatusInternalServerError)
		case strings.Contains(r.URL.Path, "/api/v1/sessions/"):
			_, _ = w.Write([]byte(`{"state":"Stopped","result":"Success","progressPercent":100}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &createBody
}

// fakeConnected returns an adapter pointed at srv with the connection
// pre-established (plain HTTP test transport + dummy token).
func fakeConnected(srv *httptest.Server) *RESTAdapter {
	a := NewRESTAdapter(Credentials{Password: "pw"}, security.NewScrubber(), nil)
	a.base = srv.URL
	a.httpc = srv.Client()
	a.accessToken = "test-token"
	return a
}

type orderedReadCloser struct {
	*bytes.Reader
	events *[]string
}

func (r *orderedReadCloser) Close() error {
	*r.events = append(*r.events, "body-close")
	return nil
}

func TestCleanupReadCloserPreservesEOFAndClosesBeforeCleanup(t *testing.T) {
	events := []string{}
	r := &cleanupReadCloser{
		body: &orderedReadCloser{Reader: bytes.NewReader([]byte("complete archive")), events: &events},
		cleanup: func() {
			events = append(events, "cleanup")
		},
	}

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read complete archive: %v", err)
	}
	if string(got) != "complete archive" {
		t.Fatalf("archive = %q", got)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := strings.Join(events, ","); got != "body-close,cleanup" {
		t.Fatalf("events = %q, want body-close,cleanup exactly once", got)
	}
}

func TestTemporaryProtectionGroupMissing(t *testing.T) {
	if !temporaryProtectionGroupMissing(errors.New("vbr DELETE: 404 Not Found")) {
		t.Fatal("404 should make a cleanup retry idempotently complete")
	}
	if temporaryProtectionGroupMissing(errors.New("context deadline exceeded")) {
		t.Fatal("timeout must remain retryable")
	}
}

// TestCreateProtectionGroupWireContract pins the exact POST body to the
// IndividualComputersProtectionGroupSpec shape from the 1.3-rev2 OpenAPI.
func TestCreateProtectionGroupWireContract(t *testing.T) {
	srv, bodyPtr := newFakeVBR(t)
	a := fakeConnected(srv)

	ref, err := a.CreateProtectionGroup(context.Background(), ProtectionGroupSpec{
		Name:      "prod-linux",
		Computers: []IndividualComputer{{HostName: "web01.lab.local"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ref.ID != "session-1" {
		t.Fatalf("session id = %q, want session-1", ref.ID)
	}

	body := *bodyPtr
	if body["name"] != "prod-linux" {
		t.Fatalf("name = %v", body["name"])
	}
	if body["description"] != "Created by AgentBridge" {
		t.Fatalf("description = %v, want the required default", body["description"])
	}
	if body["type"] != "IndividualComputers" {
		t.Fatalf("type = %v, want IndividualComputers", body["type"])
	}
	computers, ok := body["computers"].([]any)
	if !ok || len(computers) != 1 {
		t.Fatalf("computers = %#v", body["computers"])
	}
	c := computers[0].(map[string]any)
	if c["hostName"] != "web01.lab.local" || c["connectionType"] != "Certificate" {
		t.Fatalf("computer = %#v", c)
	}
	opts, ok := body["options"].(map[string]any)
	if !ok || opts["installBackupAgent"] != true {
		t.Fatalf("options = %#v", body["options"])
	}

	// No invented keys anywhere — those are what produced VBR 400s before.
	raw, _ := json.Marshal(body)
	for _, banned := range []string{"containerType", "connectionMode", "ContainerType", "ConnectionMode"} {
		if strings.Contains(string(raw), banned) {
			t.Fatalf("body contains invented key %q: %s", banned, raw)
		}
	}
}

// TestGetSessionDecodesSessionModel verifies the poll decodes the real field
// names (state/result/progressPercent — not `percent`).
func TestGetSessionDecodesSessionModel(t *testing.T) {
	srv, _ := newFakeVBR(t)
	a := fakeConnected(srv)

	s, err := a.GetSession(context.Background(), "session-1")
	if err != nil {
		t.Fatal(err)
	}
	if s.State != "Stopped" || s.Result != "Success" || s.Progress != 100 {
		t.Fatalf("session = %+v, want {Stopped Success 100}", s)
	}
}

func TestGetSessionDecodesSessionResultModel(t *testing.T) {
	const vbrMessage = "testlab Error: System reboot is required to continue installation"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"state":"Stopped","result":{"result":"Failed","message":"` + vbrMessage + `","isCanceled":false},"progressPercent":100}`))
	}))
	defer srv.Close()

	s, err := fakeConnected(srv).GetSession(context.Background(), "session-1")
	if err != nil {
		t.Fatal(err)
	}
	if s.State != "Stopped" || s.Result != "Failed" || s.Message != vbrMessage || s.Progress != 100 {
		t.Fatalf("session = %+v, want VBR failure message preserved", s)
	}
}

func TestGetSessionMapsFailedChildTaskLogsToHost(t *testing.T) {
	const vbrMessage = "testlab Error: System reboot is required to continue installation"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/sessions/session-1":
			_, _ = w.Write([]byte(`{"state":"Stopped","result":{"result":"Failed","message":"Rescan failed, check session log for details."},"progressPercent":100}`))
		case "/api/v1/sessions/session-1/taskSessions":
			_, _ = w.Write([]byte(`{"data":[{"id":"task-1","name":"10.10.1.22","result":{"result":"Failed","message":"Failed"}}]}`))
		case "/api/v1/taskSessions/task-1/logs":
			if r.URL.Query().Get("statusFilter") != "Failed" {
				t.Fatalf("statusFilter = %q", r.URL.Query().Get("statusFilter"))
			}
			_, _ = w.Write([]byte(`{"totalRecords":2,"records":[` +
				`{"status":"Failed","title":"Processing finished with errors at 8/16/2026 8:49:48 PM","description":""},` +
				`{"status":"Failed","title":"` + vbrMessage + `","description":""}` +
				`]}`))
		case "/api/v1/sessions/session-1/logs":
			t.Fatal("parent logs must not be used when child task logs contain the error")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	s, err := fakeConnected(srv).GetSession(context.Background(), "session-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Failures) != 1 || s.Failures[0].Host != "10.10.1.22" || s.Failures[0].Message != vbrMessage {
		t.Fatalf("failures = %#v", s.Failures)
	}
	if s.Message != vbrMessage {
		t.Fatalf("message = %q", s.Message)
	}
}

func TestGetDiscoveredEntitiesDecodesVBRModel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/v1/agents/protectionGroups/pg-1/discoveredEntities" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{
			"data":[{
				"state":"Online",
				"agentStatus":"Installed",
				"agentVersion":"13.1.1.4",
				"lastConnected":"2026-08-16T00:01:54.120+08:00",
				"name":"centos7"
			}],
			"pagination":{"total":1,"count":1,"skip":0,"limit":200}
		}`))
	}))
	defer srv.Close()

	entities, err := fakeConnected(srv).GetDiscoveredEntities(context.Background(), "pg-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(entities) != 1 {
		t.Fatalf("entities = %+v", entities)
	}
	got := entities[0]
	if got.Host != "centos7" || !got.Online || got.AgentStatus != "Installed" || got.AgentVersion != "13.1.1.4" || got.LastConnected != "2026-08-16T00:01:54.120+08:00" {
		t.Fatalf("entity = %+v", got)
	}
}

func TestServerInfoReadsVersionHostAndServerClock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/serverInfo":
			_, _ = w.Write([]byte(`{"vbrId":"vbr-1","name":"vbr01.example.test","buildVersion":"13.0.0.4883","patches":["P20250715"]}`))
		case "/api/v1/serverTime":
			_, _ = w.Write([]byte(`{"serverTime":"2026-08-15T18:31:50.7300443+08:00","timeZone":"(UTC+08:00) Beijing","ianaTimeZoneId":"Asia/Shanghai"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	info, err := fakeConnected(srv).ServerInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.ProductVersion != "13.0.0.4883" || info.Host != "vbr01.example.test" || info.VBRID != "vbr-1" || len(info.Patches) != 1 || info.TimeZone == "" || info.IANAZone != "Asia/Shanghai" || info.ServerTime == nil {
		t.Fatalf("server info = %+v", info)
	}
	if info.APIRevision != APIRevisionBaseline {
		t.Fatalf("adapter revision = %q, want internal baseline", info.APIRevision)
	}
}

func TestDownloadAgentPackagesUsesTemporaryPreInstalledGroup(t *testing.T) {
	var createBody map[string]any
	var downloadBody map[string]any
	deleted := make(chan struct{}, 1)

	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	for name, data := range map[string]string{
		"protection-group.xml": "temporary metadata",
		"README.txt":           "temporary readme",
		"veeamagent.rpm":       "rpm payload",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(data))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/agents/protectionGroups":
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				t.Errorf("decode create body: %v", err)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"create-pg-session"}`))
		case strings.Contains(r.URL.Path, "/api/v1/automation/sessions/"):
			t.Errorf("Infrastructure session was queried through Automation endpoint: %s", r.URL.Path)
			http.Error(w, "wrong session endpoint", http.StatusInternalServerError)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/sessions/create-pg-session":
			_, _ = w.Write([]byte(`{"state":"Stopped","result":{"result":"Success","message":"","isCanceled":false},"progressPercent":100}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/agents/protectionGroups":
			_, _ = w.Write([]byte(`{"data":[{"id":"pg-temp-1","name":"` + createBody["name"].(string) + `"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/agents/protectionGroups/pg-temp-1/packages":
			if err := json.NewDecoder(r.Body).Decode(&downloadBody); err != nil {
				t.Errorf("decode package body: %v", err)
			}
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(archive.Bytes())
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/agents/protectionGroups/pg-temp-1":
			deleted <- struct{}{}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"delete-pg-session"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/sessions/delete-pg-session":
			_, _ = w.Write([]byte(`{"state":"Stopped","result":"Success","progressPercent":100}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a := fakeConnected(srv)
	body, err := a.DownloadAgentPackages(context.Background(), PackageRequest{
		PackageNames: []string{"Ubuntu 24.04 x64 - 13.0.0.1"},
		Format:       "Tar",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("downloaded archive is empty")
	}
	select {
	case <-deleted:
	case <-time.After(2 * time.Second):
		t.Fatal("temporary protection group was not cleaned up in the background")
	}
	if createBody["type"] != "PreInstalledAgents" {
		t.Fatalf("create body = %#v", createBody)
	}
	if downloadBody["format"] != "Tar" {
		t.Fatalf("download format = %#v", downloadBody["format"])
	}
	linux, ok := downloadBody["linuxPackages"].(map[string]any)
	if !ok || linux["include"] != true {
		t.Fatalf("linux package settings = %#v", downloadBody["linuxPackages"])
	}
	if names, ok := linux["packageNames"].([]any); !ok || len(names) != 1 || names[0] != "Ubuntu 24.04 x64 - 13.0.0.1" {
		t.Fatalf("package names = %#v", linux["packageNames"])
	}
}
