package httpserver

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVersionEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	registerVersion(mux, false, "", "v0.1.0")

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/version", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if strings.TrimSpace(recorder.Body.String()) != `{"version":"v0.1.0"}` {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

func TestCleanupRuntimeArtifactsPreservesLogsAndOtherData(t *testing.T) {
	root := t.TempDir()
	for _, dir := range runtimeArtifactDirs {
		path := filepath.Join(root, dir, "nested")
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "artifact.bin"), []byte(dir), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{
		filepath.Join(root, "logs", "agentbridge.log"),
		filepath.Join(root, "jobs", "journal.json"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := cleanupRuntimeArtifacts(root); err != nil {
		t.Fatal(err)
	}
	for _, dir := range runtimeArtifactDirs {
		assertEmptyDir(t, filepath.Join(root, dir))
	}
	for _, path := range []string{
		filepath.Join(root, "logs", "agentbridge.log"),
		filepath.Join(root, "jobs", "journal.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("preserved file %s: %v", path, err)
		}
	}
}

func TestServeContextCancellationCleansRuntimeArtifacts(t *testing.T) {
	root := t.TempDir()
	for _, dir := range runtimeArtifactDirs {
		path := filepath.Join(root, dir)
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "stale.bin"), []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	var status bytes.Buffer
	go func() {
		errCh <- Serve(ctx, Options{Listen: "127.0.0.1:0", DataDir: root, NoBrowser: true, StatusWriter: &status})
	}()

	logPath := filepath.Join(root, "logs", "agentbridge.log")
	deadline := time.Now().Add(3 * time.Second)
	for {
		raw, _ := os.ReadFile(logPath)
		if strings.Contains(string(raw), "agentbridge serving") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start; log=%s", raw)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(status.String(), "\nAgentBridge\n") ||
		!strings.Contains(status.String(), "Veeam Agent deployment for Windows and Linux hosts") ||
		!strings.Contains(status.String(), "\nWeb interface:\n  http://127.0.0.1:") ||
		!strings.Contains(status.String(), "\n  http://localhost:") ||
		!strings.Contains(status.String(), "Open one of the addresses above in your browser.") ||
		!strings.HasSuffix(status.String(), "Press Ctrl+C to stop AgentBridge.\n\n") {
		t.Fatalf("startup status = %q", status.String())
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Serve after cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop after cancellation")
	}

	for _, dir := range runtimeArtifactDirs {
		assertEmptyDir(t, filepath.Join(root, dir))
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("log must be preserved: %v", err)
	}
	if !strings.Contains(string(raw), "runtime artifact cleanup completed") {
		t.Fatalf("cleanup completion was not logged: %s", raw)
	}
}

func TestServeOpensDefaultBrowser(t *testing.T) {
	original := launchBrowser
	defer func() { launchBrowser = original }()

	opened := make(chan string, 1)
	launchBrowser = func(rawURL string) error {
		opened <- rawURL
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	root := t.TempDir()
	go func() {
		errCh <- Serve(ctx, Options{
			Listen:       "127.0.0.1:0",
			DataDir:      root,
			StatusWriter: &bytes.Buffer{},
		})
	}()

	select {
	case rawURL := <-opened:
		if !strings.HasPrefix(rawURL, "http://127.0.0.1:") || !strings.HasSuffix(rawURL, "/") {
			t.Fatalf("opened URL = %q", rawURL)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("default browser was not opened")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Serve after cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop after cancellation")
	}
}

func assertEmptyDir(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(entries) != 0 {
		t.Fatalf("%s is not empty: %v", path, entries)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("%s permissions = %o, want 700", path, info.Mode().Perm())
	}
}
