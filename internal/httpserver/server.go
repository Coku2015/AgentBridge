package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Coku2015/agentbridge/internal/logging"
	"github.com/Coku2015/agentbridge/internal/security"
)

// Options configures the embedded HTTP server (section 7.2).
type Options struct {
	// Listen defaults to 127.0.0.1:8787 in localhost mode. Any non-loopback
	// value requires TLSCert, TLSKey and AdminTokenFile (AB-FR-005).
	Listen string

	// DataDir holds jobs, cache, campaigns and logs (section 16.3).
	DataDir string

	// TLSCert / TLSKey are required for a non-loopback listener.
	TLSCert string
	TLSKey  string

	// AdminTokenFile points to a file whose contents become the admin bearer
	// token for server mode.
	AdminTokenFile string

	// NoBrowser suppresses the automatic browser open in localhost mode.
	NoBrowser bool

	// StatusWriter receives the concise human-readable startup banner. Diagnostic
	// logs are always written to DataDir/logs/agentbridge.log instead.
	StatusWriter io.Writer

	// ProductVersion is displayed in the startup banner when supplied by the
	// CLI build. It does not affect server behavior.
	ProductVersion string
}

// Serve runs the embedded Web UI and HTTP API until ctx is cancelled.
//
// Localhost mode (default) binds 127.0.0.1 and issues an ephemeral session
// token. Remote mode is REJECTED unless TLS + admin authentication are fully
// configured (AB-FR-003, AB-FR-005, FR-041).
func Serve(ctx context.Context, opts Options) (retErr error) {
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:8787"
	}
	if opts.DataDir == "" {
		opts.DataDir = "data" // local runtime dir (cache + campaigns); never holds secrets
	}
	remote := !isLoopback(opts.Listen)
	if remote && (opts.TLSCert == "" || opts.TLSKey == "" || opts.AdminTokenFile == "") {
		return errors.New("remote --listen requires --tls-cert, --tls-key and --admin-token-file")
	}

	logger, scrubber, adminToken, sessionToken, logFile, err := bootstrap(opts, remote)
	if err != nil {
		return err
	}
	defer logFile.Close()
	bus := NewBus(256)
	manualDownloads := newManualDownloadServer(logger)
	cleanupOnExit := false
	defer func() {
		// The LAN bundle endpoint must release every open file before its backing
		// bundle directory is cleared.
		if err := manualDownloads.close(); err != nil {
			logger.Warn("manual install download service cleanup failed", "error", err)
			retErr = errors.Join(retErr, err)
		}
		if cleanupOnExit {
			logger.Info("runtime artifact cleanup started", "data_dir", opts.DataDir, "directories", []string{"bundles", "packages", "kit"})
			if err := cleanupRuntimeArtifacts(opts.DataDir); err != nil {
				logger.Error("runtime artifact cleanup failed", "data_dir", opts.DataDir, "error", err)
				retErr = errors.Join(retErr, err)
			} else {
				logger.Info("runtime artifact cleanup completed", "data_dir", opts.DataDir)
			}
		}
	}()

	mux := http.NewServeMux()
	registerAPI(mux, logger, scrubber, bus, remote, adminToken, sessionToken, opts.ProductVersion, opts.DataDir, manualDownloads)
	if err := registerUI(mux); err != nil {
		return err
	}

	listener, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", opts.Listen, err)
	}
	defer listener.Close()

	srv := &http.Server{
		Addr:              opts.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("agentbridge serving", "listen", listener.Addr().String(), "remote", remote)
		if remote {
			serverErr <- srv.ServeTLS(listener, opts.TLSCert, opts.TLSKey)
		} else {
			serverErr <- srv.Serve(listener)
		}
	}()

	primaryURL, alternativeURL := accessURLs(listener.Addr().String(), remote)
	browserOpened := false
	if !remote && !opts.NoBrowser {
		if err := launchBrowser(primaryURL); err != nil {
			logger.Warn("default browser could not be opened", "url", primaryURL, "error", err)
		} else {
			browserOpened = true
		}
	}
	writeStartupStatus(opts.StatusWriter, opts.ProductVersion, primaryURL, alternativeURL, browserOpened)

	select {
	case <-ctx.Done():
		cleanupOnExit = true
	case err := <-serverErr:
		return err
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		// SSE or a slow client may outlive the graceful deadline. Force-close it
		// before the deferred artifact cleanup removes served files.
		logger.Warn("http shutdown deadline reached; forcing close", "error", err)
		if closeErr := srv.Close(); closeErr != nil {
			return errors.Join(err, closeErr)
		}
	}
	return nil
}

func writeStartupStatus(w io.Writer, version, primaryURL, alternativeURL string, browserOpened bool) {
	if w == nil {
		return
	}
	title := "AgentBridge"
	if strings.TrimSpace(version) != "" {
		title += " " + strings.TrimSpace(version)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, title)
	fmt.Fprintln(w, "Veeam Agent deployment for Windows and Linux hosts")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Web interface:")
	fmt.Fprintf(w, "  %s\n", primaryURL)
	if alternativeURL != "" {
		fmt.Fprintf(w, "  %s\n", alternativeURL)
	}
	fmt.Fprintln(w)
	if browserOpened {
		fmt.Fprintln(w, "The web interface has been opened in your default browser.")
	} else {
		fmt.Fprintln(w, "Open one of the addresses above in your browser.")
	}
	fmt.Fprintln(w, "Press Ctrl+C to stop AgentBridge.")
	fmt.Fprintln(w)
}

var runtimeArtifactDirs = []string{"bundles", "packages", "kit"}

// cleanupRuntimeArtifacts clears only process-owned, reproducible artifacts.
// Logs and every unrelated data-dir entry are deliberately preserved. Each
// managed directory is recreated empty so the next serve starts with the same
// protected directory permissions.
func cleanupRuntimeArtifacts(dataDir string) error {
	root, err := filepath.Abs(dataDir)
	if err != nil {
		return fmt.Errorf("resolve data directory: %w", err)
	}
	var cleanupErr error
	for _, name := range runtimeArtifactDirs {
		target := filepath.Join(root, name)
		rel, err := filepath.Rel(root, target)
		if err != nil || rel != name {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("refuse unsafe artifact path %q", target))
			continue
		}
		if err := os.RemoveAll(target); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("clear %s: %w", name, err))
			continue
		}
		if err := os.MkdirAll(target, 0o700); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("recreate %s: %w", name, err))
		}
	}
	return cleanupErr
}

// bootstrap prepares the scrubbing logger and resolves the admin token (remote)
// or mints a localhost session token. Secrets stay in memory only.
func bootstrap(opts Options, remote bool) (*slog.Logger, *security.Scrubber, string, string, *os.File, error) {
	scrubber := security.NewScrubber()
	logDir := filepath.Join(opts.DataDir, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return nil, nil, "", "", nil, fmt.Errorf("create log directory: %w", err)
	}
	logPath := filepath.Join(logDir, "agentbridge.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, "", "", nil, fmt.Errorf("open log file: %w", err)
	}
	logger := logging.New(scrubber, logFile)
	logger.Info("diagnostic logging enabled", "path", logPath)
	if remote {
		raw, err := os.ReadFile(opts.AdminTokenFile)
		if err != nil {
			_ = logFile.Close()
			return nil, nil, "", "", nil, err
		}
		return logger, scrubber, strings.TrimSpace(string(raw)), "", logFile, nil
	}
	tok, err := randomToken(32)
	if err != nil {
		_ = logFile.Close()
		return nil, nil, "", "", nil, err
	}
	return logger, scrubber, "", tok, logFile, nil
}

func registerAPI(mux *http.ServeMux, log *slog.Logger, scrubber *security.Scrubber, bus *Bus, remote bool, adminToken, sessionToken, productVersion, dataDir string, manualDownloads *manualDownloadServer) {
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	registerVersion(mux, remote, adminToken, productVersion)

	mux.HandleFunc("GET /api/session", func(w http.ResponseWriter, r *http.Request) {
		if remote && !validBearer(r, adminToken) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		resp := map[string]any{"remote": remote}
		if !remote {
			resp["token"] = sessionToken
		}
		writeJSON(w, http.StatusOK, resp)
	})

	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		if remote && !validBearer(r, adminToken) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sse := newSSEReceiver(w, r)
		sse.serve(bus)
	})

	registerVBR(mux, log, scrubber)
	registerInstall(mux, log, dataDir)
	registerWindowsInstall(mux, log, dataDir)
	registerDeploymentKitProbe(mux, log, dataDir)
	registerProbe(mux)
	registerPG(mux)
	registerPackages(mux, log, dataDir)
	registerBundle(mux, dataDir, manualDownloads)
	registerBatch(mux, bus)

	// Generic 404 for unknown /api routes keeps the contract explicit.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if remote && !validBearer(r, adminToken) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		http.NotFound(w, r)
	})
	log.Info("api routes registered", "remote", remote)
}

func registerVersion(mux *http.ServeMux, remote bool, adminToken, productVersion string) {
	version := strings.TrimSpace(productVersion)
	if version == "" {
		version = "dev"
	}
	mux.HandleFunc("GET /api/version", func(w http.ResponseWriter, r *http.Request) {
		if remote && !validBearer(r, adminToken) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"version": version})
	})
}

// sseReceiver writes Bus events to an SSE stream; it replays recent events first
// (refresh-safe, FR-038) then streams live updates until the client disconnects.
type sseReceiver struct {
	w  http.ResponseWriter
	r  *http.Request
	fl http.Flusher
}

func newSSEReceiver(w http.ResponseWriter, r *http.Request) *sseReceiver {
	return &sseReceiver{w: w, r: r, fl: w.(http.Flusher)}
}

func (s *sseReceiver) serve(bus *Bus) {
	s.w.Header().Set("Content-Type", "text/event-stream")
	s.w.Header().Set("Cache-Control", "no-cache")
	s.w.Header().Set("Connection", "keep-alive")
	s.w.WriteHeader(http.StatusOK)
	if s.fl != nil {
		s.fl.Flush()
	}
	for _, e := range bus.Recent() {
		s.write(e)
	}
	ch, cancel := bus.Subscribe()
	defer cancel()
	ctx := s.r.Context()
	for {
		select {
		case e, ok := <-ch:
			if !ok {
				return
			}
			s.write(e)
		case <-ctx.Done():
			return
		}
	}
}

func (s *sseReceiver) write(e Event) {
	raw, _ := json.Marshal(e)
	_, _ = s.w.Write([]byte("data: "))
	_, _ = s.w.Write(raw)
	_, _ = s.w.Write([]byte("\n\n"))
	if s.fl != nil {
		s.fl.Flush()
	}
}

// registerUI serves the embedded Vue build (SPA) under "/" with index.html
// fallback for client-side routing.
func registerUI(mux *http.ServeMux) error {
	sub, err := fs.Sub(dist, "web/dist")
	if err != nil {
		return err
	}
	fileServer := http.FileServer(http.FS(sub))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// SPA fallback: unknown non-file paths serve index.html.
		if _, err := fs.Stat(sub, strings.TrimPrefix(r.URL.Path, "/")); err != nil {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			fileServer.ServeHTTP(w, r2)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
	return nil
}

// validBearer checks an Authorization: Bearer <token> header in constant time.
func validBearer(r *http.Request, expected string) bool {
	if expected == "" {
		return false
	}
	got := r.Header.Get("Authorization")
	got = strings.TrimPrefix(got, "Bearer ")
	return subtleEqual(got, expected)
}

// subtleEqual compares two strings without short-circuiting.
func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func randomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// newDefaultLogger is retained for tests/diagnostics that want a plain logger.
func newDefaultLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	switch host {
	case "", "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}
