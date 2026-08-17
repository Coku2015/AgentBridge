package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

const manualDownloadTTL = 30 * time.Minute

type manualDownload struct {
	path        string
	filename    string
	downloadURL string
	expiresAt   time.Time
	platform    string
	sha256      string
}

// manualDownloadServer is deliberately separate from the management listener.
// The UI/API can remain bound to localhost while a short-lived, tokenized
// archive endpoint is reachable from the target Windows or Linux host on the LAN.
type manualDownloadServer struct {
	mu       sync.Mutex
	items    map[string]manualDownload
	listener net.Listener
	server   *http.Server
	log      *slog.Logger
}

func newManualDownloadServer(log *slog.Logger) *manualDownloadServer {
	return &manualDownloadServer{items: make(map[string]manualDownload), log: log}
}

func (s *manualDownloadServer) publish(path string) (string, time.Time, error) {
	return s.publishWithOptions(path, "linux", "")
}

func (s *manualDownloadServer) publishForPlatform(path, platform, digest string) (string, time.Time, error) {
	return s.publishWithOptions(path, platform, digest)
}

func (s *manualDownloadServer) publishWithOptions(path, platform, digest string) (string, time.Time, error) {
	if path == "" {
		return "", time.Time{}, fmt.Errorf("manual install: empty bundle path")
	}
	if _, err := os.Stat(path); err != nil {
		return "", time.Time{}, fmt.Errorf("manual install: bundle is unavailable: %w", err)
	}
	token, err := randomManualToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := time.Now().Add(manualDownloadTTL)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureStartedLocked(); err != nil {
		return "", time.Time{}, err
	}
	for key, item := range s.items {
		if time.Now().After(item.expiresAt) {
			delete(s.items, key)
		}
	}
	host := manualDownloadHost()
	baseURL := "http://" + net.JoinHostPort(host, fmt.Sprint(s.listener.Addr().(*net.TCPAddr).Port))
	downloadURL := baseURL + "/manual-install/download/" + token
	s.items[token] = manualDownload{
		path:        path,
		filename:    filepath.Base(path),
		downloadURL: downloadURL,
		expiresAt:   expiresAt,
		platform:    platform,
		sha256:      digest,
	}
	return baseURL + "/manual-install/bootstrap/" + token, expiresAt, nil
}

func (s *manualDownloadServer) ensureStartedLocked() error {
	if s.listener != nil {
		return nil
	}
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("manual install: open LAN download service: %w", err)
	}
	s.listener = listener
	s.server = &http.Server{
		Handler:           http.HandlerFunc(s.handleDownload),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed && s.log != nil {
			s.log.Warn("manual install download service stopped", "error", err)
		}
	}()
	return nil
}

func (s *manualDownloadServer) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	const (
		bootstrapPrefix = "/manual-install/bootstrap/"
		downloadPrefix  = "/manual-install/download/"
	)
	bootstrap := strings.HasPrefix(r.URL.Path, bootstrapPrefix)
	download := strings.HasPrefix(r.URL.Path, downloadPrefix)
	if !bootstrap && !download {
		http.NotFound(w, r)
		return
	}
	prefix := downloadPrefix
	if bootstrap {
		prefix = bootstrapPrefix
	}
	token := strings.TrimPrefix(r.URL.Path, prefix)
	if token == "" || strings.ContainsAny(token, "/\\") {
		http.NotFound(w, r)
		return
	}

	s.mu.Lock()
	item, ok := s.items[token]
	if ok && download {
		delete(s.items, token) // one download command consumes its token
	}
	s.mu.Unlock()
	if !ok || time.Now().After(item.expiresAt) {
		http.NotFound(w, r)
		return
	}
	if bootstrap {
		if item.platform == "windows" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = io.WriteString(w, manualWindowsBootstrapScript(item.downloadURL, item.sha256))
			return
		}
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, manualBootstrapScript(item.downloadURL))
		return
	}

	f, err := os.Open(item.path)
	if err != nil {
		http.Error(w, "bundle unavailable", http.StatusGone)
		return
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		http.Error(w, "bundle unavailable", http.StatusGone)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", item.filename))
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, item.filename, stat.ModTime(), f)
}

// manualBootstrapScript hides download, extraction and installer orchestration
// behind the short command shown in the UI. It contains no credential and its
// archive URL is short-lived and one-shot.
func manualBootstrapScript(downloadURL string) string {
	return fmt.Sprintf(`#!/bin/sh
set -eu
work_dir=$(mktemp -d /tmp/agentbridge.XXXXXX)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
curl -fsSL %s -o "$work_dir/bundle.tar.gz"
tar -xzf "$work_dir/bundle.tar.gz" -C "$work_dir"
cd "$work_dir"
if ./install.sh >"$work_dir/install.log" 2>&1; then
  printf 'AgentBridge installation completed.\n'
else
  cat "$work_dir/install.log" >&2
  exit 1
fi
`, shellQuote(downloadURL))
}

// manualWindowsBootstrapScript is served through a short-lived token. It
// verifies the kit digest, asks for elevation when needed, and invokes the
// official batch installer in an administrator context.
func manualWindowsBootstrapScript(downloadURL, digest string) string {
	body := "$ErrorActionPreference = 'Stop'\n" +
		"$expectedSHA = '" + strings.ToUpper(digest) + "'\n" +
		"$download = '" + strings.ReplaceAll(downloadURL, "'", "''") + "'\n" +
		"function Get-AgentBridgeSHA256([string]$path) { $stream = [System.IO.File]::OpenRead($path); $sha = [System.Security.Cryptography.SHA256]::Create(); try { return ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '') } finally { $sha.Dispose(); $stream.Dispose() } }\n" +
		"$root = Join-Path $env:TEMP ('AgentBridge-' + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Force $root | Out-Null\n" +
		"$zip = Join-Path $root 'deployment-kit.zip'; Invoke-WebRequest -UseBasicParsing -Uri $download -OutFile $zip\n" +
		"if ((Get-AgentBridgeSHA256 $zip) -ine $expectedSHA) { throw 'Deployment Kit SHA-256 verification failed' }\n" +
		"Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $root)\n" +
		"$bat = Get-ChildItem -LiteralPath $root -Filter 'InstallDeploymentKit.bat' -Recurse | Select-Object -First 1; if (-not $bat) { throw 'InstallDeploymentKit.bat not found' }\n" +
		"Push-Location $bat.DirectoryName; & cmd.exe /c $bat.FullName; Pop-Location; if ($LASTEXITCODE -ne 0) { throw ('InstallDeploymentKit.bat exit code ' + $LASTEXITCODE) }\n" +
		"$svc = Get-Service -Name VeeamDeploySvc -ErrorAction SilentlyContinue; if (-not $svc) { throw 'VeeamDeploySvc was not found after installation' }\n" +
		"Remove-Item -LiteralPath $root -Recurse -Force\n"
	encoded := base64.StdEncoding.EncodeToString(utf16LE(body))
	return "$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)\n" +
		"if (-not $isAdmin) { Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand','" + encoded + "') | Out-Null; return }\n" + body
}

func utf16LE(value string) []byte {
	codes := utf16.Encode([]rune(value))
	out := make([]byte, len(codes)*2)
	for i, code := range codes {
		out[i*2] = byte(code)
		out[i*2+1] = byte(code >> 8)
	}
	return out
}

func (s *manualDownloadServer) close() error {
	s.mu.Lock()
	server := s.server
	s.mu.Unlock()
	if server == nil {
		return nil
	}
	ctx, cancel := contextWithManualShutdown()
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		if closeErr := server.Close(); closeErr != nil {
			return fmt.Errorf("manual install: shutdown: %w", errors.Join(err, closeErr))
		}
	}
	return nil
}

// contextWithManualShutdown keeps this small helper local to the delivery
// server and makes its shutdown deadline explicit.
func contextWithManualShutdown() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

func randomManualToken() (string, error) {
	b := make([]byte, 18)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("manual install: create download token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func manualDownloadHost() string {
	var candidates []string
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.To4() == nil {
					continue
				}
				candidates = append(candidates, ip.String())
			}
		}
	}
	sort.Strings(candidates)
	if len(candidates) > 0 {
		return candidates[0]
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		return host
	}
	return "127.0.0.1"
}
