package httpserver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestManualDownloadIsTokenizedAndOneShot(t *testing.T) {
	bundle := t.TempDir() + "/bundle.tar.gz"
	if err := os.WriteFile(bundle, []byte("bundle-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := newManualDownloadServer(nil)
	defer d.close()
	url, _, err := d.publish(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapPath := strings.TrimPrefix(url, "http://")
	bootstrapPath = bootstrapPath[strings.IndexByte(bootstrapPath, '/'):] // discard the advertised host/port
	downloadPath := strings.Replace(bootstrapPath, "/bootstrap/", "/download/", 1)

	req := httptest.NewRequest(http.MethodGet, bootstrapPath, nil)
	w := httptest.NewRecorder()
	d.handleDownload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("bootstrap status = %d, want 200", w.Code)
	}
	bootstrap, err := io.ReadAll(w.Result().Body)
	if err != nil || !strings.Contains(string(bootstrap), "curl -fsSL") || !strings.Contains(string(bootstrap), "/manual-install/download/") {
		t.Fatalf("bootstrap body = %q, err=%v", bootstrap, err)
	}

	req = httptest.NewRequest(http.MethodGet, downloadPath, nil)
	w = httptest.NewRecorder()
	d.handleDownload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first download status = %d, want 200", w.Code)
	}
	body, err := io.ReadAll(w.Result().Body)
	if err != nil || string(body) != "bundle-bytes" {
		t.Fatalf("first download body = %q, err=%v", body, err)
	}

	req = httptest.NewRequest(http.MethodGet, downloadPath, nil)
	w = httptest.NewRecorder()
	d.handleDownload(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("second download status = %d, want 404", w.Code)
	}
}

func TestManualWindowsDownloadUsesHTTPAndKeepsDigestVerification(t *testing.T) {
	kit := t.TempDir() + "/deployment-kit.zip"
	if err := os.WriteFile(kit, []byte("kit-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	d := newManualDownloadServer(nil)
	defer d.close()
	url, _, err := d.publishForPlatform(kit, "windows", digest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(url, "http://") {
		t.Fatalf("Windows bootstrap URL = %q, want HTTP", url)
	}

	bootstrapPath := strings.TrimPrefix(url, "http://")
	bootstrapPath = bootstrapPath[strings.IndexByte(bootstrapPath, '/'):]
	req := httptest.NewRequest(http.MethodGet, bootstrapPath, nil)
	w := httptest.NewRecorder()
	d.handleDownload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("bootstrap status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, strings.ToUpper(digest)) || !strings.Contains(body, "Get-AgentBridgeSHA256") {
		t.Fatalf("Windows bootstrap does not verify the kit digest:\n%s", body)
	}
	for _, unwanted := range []string{"https://", "ServerCertificateValidationCallback", "expectedFingerprint"} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("Windows HTTP bootstrap contains %q:\n%s", unwanted, body)
		}
	}
}

func TestManualInstallCommandPullsAndInstalls(t *testing.T) {
	cmd := manualInstallCommand("http://10.0.0.5:4567/manual-install/bootstrap/token")
	want := "curl -fsSL 'http://10.0.0.5:4567/manual-install/bootstrap/token' | sudo bash"
	if cmd != want {
		t.Fatalf("command = %q, want %q", cmd, want)
	}
	for _, unwanted := range []string{"wget", "mktemp", "tar -xzf", "result.json"} {
		if strings.Contains(cmd, unwanted) {
			t.Fatalf("command exposes %q: %s", unwanted, cmd)
		}
	}
}

func TestManualWindowsInstallCommandIsOneLineHTTP(t *testing.T) {
	url := "http://10.0.0.5:4567/manual-install/bootstrap/token"
	cmd := manualWindowsInstallCommand(url)
	want := "Invoke-Expression ((Invoke-WebRequest -UseBasicParsing -Uri 'http://10.0.0.5:4567/manual-install/bootstrap/token').Content)"
	if cmd != want {
		t.Fatalf("Windows command = %q, want %q", cmd, want)
	}
	if strings.ContainsAny(cmd, "\r\n") {
		t.Fatalf("Windows command must stay on one line:\n%s", cmd)
	}
	for _, unwanted := range []string{"https://", "TlsFingerprint", "ServerCertificateValidationCallback", "ScriptBlock]::Create", "-Command", "powershell.exe", "AgentBridge-Install.ps1"} {
		if strings.Contains(cmd, unwanted) {
			t.Fatalf("Windows command contains unwanted wrapper %q:\n%s", unwanted, cmd)
		}
	}
}

func TestManualBootstrapScriptIsValidAndHumanFacing(t *testing.T) {
	script := manualBootstrapScript("http://10.0.0.5:4567/manual-install/download/token")
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bootstrap syntax invalid: %v\n%s", err, out)
	}
	for _, want := range []string{"curl -fsSL", "tar -xzf", "./install.sh", "AgentBridge installation completed."} {
		if !strings.Contains(script, want) {
			t.Fatalf("bootstrap missing %q", want)
		}
	}
	if strings.Contains(script, "result.json") {
		t.Fatal("bootstrap asks the operator to handle result.json")
	}
}

func TestManualWindowsBootstrapSupportsWindowsServer2012(t *testing.T) {
	script := manualWindowsBootstrapScript("http://10.0.0.5:4567/manual-install/download/token", strings.Repeat("a", 64))
	for _, want := range []string{"System.IO.Compression.ZipFile]::ExtractToDirectory", "System.Security.Cryptography.SHA256]::Create", "InstallDeploymentKit.bat"} {
		if !strings.Contains(script, want) {
			t.Fatalf("Windows bootstrap missing %q", want)
		}
	}
	for _, unsupported := range []string{"https://", "ServerCertificateValidationCallback", "Expand-Archive", "Get-FileHash"} {
		if strings.Contains(script, unsupported) {
			t.Fatalf("Windows bootstrap must support Windows Server 2012 and not contain %q", unsupported)
		}
	}
}
