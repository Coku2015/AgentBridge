package windowsdeploy

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
	"time"
)

// TestLiveWindowsPreflight is an opt-in integration test for a real Windows
// target. It is skipped unless all three environment variables are supplied;
// credentials are never embedded in the repository or printed by the test.
func TestLiveWindowsPreflight(t *testing.T) {
	host, username, password := liveWindowsCredentials(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	result := (Client{Timeout: 75 * time.Second}).Preflight(ctx, Request{
		Host: host, Username: username, Password: password,
	})
	t.Logf("status=%s serviceReady=%v error=%s stage=%s code=%s field=%s value=%s", result.Status, result.ServiceReady, result.ErrorKey, result.FailureStage, result.ErrorCode, result.ErrorField, result.ErrorValue)
	if result.Status != StatusReady {
		t.Fatalf("live preflight failed: detail=%s technical=%s", result.Detail, result.TechnicalDetail)
	}
	if os.Getenv("AGENTBRIDGE_TEST_WINDOWS_EXPECT_SERVICE_READY") == "1" && !result.ServiceReady {
		ready, err := (Client{Timeout: 75 * time.Second}).deploymentServiceReady(ctx, host, Request{
			Host: host, Username: username, Password: password,
		})
		t.Fatalf("live preflight succeeded but VeeamDeploySvc and port 6160 were not reported ready: ready=%v err=%v", ready, err)
	}
}

// TestLiveWindowsInstall performs the complete SMB upload, SYSTEM scheduled
// task execution and VeeamDeploySvc verification against an explicitly opted-in
// target. The kit path and digest must also be supplied by the caller.
func TestLiveWindowsInstall(t *testing.T) {
	host, username, password := liveWindowsCredentials(t)
	kitPath := os.Getenv("AGENTBRIDGE_TEST_WINDOWS_KIT_PATH")
	kitSHA256 := os.Getenv("AGENTBRIDGE_TEST_WINDOWS_KIT_SHA256")
	if kitPath == "" || kitSHA256 == "" {
		t.Skip("set AGENTBRIDGE_TEST_WINDOWS_KIT_PATH and AGENTBRIDGE_TEST_WINDOWS_KIT_SHA256")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	result := (Client{Timeout: 2 * time.Minute}).Install(ctx, Request{
		Host: host, Username: username, Password: password,
		KitPath: kitPath, KitSHA256: kitSHA256,
	})
	t.Logf("status=%s serviceReady=%v error=%s stage=%s code=%s field=%s value=%s", result.Status, result.ServiceReady, result.ErrorKey, result.FailureStage, result.ErrorCode, result.ErrorField, result.ErrorValue)
	if result.Status != StatusInstalled || !result.ServiceReady {
		t.Fatalf("live install failed: detail=%s technical=%s", result.Detail, result.TechnicalDetail)
	}
}

func TestLiveWindowsLocalServiceVerification(t *testing.T) {
	host, username, password := liveWindowsCredentials(t)
	req := Request{Host: host, Username: username, Password: password}
	client := Client{Timeout: 75 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	session, share, conn, err := client.mount(ctx, &req)
	if err != nil {
		t.Fatalf("mount ADMIN$: %v", err)
	}
	defer conn.Close()
	defer session.Logoff()
	defer share.Umount()

	remoteDir := path.Join("Temp", "AgentBridge-ServiceProbe-"+randomID())
	if err := share.MkdirAll(remoteDir, 0700); err != nil {
		t.Fatalf("create service probe directory: %v", err)
	}
	defer share.RemoveAll(remoteDir)
	taskName := "AgentBridge-ServiceProbe-" + randomID()
	resultName := path.Join(remoteDir, "result.json")
	scriptName := path.Join(remoteDir, "verify.ps1")
	script := fmt.Sprintf("$ErrorActionPreference = 'Stop'\n$result = Join-Path $env:windir 'Temp\\%s\\result.json'\n$utf8NoBom = New-Object System.Text.UTF8Encoding($false)\ntry {\n  $svc = Get-Service -Name 'VeeamDeploySvc' -ErrorAction Stop\n  $json = @{ok=$true; serviceName=$svc.Name; serviceStatus=[string]$svc.Status} | ConvertTo-Json -Compress\n} catch {\n  $json = @{ok=$false; detail=$_.Exception.Message} | ConvertTo-Json -Compress\n}\n[System.IO.File]::WriteAllText($result, $json, $utf8NoBom)\ntry { schtasks.exe /Delete /TN '\\%s' /F | Out-Null } catch {}\n", path.Base(remoteDir), taskName)
	if err := share.WriteFile(scriptName, []byte(script), 0600); err != nil {
		t.Fatalf("upload service probe script: %v", err)
	}
	if err := client.runTask(ctx, host, req, taskName, fmt.Sprintf("C:\\Windows\\Temp\\%s\\verify.ps1", path.Base(remoteDir))); err != nil {
		t.Fatalf("run service probe task: %v", err)
	}

	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		data, err := share.ReadFile(resultName)
		if err == nil {
			marker, err := decodeInstallMarker(data)
			if err != nil {
				t.Fatalf("decode service probe result: %v", err)
			}
			t.Logf("service=%s status=%s", marker.ServiceName, marker.ServiceStatus)
			if !marker.OK || marker.ServiceName != "VeeamDeploySvc" || marker.ServiceStatus != "Running" {
				t.Fatalf("service probe failed: %#v", marker)
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
	t.Fatal("timed out waiting for service probe result")
}

// TestLiveWindowsCompatibilityInfo records the target OS and PowerShell
// versions through the same encrypted remote-task path used by installation.
// It helps maintain the representative Windows compatibility matrix without
// persisting credentials or inventory data.
func TestLiveWindowsCompatibilityInfo(t *testing.T) {
	host, username, password := liveWindowsCredentials(t)
	req := Request{Host: host, Username: username, Password: password}
	client := Client{Timeout: 75 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	session, share, conn, err := client.mount(ctx, &req)
	if err != nil {
		t.Fatalf("mount ADMIN$: %v", err)
	}
	defer conn.Close()
	defer session.Logoff()
	defer share.Umount()

	remoteDir := path.Join("Temp", "AgentBridge-CompatibilityProbe-"+randomID())
	if err := share.MkdirAll(remoteDir, 0700); err != nil {
		t.Fatalf("create compatibility probe directory: %v", err)
	}
	defer share.RemoveAll(remoteDir)
	taskName := "AgentBridge-CompatibilityProbe-" + randomID()
	resultName := path.Join(remoteDir, "result.json")
	scriptName := path.Join(remoteDir, "probe.ps1")
	script := fmt.Sprintf("$ErrorActionPreference = 'Stop'\n$result = Join-Path $env:windir 'Temp\\%s\\result.json'\n$utf8NoBom = New-Object System.Text.UTF8Encoding($false)\ntry { $os = Get-WmiObject -Class Win32_OperatingSystem; $detail = ([string]$os.Caption + ' | ' + [string]$os.Version + ' | PowerShell ' + $PSVersionTable.PSVersion.ToString()); $json = @{ok=$true; detail=$detail} | ConvertTo-Json -Compress } catch { $json = @{ok=$false; detail=$_.Exception.Message} | ConvertTo-Json -Compress }\n[System.IO.File]::WriteAllText($result, $json, $utf8NoBom)\ntry { schtasks.exe /Delete /TN '\\%s' /F | Out-Null } catch {}\n", path.Base(remoteDir), taskName)
	if err := share.WriteFile(scriptName, []byte(script), 0600); err != nil {
		t.Fatalf("upload compatibility probe script: %v", err)
	}
	if err := client.runTask(ctx, host, req, taskName, fmt.Sprintf("C:\\Windows\\Temp\\%s\\probe.ps1", path.Base(remoteDir))); err != nil {
		t.Fatalf("run compatibility probe task: %v", err)
	}

	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		data, err := share.ReadFile(resultName)
		if err == nil {
			marker, err := decodeInstallMarker(data)
			if err != nil {
				t.Fatalf("decode compatibility probe result: %v", err)
			}
			if !marker.OK {
				t.Fatalf("compatibility probe failed: %s", marker.Detail)
			}
			t.Log(marker.Detail)
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
	t.Fatal("timed out waiting for compatibility probe result")
}

// TestLiveWindowsDeploymentKitStaging reproduces the non-mutating portion of
// Windows installation: encrypted upload, SYSTEM-side SHA-256 verification,
// ZIP extraction and discovery of InstallDeploymentKit.bat. It deliberately
// does not execute the official installer.
func TestLiveWindowsDeploymentKitStaging(t *testing.T) {
	host, username, password := liveWindowsCredentials(t)
	kitPath := os.Getenv("AGENTBRIDGE_TEST_WINDOWS_KIT_PATH")
	kitSHA256 := os.Getenv("AGENTBRIDGE_TEST_WINDOWS_KIT_SHA256")
	if kitPath == "" || kitSHA256 == "" {
		t.Skip("set AGENTBRIDGE_TEST_WINDOWS_KIT_PATH and AGENTBRIDGE_TEST_WINDOWS_KIT_SHA256")
	}
	kit, err := readFile(kitPath)
	if err != nil {
		t.Fatalf("read deployment kit: %v", err)
	}

	req := Request{Host: host, Username: username, Password: password}
	client := Client{Timeout: 2 * time.Minute}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	session, share, conn, err := client.mount(ctx, &req)
	if err != nil {
		t.Fatalf("mount ADMIN$: %v", err)
	}
	defer conn.Close()
	defer session.Logoff()
	defer share.Umount()

	remoteDir := path.Join("Temp", "AgentBridge-StagingProbe-"+randomID())
	if err := share.MkdirAll(remoteDir, 0700); err != nil {
		t.Fatalf("create staging probe directory: %v", err)
	}
	defer share.RemoveAll(remoteDir)
	zipName := path.Join(remoteDir, "deployment-kit.zip")
	if err := share.WriteFile(zipName, kit, 0600); err != nil {
		t.Fatalf("upload deployment kit: %v", err)
	}

	taskName := "AgentBridge-StagingProbe-" + randomID()
	resultName := path.Join(remoteDir, "result.json")
	scriptName := path.Join(remoteDir, "probe.ps1")
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$root = Join-Path $env:windir 'Temp\%s'
$zip = Join-Path $root 'deployment-kit.zip'
$expanded = Join-Path $root 'expanded'
$result = Join-Path $root 'result.json'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
function Write-Result([bool]$ok, [string]$detail) {
  $json = @{ok=$ok; detail=$detail} | ConvertTo-Json -Compress
  [System.IO.File]::WriteAllText($result, $json, $utf8NoBom)
}
try {
  $stage = 'sha256'
  $stream = [System.IO.File]::OpenRead($zip)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try { $actual = ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '') } finally { $sha.Dispose(); $stream.Dispose() }
  if ($actual -ne '%s') { throw "SHA-256 mismatch: $actual" }
  $stage = 'extract'
  New-Item -ItemType Directory -Force $expanded | Out-Null
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $expanded)
  $stage = 'locate_installer'
  $bat = Get-ChildItem -LiteralPath $expanded -Filter 'InstallDeploymentKit.bat' -Recurse | Select-Object -First 1
  if (-not $bat) { throw 'InstallDeploymentKit.bat not found' }
  Write-Result $true ("completed; installer=" + $bat.FullName)
} catch {
  Write-Result $false ("stage=" + $stage + "; error=" + $_.Exception.Message)
}
try { schtasks.exe /Delete /TN '\%s' /F | Out-Null } catch {}
`, path.Base(remoteDir), strings.ToUpper(kitSHA256), taskName)
	if err := share.WriteFile(scriptName, []byte(script), 0600); err != nil {
		t.Fatalf("upload staging probe script: %v", err)
	}
	if err := client.runTask(ctx, host, req, taskName, fmt.Sprintf("C:\\Windows\\Temp\\%s\\probe.ps1", path.Base(remoteDir))); err != nil {
		t.Fatalf("run staging probe task: %v", err)
	}

	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		data, err := share.ReadFile(resultName)
		if err == nil {
			marker, err := decodeInstallMarker(data)
			if err != nil {
				t.Fatalf("decode staging result: %v", err)
			}
			t.Log(marker.Detail)
			if !marker.OK {
				t.Fatalf("deployment kit staging failed: %s", marker.Detail)
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
	t.Fatal("timed out waiting for deployment kit staging result")
}

// TestLiveWindowsInstallDiagnostic executes the official Deployment Kit with
// persistent stage and output files. Unlike the production path, it allows a
// long installer window and keeps the remote directory when installation
// fails so the original evidence is not destroyed.
func TestLiveWindowsInstallDiagnostic(t *testing.T) {
	host, username, password := liveWindowsCredentials(t)
	kitPath := os.Getenv("AGENTBRIDGE_TEST_WINDOWS_KIT_PATH")
	kitSHA256 := os.Getenv("AGENTBRIDGE_TEST_WINDOWS_KIT_SHA256")
	if kitPath == "" || kitSHA256 == "" {
		t.Skip("set AGENTBRIDGE_TEST_WINDOWS_KIT_PATH and AGENTBRIDGE_TEST_WINDOWS_KIT_SHA256")
	}
	kit, err := readFile(kitPath)
	if err != nil {
		t.Fatalf("read deployment kit: %v", err)
	}

	req := Request{Host: host, Username: username, Password: password}
	client := Client{Timeout: 10 * time.Minute}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	session, share, conn, err := client.mount(ctx, &req)
	if err != nil {
		t.Fatalf("mount ADMIN$: %v", err)
	}
	defer conn.Close()
	defer session.Logoff()
	defer share.Umount()

	remoteDir := path.Join("Temp", "AgentBridge-DiagnosticInstall-"+randomID())
	if err := share.MkdirAll(remoteDir, 0700); err != nil {
		t.Fatalf("create diagnostic install directory: %v", err)
	}
	t.Logf("remote diagnostic directory: C:\\Windows\\%s", strings.ReplaceAll(remoteDir, "/", "\\"))
	zipName := path.Join(remoteDir, "deployment-kit.zip")
	if err := share.WriteFile(zipName, kit, 0600); err != nil {
		t.Fatalf("upload deployment kit: %v", err)
	}

	taskName := "AgentBridge-DiagnosticInstall-" + randomID()
	resultName := path.Join(remoteDir, "result.json")
	stageName := path.Join(remoteDir, "stage.txt")
	outputName := path.Join(remoteDir, "installer-output.log")
	scriptName := path.Join(remoteDir, "install-diagnostic.ps1")
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$root = Join-Path $env:windir 'Temp\%s'
$zip = Join-Path $root 'deployment-kit.zip'
$expanded = Join-Path $root 'expanded'
$result = Join-Path $root 'result.json'
$stagePath = Join-Path $root 'stage.txt'
$outputPath = Join-Path $root 'installer-output.log'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
function Write-Stage([string]$stage) { [System.IO.File]::WriteAllText($stagePath, $stage, $utf8NoBom) }
function Write-Result([bool]$ok, [string]$detail, [string]$serviceName, [string]$serviceStatus) {
  $json = @{ok=$ok; detail=$detail; serviceName=$serviceName; serviceStatus=$serviceStatus} | ConvertTo-Json -Compress
  [System.IO.File]::WriteAllText($result, $json, $utf8NoBom)
}
try {
  Write-Stage 'sha256'
  $stream = [System.IO.File]::OpenRead($zip)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try { $actual = ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '') } finally { $sha.Dispose(); $stream.Dispose() }
  if ($actual -ne '%s') { throw "SHA-256 mismatch: $actual" }

  Write-Stage 'extract'
  New-Item -ItemType Directory -Force $expanded | Out-Null
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $expanded)
  $bat = Get-ChildItem -LiteralPath $expanded -Filter 'InstallDeploymentKit.bat' -Recurse | Select-Object -First 1
  if (-not $bat) { throw 'InstallDeploymentKit.bat not found' }

  Write-Stage 'official_installer'
  Push-Location $bat.DirectoryName
  try {
    $installerOutput = & cmd.exe /d /c $bat.FullName 2>&1
    $installerExitCode = $LASTEXITCODE
  } finally {
    Pop-Location
  }
  [System.IO.File]::WriteAllText($outputPath, ($installerOutput | Out-String), $utf8NoBom)
  if ($installerExitCode -ne 0) { throw "InstallDeploymentKit.bat exit code $installerExitCode" }

  Write-Stage 'verify_service'
  $serviceDeadline = [DateTime]::UtcNow.AddSeconds(90)
  do {
    $svc = Get-Service -Name 'VeeamDeploySvc' -ErrorAction SilentlyContinue
    if ($svc -and [string]$svc.Status -eq 'Running') { break }
    Start-Sleep -Seconds 1
  } while ([DateTime]::UtcNow -lt $serviceDeadline)
  if (-not $svc) { throw 'VeeamDeploySvc was not found after installation' }
  if ([string]$svc.Status -ne 'Running') { throw "VeeamDeploySvc status is $($svc.Status)" }

  Write-Stage 'completed'
  Write-Result $true 'Deployment Kit installation completed.' $svc.Name ([string]$svc.Status)
} catch {
  $diagnostic = "stage=" + (Get-Content $stagePath -ErrorAction SilentlyContinue) + "; error=" + $_.Exception.Message
  try { [System.IO.File]::AppendAllText($outputPath, [Environment]::NewLine + $diagnostic + [Environment]::NewLine + ($_ | Out-String), $utf8NoBom) } catch {}
  try { Write-Stage 'failed' } catch {}
  try { Write-Result $false $diagnostic '' '' } catch {}
}
try { schtasks.exe /Delete /TN '\%s' /F | Out-Null } catch {}
`, path.Base(remoteDir), strings.ToUpper(kitSHA256), taskName)
	if err := share.WriteFile(scriptName, []byte(script), 0600); err != nil {
		t.Fatalf("upload diagnostic install script: %v", err)
	}
	if err := client.runTask(ctx, host, req, taskName, fmt.Sprintf("C:\\Windows\\Temp\\%s\\install-diagnostic.ps1", path.Base(remoteDir))); err != nil {
		t.Fatalf("run diagnostic install task: %v", err)
	}

	lastStage := ""
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		if stage, err := share.ReadFile(stageName); err == nil {
			current := strings.TrimSpace(string(stage))
			if current != "" && current != lastStage {
				t.Logf("stage=%s", current)
				lastStage = current
			}
		}
		data, err := share.ReadFile(resultName)
		if err == nil {
			marker, err := decodeInstallMarker(data)
			if err != nil {
				t.Fatalf("decode diagnostic install result: %v", err)
			}
			output, _ := share.ReadFile(outputName)
			if len(output) > 0 {
				t.Logf("installer output:\n%s", output)
			}
			if !marker.OK {
				t.Fatalf("diagnostic installation failed: %s; evidence retained at C:\\Windows\\%s", marker.Detail, strings.ReplaceAll(remoteDir, "/", "\\"))
			}
			if marker.ServiceName != "VeeamDeploySvc" || !strings.EqualFold(marker.ServiceStatus, "Running") {
				t.Fatalf("unexpected service result: %#v", marker)
			}
			if err := tcpProbe(ctx, host, 6160); err != nil {
				t.Fatalf("VeeamDeploySvc is running but port 6160 is unavailable: %v", err)
			}
			if err := share.RemoveAll(remoteDir); err != nil {
				t.Logf("installation succeeded but remote diagnostic cleanup failed: %v", err)
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("diagnostic installation context ended at stage %q: %v; evidence retained at C:\\Windows\\%s", lastStage, ctx.Err(), strings.ReplaceAll(remoteDir, "/", "\\"))
		case <-time.After(time.Second):
		}
	}
	t.Fatalf("diagnostic installation timed out at stage %q; evidence retained at C:\\Windows\\%s", lastStage, strings.ReplaceAll(remoteDir, "/", "\\"))
}

func liveWindowsCredentials(t *testing.T) (string, string, string) {
	t.Helper()
	host := os.Getenv("AGENTBRIDGE_TEST_WINDOWS_HOST")
	username := os.Getenv("AGENTBRIDGE_TEST_WINDOWS_USER")
	password := os.Getenv("AGENTBRIDGE_TEST_WINDOWS_PASSWORD")
	if host == "" || username == "" || password == "" {
		t.Skip("set AGENTBRIDGE_TEST_WINDOWS_HOST, AGENTBRIDGE_TEST_WINDOWS_USER and AGENTBRIDGE_TEST_WINDOWS_PASSWORD")
	}
	return host, username, password
}
