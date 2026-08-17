package windowsdeploy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	itaskschedulerservice "github.com/oiweiwei/go-msrpc/msrpc/tsch/itaskschedulerservice/v1"
	"github.com/oiweiwei/go-msrpc/smb2"
)

func TestKerberosPreferred(t *testing.T) {
	tests := []struct {
		name     string
		req      Request
		want     bool
		authName string
	}{
		{
			name:     "bare local account uses NTLMv2",
			req:      Request{Host: "win2025", Username: "Administrator"},
			want:     false,
			authName: "SPNEGO (NTLMv2 for local/workgroup account)",
		},
		{
			name:     "dot qualified local account uses NTLMv2",
			req:      Request{Host: "win2025", Username: `.\Administrator`},
			want:     false,
			authName: "SPNEGO (NTLMv2 for local/workgroup account)",
		},
		{
			name:     "computer qualified local account uses NTLMv2",
			req:      Request{Host: "win2025.example.test", Username: `WIN2025\Administrator`},
			want:     false,
			authName: "SPNEGO (NTLMv2 for local/workgroup account)",
		},
		{
			name:     "ip target uses NTLMv2",
			req:      Request{Host: "192.0.2.25", Username: `WIN2025\Administrator`},
			want:     false,
			authName: "SPNEGO (NTLMv2 for local/workgroup account)",
		},
		{
			name:     "domain account prefers kerberos",
			req:      Request{Host: "win2025.example.test", Username: `CONTOSO\Administrator`},
			want:     true,
			authName: "SPNEGO (Kerberos preferred, NTLMv2 fallback)",
		},
		{
			name:     "upn account prefers kerberos",
			req:      Request{Host: "win2025.example.test", Username: "Administrator@contoso.test"},
			want:     true,
			authName: "SPNEGO (Kerberos preferred, NTLMv2 fallback)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := kerberosPreferred(tt.req); got != tt.want {
				t.Fatalf("kerberosPreferred(%q) = %v, want %v", tt.req.Username, got, tt.want)
			}
			if got := authentication(tt.req); got != tt.authName {
				t.Fatalf("authentication(%q) = %q, want %q", tt.req.Username, got, tt.authName)
			}
		})
	}
}

func TestLocalDialerInitializesWithoutKerberosRealm(t *testing.T) {
	dialer := (Client{}).dialer(Request{Host: "win2025", Username: "Administrator", Password: "secret"})
	if dialer.Negotiator.SpecifiedDialect != uint16(smb2.SMB311) {
		t.Fatalf("default SMB dialect = 0x%04x, want SMB 3.1.1", dialer.Negotiator.SpecifiedDialect)
	}
	if !dialer.Negotiator.RequireMessageSigning || !dialer.Negotiator.UseMessageEncryption {
		t.Fatal("Windows dialer must require signing and request SMB encryption")
	}
	if _, err := dialer.Initiator.InitSecContext(); err != nil {
		t.Fatalf("local/workgroup dialer unexpectedly initialized Kerberos: %v", err)
	}
}

func TestDialerUsesSelectedSMB3Fallback(t *testing.T) {
	dialer := (Client{}).dialer(Request{Host: "win2012", Username: "Administrator", Password: "secret", smbDialect: smb2.SMB300})
	if dialer.Negotiator.SpecifiedDialect != uint16(smb2.SMB300) {
		t.Fatalf("fallback SMB dialect = 0x%04x, want SMB 3.0", dialer.Negotiator.SpecifiedDialect)
	}
}

func TestDialectUnsupported(t *testing.T) {
	if !dialectUnsupported(errors.New("response error: The request is not supported.")) {
		t.Fatal("Windows Server 2012 unsupported-dialect response must trigger SMB 3 fallback")
	}
	if dialectUnsupported(errors.New("response error: Access is denied.")) {
		t.Fatal("authentication and authorization failures must not trigger a dialect fallback")
	}
}

func TestRPCOptionsCreatePrivateSecurityContextForLocalAccount(t *testing.T) {
	opts := (Client{}).rpcOptions(Request{
		Host:     "win2025",
		Username: "Administrator",
		Password: "secret",
	})
	opts = append(opts, dcerpc.WithAbstractSyntax(itaskschedulerservice.TaskSchedulerServiceSyntaxV1_0))
	parsed, err := dcerpc.ParseOptions(context.Background(), opts...)
	if err != nil {
		t.Fatalf("RPC options did not create a security context: %v", err)
	}
	if parsed.Security.Level != dcerpc.AuthLevelPktPrivacy {
		t.Fatalf("RPC auth level = %d, want packet privacy (%d)", parsed.Security.Level, dcerpc.AuthLevelPktPrivacy)
	}
}

func TestClassifyTaskRegistrationAccessDenied(t *testing.T) {
	result := classify(errors.New("dcerpc: invoke: /ITaskSchedulerService/v1/SchRpcRegisterTask: response: decode packet: error: code: 0x00000005"), "Task Scheduler RPC")
	if result.Status != StatusTaskSchedulerDenied {
		t.Fatalf("status = %q, want %q", result.Status, StatusTaskSchedulerDenied)
	}
	if result.Detail != "Task Scheduler authenticated the request but denied the task operation." {
		t.Fatalf("unexpected human-readable detail: %q", result.Detail)
	}
	if result.TaskSchedulerRPC != "access_denied" {
		t.Fatalf("taskSchedulerRpc = %q, want access_denied", result.TaskSchedulerRPC)
	}
	if result.RPCAuthLevel != "packet_privacy" || result.FailureStage != "task_registration" || result.ErrorCode != "ERROR_ACCESS_DENIED (0x00000005)" {
		t.Fatalf("unexpected structured diagnostics: %#v", result)
	}
	if strings.Contains(result.Detail, "/ITaskSchedulerService") || !strings.Contains(result.TechnicalDetail, "/ITaskSchedulerService") {
		t.Fatalf("technical RPC detail leaked into public detail: %#v", result)
	}
}

func TestProbeTaskXMLDoesNotRunOnRegistration(t *testing.T) {
	xml := probeTaskXML()
	if strings.Contains(xml, "RegistrationTrigger") {
		t.Fatal("probe task must not contain a registration trigger")
	}
	for _, want := range []string{"<UserId>S-1-5-18</UserId>", "cmd.exe", "/c exit 0"} {
		if !strings.Contains(xml, want) {
			t.Fatalf("probe XML %q does not contain %q", xml, want)
		}
	}
	for _, invalid := range []string{"<UserId>SYSTEM</UserId>", "<LogonType>ServiceAccount</LogonType>"} {
		if strings.Contains(xml, invalid) {
			t.Fatalf("probe task XML contains unsupported value %q", invalid)
		}
	}
}

func TestTaskXMLUsesLocalSystemAndOnDemandRun(t *testing.T) {
	xml := taskXML(`C:\Windows\Temp\AgentBridge-test\install.ps1`)
	for _, want := range []string{"<UserId>S-1-5-18</UserId>", "<AllowStartOnDemand>true</AllowStartOnDemand>"} {
		if !strings.Contains(xml, want) {
			t.Fatalf("install task XML %q does not contain %q", xml, want)
		}
	}
	for _, unwanted := range []string{"<UserId>SYSTEM</UserId>", "<LogonType>ServiceAccount</LogonType>", "RegistrationTrigger", "DeleteExpiredTaskAfter"} {
		if strings.Contains(xml, unwanted) {
			t.Fatalf("install task XML must not contain %q", unwanted)
		}
	}
}

func TestServiceProbeScriptIsReadOnlyAndLegacyPowerShellCompatible(t *testing.T) {
	script := serviceProbeScript("AgentBridge-ServiceProbe-test", "AgentBridge-ServiceProbe-task")
	for _, want := range []string{
		"Get-Service -Name $serviceName",
		"$serviceStatus -eq 'Running'",
		"[System.IO.File]::WriteAllText",
		"schtasks.exe /Delete",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("service probe script does not contain %q", want)
		}
	}
	for _, unwanted := range []string{"Start-Service", "Stop-Service", "Set-Service", "ConvertTo-Json -Depth"} {
		if strings.Contains(script, unwanted) {
			t.Fatalf("service probe script must not contain %q", unwanted)
		}
	}
}

func TestTaskRegistrationErrorRetainsXMLErrorInfo(t *testing.T) {
	cause := errors.New("SCHED_E_INVALIDVALUE (0x80041318)")
	err := newTaskRegistrationError("register probe task", &itaskschedulerservice.RegisterTaskResponse{
		ErrorInfo: &itaskschedulerservice.TaskXMLErrorInfo{
			Line: 1, Column: 170, Node: "LogonType", Value: "ServiceAccount",
		},
	}, cause)
	result := classify(err, "Task Scheduler RPC")
	if result.ErrorField != "LogonType" || result.ErrorValue != "ServiceAccount" || result.ErrorLine != 1 || result.ErrorColumn != 170 {
		t.Fatalf("task XML error info was not preserved: %#v", result)
	}
}

func TestClassifyTaskXMLInvalidValueSignedHRESULT(t *testing.T) {
	raw := "register probe task: Task Scheduler RPC: /ITaskSchedulerService/v1/SchRpcRegisterTask: error: -2147216616"
	result := classify(errors.New(raw), "Task Scheduler RPC")
	if result.Status != StatusTaskDefinitionBad || result.ErrorKey != "task_xml_invalid_value" {
		t.Fatalf("unexpected classification: %#v", result)
	}
	if result.ErrorCode != "SCHED_E_INVALIDVALUE (0x80041318)" || result.FailureStage != "task_registration" {
		t.Fatalf("unexpected structured diagnostics: %#v", result)
	}
	if strings.Contains(result.Detail, "/ITaskSchedulerService") || strings.Contains(result.Detail, "-2147216616") {
		t.Fatalf("code-level error leaked into public detail: %q", result.Detail)
	}
	if result.TechnicalDetail != raw {
		t.Fatalf("technical detail was not retained for diagnostics: %q", result.TechnicalDetail)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "ITaskSchedulerService") || strings.Contains(string(encoded), "-2147216616") {
		t.Fatalf("technical detail leaked into JSON response: %s", encoded)
	}
}

func TestClassifyInstallerExitCode(t *testing.T) {
	result := classifyInstallerFailure("InstallDeploymentKit.bat exit code 7")
	if result.ErrorKey != "deployment_kit_installer_failed" || result.ErrorCode != "INSTALLER_EXIT_CODE (7)" {
		t.Fatalf("unexpected installer classification: %#v", result)
	}
	if strings.Contains(result.Detail, "exit code 7") || !strings.Contains(result.TechnicalDetail, "exit code 7") {
		t.Fatalf("installer technical detail was not separated from public detail: %#v", result)
	}
}

func TestClassifyConnectivity(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"dial tcp: lookup win.invalid: no such host", "host_not_found"},
		{"dial tcp 192.0.2.1:445: i/o timeout", "network_timeout"},
		{"dial tcp 192.0.2.1:445: connect: connection refused", "connection_refused"},
		{"dial tcp 192.0.2.1:445: no route to host", "network_unreachable"},
	}
	for _, tt := range tests {
		result := classify(errors.New(tt.raw), "ADMIN$")
		if result.ErrorKey != tt.want || result.TechnicalDetail != tt.raw {
			t.Fatalf("classify(%q) = %#v, want error %q", tt.raw, result, tt.want)
		}
	}
}

func TestClassifyWindowsAccountState(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"STATUS_ACCOUNT_LOCKED_OUT (0xC0000234)", "windows_account_locked"},
		{"STATUS_PASSWORD_EXPIRED (0xC0000071)", "windows_password_expired"},
		{"STATUS_PASSWORD_MUST_CHANGE (0xC0000224)", "windows_password_change_required"},
		{"STATUS_ACCOUNT_DISABLED (0xC0000072)", "windows_account_disabled"},
		{"STATUS_LOGON_TYPE_NOT_GRANTED (0xC000015B)", "windows_remote_logon_denied"},
	}
	for _, tt := range tests {
		result := classify(errors.New(tt.raw), "ADMIN$")
		if result.ErrorKey != tt.want {
			t.Fatalf("classify(%q) = %#v, want error %q", tt.raw, result, tt.want)
		}
	}
}

func TestDecodeInstallMarkerAcceptsPowerShellUTF8BOM(t *testing.T) {
	marker, err := decodeInstallMarker(append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"ok":true}`)...))
	if err != nil {
		t.Fatalf("PowerShell UTF-8 BOM result was rejected: %v", err)
	}
	if !marker.OK {
		t.Fatalf("unexpected marker: %#v", marker)
	}
}

func TestPowerShellResultWriterUsesBOMlessUTF8(t *testing.T) {
	script := powershellScript("Temp/AgentBridge-test", "", "AgentBridge-test")
	for _, want := range []string{"System.Text.UTF8Encoding($false)", "System.IO.File]::WriteAllText", "ConvertTo-Json -Compress", "Get-Service -Name 'VeeamDeploySvc'", "serviceStatus=[string]$svc.Status", "System.IO.Compression.ZipFile]::ExtractToDirectory", "System.Security.Cryptography.SHA256]::Create"} {
		if !strings.Contains(script, want) {
			t.Fatalf("PowerShell script does not contain %q", want)
		}
	}
	for _, unsupported := range []string{"Set-Content -Encoding UTF8", "Expand-Archive", "Get-FileHash"} {
		if strings.Contains(script, unsupported) {
			t.Fatalf("PowerShell script must support Windows Server 2012 and not contain %q", unsupported)
		}
	}
}
