package windowsdeploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/tsch/itaskschedulerservice/v1"
	"github.com/oiweiwei/go-msrpc/smb2"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	smb2fork "github.com/oiweiwei/go-smb2.fork"
)

const (
	StatusReady               = "ready"
	StatusAuthFailed          = "auth_failed"
	StatusRemoteUACBlocked    = "remote_uac_blocked"
	StatusAdminShareMissing   = "admin_share_unavailable"
	StatusRPCUnavailable      = "rpc_unavailable"
	StatusTaskSchedulerDenied = "task_scheduler_access_denied"
	StatusTaskDefinitionBad   = "task_definition_invalid"
	StatusInstallFailed       = "install_failed"
	StatusInstalled           = "installed"

	taskCreate              = 0x2
	taskLogonServiceAccount = 5
)

type Request struct {
	Host       string
	Username   string
	Password   string
	KitPath    string
	KitSHA256  string
	smbDialect smb2.Dialect
}

type Result struct {
	Status           string `json:"status"`
	ErrorKey         string `json:"error,omitempty"`
	Authentication   string `json:"authentication,omitempty"`
	AdminShare       string `json:"adminShare,omitempty"`
	TaskSchedulerRPC string `json:"taskSchedulerRpc,omitempty"`
	RPCAuthLevel     string `json:"rpcAuthLevel,omitempty"`
	FailureStage     string `json:"failureStage,omitempty"`
	ErrorCode        string `json:"errorCode,omitempty"`
	ErrorField       string `json:"errorField,omitempty"`
	ErrorValue       string `json:"errorValue,omitempty"`
	ErrorLine        uint32 `json:"errorLine,omitempty"`
	ErrorColumn      uint32 `json:"errorColumn,omitempty"`
	ServiceReady     bool   `json:"serviceReady"`
	Detail           string `json:"detail,omitempty"`
	TechnicalDetail  string `json:"-"`
}

type installMarker struct {
	OK            bool   `json:"ok"`
	Detail        string `json:"detail"`
	ServiceName   string `json:"serviceName"`
	ServiceStatus string `json:"serviceStatus"`
}

type Client struct {
	Timeout time.Duration
}

type taskRegistrationError struct {
	operation string
	cause     error
	line      uint32
	column    uint32
	node      string
	value     string
}

func (e *taskRegistrationError) Error() string {
	if e == nil {
		return "task registration failed"
	}
	return fmt.Sprintf("%s: %v (task XML line=%d column=%d node=%q value=%q)", e.operation, e.cause, e.line, e.column, e.node, e.value)
}

func (e *taskRegistrationError) Unwrap() error { return e.cause }

func (c Client) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 45 * time.Second
	}
	return c.Timeout
}

func (c Client) Preflight(parent context.Context, req Request) Result {
	if err := validate(req); err != nil {
		return failure(StatusAuthFailed, "windows_request_invalid", "request_validation", "", "The Windows host and administrator credentials are incomplete.", err)
	}
	ctx, cancel := context.WithTimeout(parent, c.timeout())
	defer cancel()

	if err := tcpProbe(ctx, req.Host, 445); err != nil {
		return classifyConnectivity(err)
	}
	session, share, conn, err := c.mount(ctx, &req)
	if err != nil {
		return classify(err, "ADMIN$")
	}
	defer conn.Close()
	defer session.Logoff()
	defer share.Umount()

	result := Result{Status: StatusReady, Authentication: authentication(req), AdminShare: "available", RPCAuthLevel: "packet_privacy"}
	if err := c.probePipe(ctx, req.Host, req); err != nil {
		probeResult := classify(err, "Task Scheduler RPC")
		probeResult.Authentication = result.Authentication
		probeResult.AdminShare = result.AdminShare
		probeResult.RPCAuthLevel = result.RPCAuthLevel
		if probeResult.TaskSchedulerRPC == "" {
			probeResult.TaskSchedulerRPC = "unavailable"
		}
		return probeResult
	}
	result.TaskSchedulerRPC = "available"
	result.ServiceReady, _ = c.deploymentServiceReadyOnShare(ctx, req.Host, req, share)
	return result
}

func (c Client) Install(parent context.Context, req Request) Result {
	if err := validate(req); err != nil {
		return failure(StatusAuthFailed, "windows_request_invalid", "request_validation", "", "The Windows host and administrator credentials are incomplete.", err)
	}
	if req.KitPath == "" {
		return failure(StatusInstallFailed, "deployment_kit_missing", "kit_validation", "", "No active Deployment Kit is available for this installation.", nil)
	}
	if req.KitSHA256 != "" {
		sum, err := fileSHA256(req.KitPath)
		if err != nil {
			return failure(StatusInstallFailed, "deployment_kit_read_failed", "kit_validation", "", "The active Deployment Kit could not be read.", err)
		}
		if !strings.EqualFold(sum, req.KitSHA256) {
			return failure(StatusInstallFailed, "deployment_kit_integrity_failed", "kit_validation", "", "The Deployment Kit failed its SHA-256 integrity check.", nil)
		}
	}

	ctx, cancel := context.WithTimeout(parent, c.timeout())
	defer cancel()
	session, share, conn, err := c.mount(ctx, &req)
	if err != nil {
		return classify(err, "ADMIN$")
	}
	defer conn.Close()
	defer session.Logoff()
	defer share.Umount()

	remoteDir := path.Join("Temp", "AgentBridge-"+randomID())
	if err := share.MkdirAll(remoteDir, 0700); err != nil {
		return withRemoteContext(failure(StatusInstallFailed, "remote_staging_failed", "smb_upload", "", "The temporary installation directory could not be created on the target.", err), req, "available", "")
	}
	defer share.RemoveAll(remoteDir)

	kit, err := readFile(req.KitPath)
	if err != nil {
		return failure(StatusInstallFailed, "deployment_kit_read_failed", "kit_validation", "", "The active Deployment Kit could not be read.", err)
	}
	scriptName := path.Join(remoteDir, "install.ps1")
	zipName := path.Join(remoteDir, "deployment-kit.zip")
	resultName := path.Join(remoteDir, "result.json")
	if err := share.WriteFile(zipName, kit, 0600); err != nil {
		return withRemoteContext(failure(StatusInstallFailed, "deployment_kit_upload_failed", "smb_upload", "", "The Deployment Kit could not be copied to the target.", err), req, "available", "")
	}
	taskName := "AgentBridge-" + randomID()
	if err := share.WriteFile(scriptName, []byte(powershellScript(remoteDir, req.KitSHA256, taskName)), 0600); err != nil {
		return withRemoteContext(failure(StatusInstallFailed, "installer_script_upload_failed", "smb_upload", "", "The installation script could not be copied to the target.", err), req, "available", "")
	}

	taskErr := c.runTask(ctx, req.Host, req, taskName, fmt.Sprintf("C:\\Windows\\Temp\\%s\\install.ps1", path.Base(remoteDir)))
	if taskErr != nil {
		return withRemoteContext(classify(taskErr, "Task Scheduler RPC"), req, "available", "error")
	}

	result := Result{Status: StatusInstallFailed, Authentication: authentication(req), AdminShare: "available", TaskSchedulerRPC: "available"}
	deadline := time.Now().Add(c.timeout())
	for time.Now().Before(deadline) {
		data, readErr := share.ReadFile(resultName)
		if readErr == nil {
			marker, err := decodeInstallMarker(data)
			if err != nil {
				return withRemoteContext(failure(StatusInstallFailed, "installer_result_invalid", "installer_wait", "", "The remote installer returned an unreadable completion result.", err), req, "available", "available")
			}
			if marker.OK {
				result.Status = StatusInstalled
				if marker.ServiceName != "VeeamDeploySvc" || !strings.EqualFold(marker.ServiceStatus, "Running") {
					return withRemoteContext(failure(StatusInstallFailed, "veeam_deployment_service_not_ready", "service_verification", "", "The installer completed, but VeeamDeploySvc is not running.", fmt.Errorf("service=%q status=%q", marker.ServiceName, marker.ServiceStatus)), req, "available", "available")
				}
				if err := tcpProbe(ctx, req.Host, 6160); err != nil {
					return withRemoteContext(failure(StatusInstallFailed, "veeam_deployment_service_unreachable", "service_verification", "", "The installer completed, but the Veeam deployment service could not be reached.", err), req, "available", "available")
				}
				result.ServiceReady = true
				return result
			}
			return withRemoteContext(classifyInstallerFailure(marker.Detail), req, "available", "available")
		}
		select {
		case <-ctx.Done():
			return withRemoteContext(failure(StatusInstallFailed, "windows_install_timeout", "installer_wait", "", "The remote installation did not finish within the allowed time.", ctx.Err()), req, "available", "available")
		case <-time.After(750 * time.Millisecond):
		}
	}
	return withRemoteContext(failure(StatusInstallFailed, "windows_install_timeout", "installer_wait", "", "The remote installation did not finish within the allowed time.", context.DeadlineExceeded), req, "available", "available")
}

func decodeInstallMarker(data []byte) (installMarker, error) {
	// Windows PowerShell 5.1 writes a UTF-8 BOM for Set-Content -Encoding
	// UTF8. Accept that legacy output even though new scripts write BOM-less
	// UTF-8 explicitly.
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	var marker installMarker
	err := json.Unmarshal(data, &marker)
	return marker, err
}

func validate(req Request) error {
	if strings.TrimSpace(req.Host) == "" {
		return errors.New("host is required")
	}
	if strings.TrimSpace(req.Username) == "" {
		return errors.New("administrator username is required")
	}
	if req.Password == "" {
		return errors.New("administrator password is required")
	}
	return nil
}

func (c Client) dialer(req Request) *smb2fork.Dialer {
	// A bare username (or a local-machine/workgroup-qualified username) has
	// no Kerberos realm. Including KRB5 in SPNEGO for these accounts makes the
	// client try Kerberos first and fail before NTLMv2 gets a chance. Keep the
	// domain-aware behavior for explicit domain credentials, but negotiate only
	// NTLMv2 for local/workgroup accounts.
	security := []gssapi.ContextOption{
		gssapi.WithMechanismFactory(ssp.SPNEGO),
	}
	if kerberosPreferred(req) {
		security = append(security, gssapi.WithMechanismFactory(ssp.KRB5))
	}
	security = append(security,
		gssapi.WithMechanismFactory(ssp.NTLM),
		gssapi.WithCredential(credential.NewFromPassword(req.Username, req.Password)),
	)
	dialect := req.smbDialect
	if dialect == 0 {
		dialect = smb2.SMB311
	}
	return smb2.NewDialer(
		smb2.WithDialect(dialect),
		smb2.WithSign(),
		smb2.WithSeal(),
		smb2.WithSecurity(security...),
	)
}

func authentication(req Request) string {
	if kerberosPreferred(req) {
		return "SPNEGO (Kerberos preferred, NTLMv2 fallback)"
	}
	return "SPNEGO (NTLMv2 for local/workgroup account)"
}

func kerberosPreferred(req Request) bool {
	username := strings.TrimSpace(req.Username)
	if username == "" {
		return false
	}
	// An IP target cannot be used to derive a Kerberos service principal. It is
	// also the common way users reach a workgroup/local machine, so keep this
	// path on NTLMv2 even when a computer-qualified username was entered.
	if net.ParseIP(strings.TrimSpace(req.Host)) != nil {
		return false
	}

	domain := strings.TrimSpace(credential.DomainName(username))
	if domain == "" {
		return false
	}

	// These prefixes identify local/workgroup credentials rather than an AD
	// realm. A computer-qualified local account is also NTLM-only.
	switch strings.ToLower(domain) {
	case ".", "localhost", "local", "workgroup":
		return false
	}

	host := normalizeHost(req.Host)
	if host != "" && normalizeHost(domain) == host {
		return false
	}
	return true
}

func normalizeHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(value, ".")))
	if value == "" {
		return ""
	}
	if i := strings.IndexByte(value, '.'); i >= 0 {
		return value[:i]
	}
	return value
}

func (c Client) mount(ctx context.Context, req *Request) (*smb2fork.Session, *smb2fork.Share, net.Conn, error) {
	// Prefer the strongest SMB 3 dialect and only fall back when the target
	// explicitly reports that dialect as unsupported. Windows Server 2012
	// supports SMB 3.0, while current Windows supports SMB 3.1.1. No SMB 1 or
	// SMB 2.x dialect is ever offered.
	for _, dialect := range []smb2.Dialect{smb2.SMB311, smb2.SMB302, smb2.SMB300} {
		req.smbDialect = dialect
		session, share, conn, err := c.mountDialect(ctx, *req)
		if err == nil {
			return session, share, conn, nil
		}
		if !dialectUnsupported(err) {
			return nil, nil, nil, err
		}
	}
	return nil, nil, nil, errors.New("Windows does not support a compatible SMB 3 dialect")
}

func (c Client) mountDialect(ctx context.Context, req Request) (*smb2fork.Session, *smb2fork.Share, net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(req.Host, "445"))
	if err != nil {
		return nil, nil, nil, err
	}
	dialer := c.dialer(req)
	session, err := dialer.DialContext(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	share, err := session.Mount("ADMIN$")
	if err != nil {
		session.Logoff()
		conn.Close()
		return nil, nil, nil, err
	}
	return session, share, conn, nil
}

func dialectUnsupported(err error) bool {
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "request is not supported") ||
		strings.Contains(lower, "not supported") ||
		strings.Contains(lower, "unexpected dialect returned")
}

func (c Client) probePipe(ctx context.Context, host string, req Request) error {
	cc, err := dcerpc.Dial(ctx, "ncacn_np:"+host+"[atsvc]", c.rpcOptions(req)...)
	if err != nil {
		return err
	}
	defer cc.Close(ctx)
	client, err := itaskschedulerservice.NewTaskSchedulerServiceClient(ctx, cc)
	if err != nil {
		return err
	}
	// A successful named-pipe bind alone does not prove that the account may
	// register the SYSTEM task used by the installer. Register and immediately
	// delete a triggerless probe task so Remote UAC/access-denied failures are
	// reported during preflight instead of after the kit has been uploaded.
	taskPath := "\\AgentBridge-Probe-" + randomID()
	response, err := client.RegisterTask(ctx, &itaskschedulerservice.RegisterTaskRequest{
		Path:      taskPath,
		XML:       probeTaskXML(),
		Flags:     taskCreate,
		LogonType: taskLogonServiceAccount,
	})
	if err != nil {
		return newTaskRegistrationError("register probe task", response, err)
	}
	if _, err := client.Delete(ctx, &itaskschedulerservice.DeleteRequest{Path: taskPath}); err != nil {
		return fmt.Errorf("delete Task Scheduler probe task: %w", err)
	}
	return nil
}

// deploymentServiceReady is the diagnostic wrapper used by opt-in live tests.
// Preflight reuses its existing encrypted ADMIN$ session through the on-share
// implementation below.
func (c Client) deploymentServiceReady(ctx context.Context, host string, req Request) (bool, error) {
	session, share, conn, err := c.mount(ctx, &req)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	defer session.Logoff()
	defer share.Umount()
	return c.deploymentServiceReadyOnShare(ctx, host, req, share)
}

// deploymentServiceReadyOnShare verifies both halves of deployment-service
// readiness: Windows must report VeeamDeploySvc as running through its Service
// Control Manager, and port 6160 must accept a connection. A missing or stopped
// service is not a preflight failure—the host can still receive the Deployment
// Kit—so callers receive ready with serviceReady=false.
func (c Client) deploymentServiceReadyOnShare(ctx context.Context, host string, req Request, share *smb2fork.Share) (bool, error) {
	if err := tcpProbe(ctx, host, 6160); err != nil {
		return false, nil
	}

	remoteDir := path.Join("Temp", "AgentBridge-ServiceProbe-"+randomID())
	if err := share.MkdirAll(remoteDir, 0700); err != nil {
		return false, fmt.Errorf("create service probe directory: %w", err)
	}
	defer share.RemoveAll(remoteDir)

	taskName := "AgentBridge-ServiceProbe-" + randomID()
	resultName := path.Join(remoteDir, "result.json")
	scriptName := path.Join(remoteDir, "verify.ps1")
	if err := share.WriteFile(scriptName, []byte(serviceProbeScript(path.Base(remoteDir), taskName)), 0600); err != nil {
		return false, fmt.Errorf("upload service probe script: %w", err)
	}
	if err := c.runTask(ctx, host, req, taskName, fmt.Sprintf("C:\\Windows\\Temp\\%s\\verify.ps1", path.Base(remoteDir))); err != nil {
		return false, fmt.Errorf("run service probe task: %w", err)
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		data, err := share.ReadFile(resultName)
		if err == nil {
			marker, err := decodeInstallMarker(data)
			if err != nil {
				return false, fmt.Errorf("decode service probe result: %w", err)
			}
			ready := marker.OK && marker.ServiceName == "VeeamDeploySvc" && strings.EqualFold(marker.ServiceStatus, "Running")
			return ready, nil
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return false, errors.New("timed out waiting for service probe result")
}

func (c Client) runTask(ctx context.Context, host string, req Request, taskName, scriptPath string) error {
	cc, err := dcerpc.Dial(ctx, "ncacn_np:"+host+"[atsvc]", c.rpcOptions(req)...)
	if err != nil {
		return err
	}
	defer cc.Close(ctx)
	client, err := itaskschedulerservice.NewTaskSchedulerServiceClient(ctx, cc)
	if err != nil {
		return err
	}
	xml := taskXML(scriptPath)
	response, err := client.RegisterTask(ctx, &itaskschedulerservice.RegisterTaskRequest{
		Path:      "\\" + taskName,
		XML:       xml,
		Flags:     taskCreate,
		LogonType: taskLogonServiceAccount,
	})
	if err != nil {
		return newTaskRegistrationError("register install task", response, err)
	}
	_, err = client.Run(ctx, &itaskschedulerservice.RunRequest{Path: "\\" + taskName})
	if err != nil {
		// The installer script normally deletes its own task. If the scheduler
		// refuses to start it, remove the task from the control path as well.
		_, _ = client.Delete(ctx, &itaskschedulerservice.DeleteRequest{Path: "\\" + taskName})
		return fmt.Errorf("start install task: %w", err)
	}
	return nil
}

func newTaskRegistrationError(operation string, response *itaskschedulerservice.RegisterTaskResponse, cause error) error {
	result := &taskRegistrationError{operation: operation, cause: cause}
	if response != nil && response.ErrorInfo != nil {
		result.line = response.ErrorInfo.Line
		result.column = response.ErrorInfo.Column
		result.node = strings.TrimSpace(response.ErrorInfo.Node)
		result.value = strings.TrimSpace(response.ErrorInfo.Value)
	}
	return result
}

func (c Client) rpcOptions(req Request) []dcerpc.Option {
	// MS-TSCH requires RPC_C_AUTHN_LEVEL_PKT_PRIVACY (6). SMB encryption
	// protects the named-pipe transport but does not replace DCE/RPC packet
	// privacy. WithSign only selects PKT_INTEGRITY (5), which Windows can
	// accept at bind time and then reject on SchRpcRegisterTask.
	return c.protectedRPCOptions(req, dcerpc.WithSeal())
}

func (c Client) protectedRPCOptions(req Request, protection dcerpc.Option) []dcerpc.Option {
	// SMB authentication and RPC authentication are separate layers. The SMB
	// named-pipe transport already uses the signed/sealed dialer above, but the
	// RPC bind still needs an explicit security context. Without these options
	// go-msrpc rejects the bind with "security context is empty".
	opts := []dcerpc.Option{
		dcerpc.WithSMBDialer(c.dialer(req)),
		dcerpc.WithCredentials(credential.NewFromPassword(req.Username, req.Password)),
		protection,
	}
	if kerberosPreferred(req) {
		opts = append(opts,
			dcerpc.WithMechanism(ssp.SPNEGO),
			dcerpc.WithMechanism(ssp.KRB5),
			dcerpc.WithMechanism(ssp.NTLM),
		)
	} else {
		// Workgroup/local accounts do not have a Kerberos realm. Keep SPNEGO
		// available for the RPC bind, but limit its mechanism list to NTLMv2 so
		// the provider cannot attempt krb5 first.
		opts = append(opts,
			dcerpc.WithMechanism(ssp.SPNEGO),
			dcerpc.WithMechanism(ssp.NTLM),
		)
	}
	return opts
}

func classify(err error, component string) Result {
	lower := strings.ToLower(err.Error())
	if isConnectivityError(lower) {
		return classifyConnectivity(err)
	}
	if component == "Task Scheduler RPC" {
		if result, ok := classifyTaskSchedulerError(err, lower); ok {
			return result
		}
	}
	if strings.Contains(lower, "security context is empty") {
		return failure(StatusRPCUnavailable, "rpc_security_context_missing", "rpc_authentication", "", "The RPC authentication context could not be created.", err)
	}
	if strings.Contains(lower, "define realm") || strings.Contains(lower, "krb5") && strings.Contains(lower, "realm") {
		return failure(StatusAuthFailed, "kerberos_realm_missing", "authentication", "", "The supplied account has no usable Kerberos realm. Local and workgroup accounts must use NTLMv2.", err)
	}
	if component != "ADMIN$" && (strings.Contains(lower, "restricted token") || strings.Contains(lower, "remote token")) {
		return failure(StatusRemoteUACBlocked, "remote_privilege_restricted", "remote_authorization", "ERROR_ACCESS_DENIED (0x00000005)", "Windows accepted the credentials but restricted the remote administrator token.", err)
	}
	if strings.Contains(lower, "account locked") || strings.Contains(lower, "status_account_locked_out") || strings.Contains(lower, "0xc0000234") {
		return failure(StatusAuthFailed, "windows_account_locked", "authentication", "", "The Windows account is locked.", err)
	}
	if strings.Contains(lower, "password expired") || strings.Contains(lower, "status_password_expired") || strings.Contains(lower, "0xc0000071") {
		return failure(StatusAuthFailed, "windows_password_expired", "authentication", "", "The Windows account password has expired.", err)
	}
	if strings.Contains(lower, "password must change") || strings.Contains(lower, "status_password_must_change") || strings.Contains(lower, "0xc0000224") {
		return failure(StatusAuthFailed, "windows_password_change_required", "authentication", "", "The Windows account password must be changed before remote use.", err)
	}
	if strings.Contains(lower, "account disabled") || strings.Contains(lower, "status_account_disabled") || strings.Contains(lower, "0xc0000072") {
		return failure(StatusAuthFailed, "windows_account_disabled", "authentication", "", "The Windows account is disabled.", err)
	}
	if strings.Contains(lower, "logon type") || strings.Contains(lower, "status_logon_type_not_granted") || strings.Contains(lower, "0xc000015b") {
		return failure(StatusAuthFailed, "windows_remote_logon_denied", "authentication", "", "The Windows account is not allowed to sign in remotely.", err)
	}
	if strings.Contains(lower, "logon") || strings.Contains(lower, "authentication") || strings.Contains(lower, "password") || strings.Contains(lower, "status_no_such_user") || strings.Contains(lower, "0xc0000064") || strings.Contains(lower, "0xc000006a") || strings.Contains(lower, "0xc000006d") {
		return failure(StatusAuthFailed, "windows_authentication_failed", "authentication", "ERROR_LOGON_FAILURE", "Windows rejected the administrator credentials.", err)
	}
	if component == "ADMIN$" && strings.Contains(lower, "access denied") {
		return failure(StatusRemoteUACBlocked, "remote_privilege_restricted", "remote_authorization", "ERROR_ACCESS_DENIED (0x00000005)", "Windows accepted the credentials but denied remote administrator access.", err)
	}
	if strings.Contains(lower, "uac") || strings.Contains(lower, "restricted token") || (strings.Contains(lower, "remote") && strings.Contains(lower, "token")) {
		return failure(StatusRemoteUACBlocked, "remote_privilege_restricted", "remote_authorization", "ERROR_ACCESS_DENIED (0x00000005)", "Windows accepted the credentials but restricted the remote administrator token.", err)
	}
	if component == "ADMIN$" {
		return failure(StatusAdminShareMissing, "admin_share_unavailable", "smb_admin_share", "", "The ADMIN$ administrative share could not be opened.", err)
	}
	if strings.Contains(lower, "pipe") || strings.Contains(lower, "rpc") || strings.Contains(lower, "endpoint") {
		return failure(StatusRPCUnavailable, "task_scheduler_rpc_unavailable", "rpc_connection", "", "The Task Scheduler RPC service could not be reached.", err)
	}
	return failure(StatusRPCUnavailable, "windows_remote_operation_failed", "remote_operation", "", "Windows could not complete the requested remote operation.", err)
}

func classifyConnectivity(err error) Result {
	lower := strings.ToLower(err.Error())
	key := "network_unreachable"
	detail := "The target could not be reached over the network."
	switch {
	case strings.Contains(lower, "no such host"), strings.Contains(lower, "server misbehaving"), strings.Contains(lower, "name resolution"):
		key = "host_not_found"
		detail = "The target host name could not be resolved."
	case strings.Contains(lower, "i/o timeout"), strings.Contains(lower, "deadline exceeded"):
		key = "network_timeout"
		detail = "The target did not respond before the connection timed out."
	case strings.Contains(lower, "connection refused"):
		key = "connection_refused"
		detail = "The target refused the network connection."
	}
	return failure(StatusAdminShareMissing, key, "network_connect", "", detail, err)
}

func isConnectivityError(lower string) bool {
	return strings.Contains(lower, "no such host") ||
		strings.Contains(lower, "server misbehaving") ||
		strings.Contains(lower, "name resolution") ||
		strings.Contains(lower, "i/o timeout") ||
		strings.Contains(lower, "deadline exceeded") ||
		strings.Contains(lower, "connection refused") ||
		strings.Contains(lower, "no route to host") ||
		strings.Contains(lower, "network is unreachable") ||
		strings.Contains(lower, "host is down")
}

func classifyTaskSchedulerError(err error, lower string) (Result, bool) {
	stage := "task_scheduler"
	if strings.Contains(lower, "register") {
		stage = "task_registration"
	} else if strings.Contains(lower, "start install task") {
		stage = "task_start"
	}

	if isTaskRegistrationAccessDenied(lower) {
		result := failure(
			StatusTaskSchedulerDenied,
			"task_scheduler_access_denied",
			stage,
			"ERROR_ACCESS_DENIED (0x00000005)",
			"Task Scheduler authenticated the request but denied the task operation.",
			err,
		)
		result.TaskSchedulerRPC = "access_denied"
		result.RPCAuthLevel = "packet_privacy"
		return result, true
	}

	specs := []struct {
		code   uint32
		symbol string
		status string
		key    string
		detail string
	}{
		{0x80041310, "SCHED_E_ACCOUNT_NAME_NOT_FOUND", StatusInstallFailed, "task_account_not_found", "Task Scheduler could not resolve the task account."},
		{0x80041313, "SCHED_E_UNKNOWN_OBJECT_VERSION", StatusTaskDefinitionBad, "task_definition_version_invalid", "The generated task definition uses an unsupported task version."},
		{0x80041314, "SCHED_E_UNSUPPORTED_ACCOUNT_OPTION", StatusTaskDefinitionBad, "task_account_option_invalid", "The generated task uses an unsupported account and logon option combination."},
		{0x80041315, "SCHED_E_SERVICE_NOT_RUNNING", StatusRPCUnavailable, "task_scheduler_service_not_running", "The Task Scheduler service is not running on the target."},
		{0x80041316, "SCHED_E_UNEXPECTEDNODE", StatusTaskDefinitionBad, "task_xml_unexpected_node", "The generated task definition contains an unexpected XML element."},
		{0x80041317, "SCHED_E_NAMESPACE", StatusTaskDefinitionBad, "task_xml_namespace_invalid", "The generated task definition contains an invalid XML namespace."},
		{0x80041318, "SCHED_E_INVALIDVALUE", StatusTaskDefinitionBad, "task_xml_invalid_value", "The generated task definition contains a value that Windows does not accept."},
		{0x80041319, "SCHED_E_MISSINGNODE", StatusTaskDefinitionBad, "task_xml_missing_node", "The generated task definition is missing a required XML element."},
		{0x8004131A, "SCHED_E_MALFORMEDXML", StatusTaskDefinitionBad, "task_xml_malformed", "The generated task definition is not valid XML."},
		{0x8004131D, "SCHED_E_TOO_MANY_NODES", StatusTaskDefinitionBad, "task_xml_too_many_nodes", "The generated task definition repeats an XML element too many times."},
		{0x80041322, "SCHED_E_SERVICE_NOT_AVAILABLE", StatusRPCUnavailable, "task_scheduler_service_unavailable", "The Task Scheduler service is not available on the target."},
		{0x80041323, "SCHED_E_SERVICE_TOO_BUSY", StatusRPCUnavailable, "task_scheduler_service_busy", "The Task Scheduler service is busy. Retry the operation."},
		{0x80041328, "SCHED_E_START_ON_DEMAND", StatusInstallFailed, "task_start_on_demand_disabled", "The registered task does not allow an on-demand start."},
	}
	for _, spec := range specs {
		if containsHRESULT(lower, spec.code) {
			result := failure(spec.status, spec.key, stage, fmt.Sprintf("%s (0x%08X)", spec.symbol, spec.code), spec.detail, err)
			result.TaskSchedulerRPC = "error"
			result.RPCAuthLevel = "packet_privacy"
			var registrationErr *taskRegistrationError
			if errors.As(err, &registrationErr) {
				result.ErrorField = registrationErr.node
				result.ErrorValue = registrationErr.value
				result.ErrorLine = registrationErr.line
				result.ErrorColumn = registrationErr.column
			}
			return result, true
		}
	}
	return Result{}, false
}

func containsHRESULT(lower string, code uint32) bool {
	return strings.Contains(lower, fmt.Sprintf("0x%08x", code)) ||
		strings.Contains(lower, fmt.Sprintf("%d", int32(code))) ||
		strings.Contains(lower, fmt.Sprintf("%d", code))
}

func failure(status, key, stage, code, detail string, err error) Result {
	result := Result{
		Status:       status,
		ErrorKey:     key,
		FailureStage: stage,
		ErrorCode:    code,
		Detail:       detail,
	}
	if err != nil {
		result.TechnicalDetail = err.Error()
	}
	return result
}

// withRemoteContext adds safe, structured connection metadata to a failure
// without exposing the underlying SMB/RPC library error in the API response.
// TechnicalDetail remains server-side only and is emitted to the diagnostic log.
func withRemoteContext(result Result, req Request, adminShare, taskScheduler string) Result {
	if result.Authentication == "" {
		result.Authentication = authentication(req)
	}
	if result.AdminShare == "" {
		result.AdminShare = adminShare
	}
	if result.TaskSchedulerRPC == "" {
		result.TaskSchedulerRPC = taskScheduler
	}
	if result.RPCAuthLevel == "" && taskScheduler != "" {
		result.RPCAuthLevel = "packet_privacy"
	}
	return result
}

func classifyInstallerFailure(detail string) Result {
	detail = strings.TrimSpace(detail)
	err := errors.New(detail)
	if detail == "" {
		err = errors.New("installer reported failure without detail")
	}
	lower := strings.ToLower(detail)
	switch {
	case strings.Contains(lower, "sha-256 verification failed"):
		return failure(StatusInstallFailed, "deployment_kit_integrity_failed", "installer", "", "The Deployment Kit failed its SHA-256 integrity check on the target.", err)
	case strings.Contains(lower, "installdeploymentkit.bat not found"):
		return failure(StatusInstallFailed, "deployment_kit_installer_missing", "installer", "", "InstallDeploymentKit.bat was not found in the Deployment Kit.", err)
	case strings.Contains(lower, "installdeploymentkit.bat exit code"):
		code := strings.TrimSpace(detail[strings.LastIndex(lower, "exit code")+len("exit code"):])
		if code == "" {
			code = "unknown"
		}
		return failure(StatusInstallFailed, "deployment_kit_installer_failed", "installer", "INSTALLER_EXIT_CODE ("+code+")", "The official Deployment Kit installer exited unsuccessfully.", err)
	case strings.Contains(lower, "veeamdeploysvc was not found"):
		return failure(StatusInstallFailed, "veeam_deployment_service_not_found", "service_verification", "", "The installer completed, but VeeamDeploySvc was not installed.", err)
	case strings.Contains(lower, "veeamdeploysvc status is"):
		return failure(StatusInstallFailed, "veeam_deployment_service_not_ready", "service_verification", "", "The installer completed, but VeeamDeploySvc is not running.", err)
	default:
		return failure(StatusInstallFailed, "deployment_kit_installer_failed", "installer", "", "The official Deployment Kit installer reported a failure.", err)
	}
}

func isTaskRegistrationAccessDenied(lower string) bool {
	return strings.Contains(lower, "0x00000005") ||
		strings.Contains(lower, "code: 0x5") ||
		strings.Contains(lower, "error_access_denied") ||
		strings.Contains(lower, "access denied")
}

func tcpProbe(ctx context.Context, host string, port int) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return err
	}
	return conn.Close()
}

func readFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func fileSHA256(name string) (string, error) {
	data, err := readFile(name)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func randomID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func taskXML(scriptPath string) string {
	return fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Principals><Principal id=\"Author\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><AllowStartOnDemand>true</AllowStartOnDemand><ExecutionTimeLimit>PT30M</ExecutionTimeLimit></Settings><Actions Context=\"Author\"><Exec><Command>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Command><Arguments>-NoProfile -ExecutionPolicy Bypass -File \"%s\"</Arguments></Exec></Actions></Task>", scriptPath)
}

func probeTaskXML() string {
	// ServiceAccount is a valid SchRpcRegisterTask logonType parameter, but it
	// is NOT a valid value for the task XML Principal.LogonType element. The
	// MS-TSCH server applies logonType=TASK_LOGON_SERVICE_ACCOUNT to this
	// LocalSystem principal after validating the XML definition.
	return "<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Principals><Principal id=\"Author\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT1M</ExecutionTimeLimit></Settings><Actions Context=\"Author\"><Exec><Command>C:\\Windows\\System32\\cmd.exe</Command><Arguments>/c exit 0</Arguments></Exec></Actions></Task>"
}

func serviceProbeScript(remoteDir, taskName string) string {
	return fmt.Sprintf("$ErrorActionPreference = 'Stop'\n$result = Join-Path $env:windir 'Temp\\%s\\result.json'\n$utf8NoBom = New-Object System.Text.UTF8Encoding($false)\n$serviceName = 'VeeamDeploySvc'\n$serviceStatus = 'NotFound'\n$ready = $false\ntry {\n  $svc = Get-Service -Name $serviceName -ErrorAction Stop\n  $serviceName = $svc.Name\n  $serviceStatus = [string]$svc.Status\n  $ready = ($serviceStatus -eq 'Running')\n} catch {}\n$json = @{ok=$ready; serviceName=$serviceName; serviceStatus=$serviceStatus} | ConvertTo-Json -Compress\n[System.IO.File]::WriteAllText($result, $json, $utf8NoBom)\ntry { schtasks.exe /Delete /TN '\\%s' /F | Out-Null } catch {}\n", remoteDir, taskName)
}

func powershellScript(remoteDir, expectedSHA string, taskNames ...string) string {
	taskName := ""
	if len(taskNames) > 0 {
		taskName = taskNames[0]
	}
	zipPath := fmt.Sprintf("$zip = Join-Path $env:windir 'Temp\\%s\\deployment-kit.zip'\n", path.Base(remoteDir))
	installDir := fmt.Sprintf("$dir = Join-Path $env:windir 'Temp\\%s\\expanded'\n", path.Base(remoteDir))
	hashCheck := ""
	if expectedSHA != "" {
		hashCheck = fmt.Sprintf("$actual = Get-AgentBridgeSHA256 $zip\nif ($actual -ne '%s') { Write-Result ((@{ok=$false; detail='SHA-256 verification failed'} | ConvertTo-Json -Compress)); exit 1 }\n", strings.ToUpper(expectedSHA))
	}
	return "$ErrorActionPreference = 'Stop'\n" + zipPath + installDir + "$result = Join-Path (Split-Path $zip) 'result.json'\n$utf8NoBom = New-Object System.Text.UTF8Encoding($false)\nfunction Write-Result([string]$json) { [System.IO.File]::WriteAllText($result, $json, $utf8NoBom) }\nfunction Get-AgentBridgeSHA256([string]$path) {\n  $stream = [System.IO.File]::OpenRead($path)\n  $sha = [System.Security.Cryptography.SHA256]::Create()\n  try { return ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '') } finally { $sha.Dispose(); $stream.Dispose() }\n}\n" + hashCheck + "try {\n  New-Item -ItemType Directory -Force $dir | Out-Null\n  Add-Type -AssemblyName System.IO.Compression.FileSystem\n  [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $dir)\n  $bat = Get-ChildItem -LiteralPath $dir -Filter 'InstallDeploymentKit.bat' -Recurse | Select-Object -First 1\n  if (-not $bat) { throw 'InstallDeploymentKit.bat not found in deployment kit' }\n  Push-Location $bat.DirectoryName\n  & cmd.exe /c $bat.FullName\n  Pop-Location\n  if ($LASTEXITCODE -ne 0) { throw \"InstallDeploymentKit.bat exit code $LASTEXITCODE\" }\n  $svcDeadline = [DateTime]::UtcNow.AddSeconds(30)\n  do {\n    $svc = Get-Service -Name 'VeeamDeploySvc' -ErrorAction SilentlyContinue\n    if ($svc -and [string]$svc.Status -eq 'Running') { break }\n    Start-Sleep -Seconds 1\n  } while ([DateTime]::UtcNow -lt $svcDeadline)\n  if (-not $svc) { throw 'VeeamDeploySvc was not found after installation' }\n  if ([string]$svc.Status -ne 'Running') { throw \"VeeamDeploySvc status is $($svc.Status)\" }\n  Write-Result ((@{ok=$true; serviceName=$svc.Name; serviceStatus=[string]$svc.Status} | ConvertTo-Json -Compress))\n} catch {\n  try { Pop-Location } catch {}\n  Write-Result ((@{ok=$false; detail=$_.Exception.Message} | ConvertTo-Json -Compress))\n}\ntry { schtasks.exe /Delete /TN '\\" + taskName + "' /F | Out-Null } catch {}\n"
}
