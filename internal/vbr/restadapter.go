package vbr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Coku2015/agentbridge/internal/security"
)

// APIRevisionBaseline is the VBR REST API revision AgentBridge is coded against.
// It is sent as the required `x-api-version` header on every /api/v1 call. We
// target 1.3-rev2 (the first rev whose CreateDeploymentKitSpec exposes
// includeLinuxPackages — the correct way to request a Linux-only Kit). VBR serves
// this contract on any 1.3-rev2 build; min-supported build for the kit-payload
// flow is therefore 1.3-rev2 (the package/PG/rescan/task endpoints first appear
// in 1.3-rev0, but a clean Linux Kit needs rev2).
const APIRevisionBaseline = "1.3-rev2"

const (
	temporaryPackageGroupPrefix = "AgentBridge temporary package source "
	maxLoggedVBRResponseBytes   = 16 << 10
)

// Credentials carries memory-only VBR secrets supplied out-of-band (AB-FR-024).
// They are never logged, persisted, or placed on ConnectionConfig.
type Credentials struct {
	Password string
}

// RESTAdapter implements the VBR REST 1.3-rev2 client. Secrets (password,
// access/refresh tokens) are held only on the struct in memory and registered
// with the scrubber so they can never reach logs (Constitution red line 1).
//
// Only the US1 methods (Connect, ServerInfo, Capabilities, CaptureFingerprint)
// are implemented here; later stories add package/kit/PG operations.
type RESTAdapter struct {
	creds        Credentials
	scrubber     *security.Scrubber
	log          *slog.Logger
	httpc        *http.Client
	base         string
	apiVersion   string // sent as required x-api-version header; default APIRevisionBaseline
	accessToken  string // memory-only
	refreshToken string // memory-only
}

// NewRESTAdapter returns an adapter that will connect with the given (memory-only)
// credentials. scrubber MUST be the shared scrubber so secrets are scrubbed from
// logs/errors.
func NewRESTAdapter(creds Credentials, scrubber *security.Scrubber, log *slog.Logger) *RESTAdapter {
	if log == nil {
		log = slog.Default()
	}
	return &RESTAdapter{creds: creds, scrubber: scrubber, log: log, apiVersion: APIRevisionBaseline}
}

// CaptureFingerprint retrieves the VBR server certificate fingerprint WITHOUT
// trusting it — the explicit "show the operator" step of trust-on-first-use
// (AB-FR-022). The caller MUST require explicit confirmation before passing the
// returned value to Connect as PinnedTLSSHA256.
func (a *RESTAdapter) CaptureFingerprint(ctx context.Context, server string, port int) (string, error) {
	addr := netJoinHostPort(server, port)
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}
	cap, err := security.CaptureLeaf(addr, 10*time.Second)
	if err != nil {
		return "", err
	}
	return cap.Fingerprint, nil
}

// Connect authenticates to VBR via the OAuth2 resource-owner password grant
// (POST /api/oauth2/token). It REQUIRES cfg.PinnedTLSSHA256 to be set: TLS
// fingerprint pinning is mandatory (red line 3). The access/refresh tokens and
// password are kept memory-only and registered with the scrubber.
func (a *RESTAdapter) Connect(ctx context.Context, cfg ConnectionConfig) error {
	if cfg.PinnedTLSSHA256 == "" {
		return errors.New("vbr: TLS fingerprint not confirmed — call CaptureFingerprint and have the operator confirm before Connect")
	}
	a.base = fmt.Sprintf("https://%s", netJoinHostPort(cfg.Server, cfg.Port))
	a.httpc = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: security.PinnedTLSConfig(cfg.Server, cfg.PinnedTLSSHA256),
		},
	}

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", cfg.Username)
	form.Set("password", a.creds.Password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+"/api/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	started := time.Now()
	resp, err := a.httpc.Do(req)
	if err != nil {
		a.logHTTPError(http.MethodPost, "/api/oauth2/token", started, err, "")
		return redactErr(fmt.Errorf("vbr connect: %w", err))
	}
	raw, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		a.logHTTPError(http.MethodPost, "/api/oauth2/token", started, readErr, "")
		return fmt.Errorf("vbr connect: read token response: %w", readErr)
	}
	if closeErr != nil {
		a.logHTTPError(http.MethodPost, "/api/oauth2/token", started, closeErr, "")
		return fmt.Errorf("vbr connect: close token response: %w", closeErr)
	}
	if resp.StatusCode != http.StatusOK {
		detail := a.safeResponseBody(raw)
		a.logHTTPResponse(http.MethodPost, "/api/oauth2/token", started, resp.StatusCode, detail)
		if detail != "" {
			return fmt.Errorf("vbr connect: oauth2 token grant returned %s: %s", resp.Status, detail)
		}
		return fmt.Errorf("vbr connect: oauth2 token grant returned %s", resp.Status)
	}

	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil {
		a.logHTTPError(http.MethodPost, "/api/oauth2/token", started, err, "")
		return fmt.Errorf("vbr connect: decode token: %w", err)
	}
	if tok.AccessToken == "" {
		return errors.New("vbr connect: empty access token")
	}
	a.accessToken = tok.AccessToken
	a.refreshToken = tok.RefreshToken
	// Register every secret so the scrubber masks them from logs/errors.
	if a.scrubber != nil {
		a.scrubber.Add(a.creds.Password)
		a.scrubber.Add(a.accessToken)
		a.scrubber.Add(a.refreshToken)
	}
	a.logHTTPResponse(http.MethodPost, "/api/oauth2/token", started, resp.StatusCode, fmt.Sprintf("token issued; expires_in=%d", tok.ExpiresIn))
	return nil
}

// ServerInfo reports the connected VBR build from GET /api/v1/serverInfo
// (buildVersion, DNS name) and GET /api/v1/serverTime (server clock). Time is
// best-effort — a build without the endpoint still connects. The old
// serverCertificate reachability probe is covered by serverInfo itself.
func (a *RESTAdapter) ServerInfo(ctx context.Context) (ServerInfo, error) {
	if err := a.requireConnected(); err != nil {
		return ServerInfo{}, err
	}
	var raw struct {
		VBRID        string   `json:"vbrId"`
		Name         string   `json:"name"`
		BuildVersion string   `json:"buildVersion"`
		Patches      []string `json:"patches"`
		Platform     string   `json:"platform"`
	}
	if err := a.getJSON(ctx, "/api/v1/serverInfo", &raw); err != nil {
		return ServerInfo{}, redactErr(err)
	}
	var tm struct {
		ServerTime time.Time `json:"serverTime"`
		TimeZone   string    `json:"timeZone"`
		IANAZone   string    `json:"ianaTimeZoneId"`
	}
	if err := a.getJSON(ctx, "/api/v1/serverTime", &tm); err == nil && !tm.ServerTime.IsZero() {
		t := tm.ServerTime
		return ServerInfo{
			ProductVersion: raw.BuildVersion,
			Host:           raw.Name,
			VBRID:          raw.VBRID,
			Patches:        raw.Patches,
			ServerTime:     &t,
			TimeZone:       tm.TimeZone,
			IANAZone:       tm.IANAZone,
			Platform:       raw.Platform,
			APIRevision:    APIRevisionBaseline,
		}, nil
	}
	return ServerInfo{
		ProductVersion: raw.BuildVersion,
		Host:           raw.Name,
		VBRID:          raw.VBRID,
		Patches:        raw.Patches,
		Platform:       raw.Platform,
		APIRevision:    APIRevisionBaseline,
	}, nil
}

// Capabilities reports which REST operations the connected build exposes. A
// false value MUST disable the corresponding UI path (AB-FR-023). GET-probable
// endpoints are probed live; POST-only operations are flagged true on the frozen
// baseline (research R2/R3 confirmed they exist in 1.3-rev2).
func (a *RESTAdapter) Capabilities(ctx context.Context) (Capabilities, error) {
	if err := a.requireConnected(); err != nil {
		return Capabilities{}, err
	}
	caps := Capabilities{
		// Baseline-supported POST-only / id-scoped operations (confirmed in plan.md).
		DeploymentKit:      true,
		ProtectionGroup:    true,
		Rescan:             true,
		Session:            true,
		DiscoveredEntities: true,
	}
	// Live-probe the GET-able collection endpoint.
	if err := a.probeOK(ctx, "/api/v1/agents/packages/linux"); err == nil {
		caps.AgentPackages = true
	}
	return caps, nil
}

// requireConnected returns an error if Connect has not succeeded.
func (a *RESTAdapter) requireConnected() error {
	if a.httpc == nil || a.accessToken == "" {
		return errors.New("vbr: not connected — call Connect first")
	}
	return nil
}

// getJSON performs an authenticated GET and decodes into out (may be nil).
func (a *RESTAdapter) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+path, nil)
	if err != nil {
		return err
	}
	a.attachAuth(req)
	started := time.Now()
	resp, err := a.httpc.Do(req)
	if err != nil {
		a.logHTTPError(http.MethodGet, path, started, err, "")
		return err
	}
	raw, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		a.logHTTPError(http.MethodGet, path, started, readErr, "")
		return readErr
	}
	if closeErr != nil {
		a.logHTTPError(http.MethodGet, path, started, closeErr, "")
		return closeErr
	}
	if resp.StatusCode >= 400 {
		detail := a.safeResponseBody(raw)
		a.logHTTPResponse(http.MethodGet, path, started, resp.StatusCode, detail)
		if detail != "" {
			return fmt.Errorf("vbr GET %s: %s: %s", path, resp.Status, detail)
		}
		return fmt.Errorf("vbr GET %s: %s", path, resp.Status)
	}
	a.logHTTPResponse(http.MethodGet, path, started, resp.StatusCode, "")
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// probeOK returns nil if the endpoint responds < 400 (capability present).
func (a *RESTAdapter) probeOK(ctx context.Context, path string) error {
	return a.getJSON(ctx, path, nil)
}

// --- US5: Protection Group create / rescan / session / discovered (FR-029/030). ---
//
// These concrete methods satisfy pg.Client structurally (pg names pg.Client, never
// *RESTAdapter — SOLID-D). They target the frozen 1.3-rev2 baseline; exact async
// response fields are confirmed against the lab build in T069. Protection Group
// names are exclusive; existing groups are never reused or mutated.

// FindByName returns the id of a Protection Group with the given name, or
// ("", false, nil). The caller uses this as a name-conflict preflight. Satisfies
// pg.Client structurally.
func (a *RESTAdapter) FindByName(ctx context.Context, name string) (string, bool, error) {
	if err := a.requireConnected(); err != nil {
		return "", false, err
	}
	var resp struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := a.getJSON(ctx, "/api/v1/agents/protectionGroups", &resp); err != nil {
		return "", false, redactErr(err)
	}
	for _, pg := range resp.Data {
		if strings.EqualFold(strings.TrimSpace(pg.Name), strings.TrimSpace(name)) {
			return pg.ID, true, nil
		}
	}
	return "", false, nil
}

// CreateProtectionGroup submits a certificate-based Individual Computers PG per
// the 1.3-rev2 OpenAPI (IndividualComputersProtectionGroupSpec) and returns the
// async session reference to poll. Every computer is enrolled with
// connectionType "Certificate" — the deployment-kit pairing — so no credentials
// record is ever referenced.
func (a *RESTAdapter) CreateProtectionGroup(ctx context.Context, s ProtectionGroupSpec) (SessionRef, error) {
	if err := a.requireConnected(); err != nil {
		return SessionRef{}, err
	}
	desc := s.Description
	if desc == "" {
		desc = "Created by AgentBridge"
	}
	computers := make([]map[string]any, 0, len(s.Computers))
	for _, c := range s.Computers {
		computers = append(computers, map[string]any{
			"hostName":       c.HostName,
			"connectionType": "Certificate", // EIndividualComputerConnectionType
		})
	}
	body := map[string]any{
		"name":        s.Name,
		"description": desc, // REQUIRED by ProtectionGroupSpec
		"type":        "IndividualComputers",
		"computers":   computers,
		// VBR distributes the Agent package to discovered computers through the
		// deployment service the kit installed — exactly the enrollment model.
		"options": map[string]any{"installBackupAgent": true},
	}
	raw, err := a.postJSON(ctx, "/api/v1/agents/protectionGroups", body)
	if err != nil {
		return SessionRef{}, redactErr(fmt.Errorf("create protection group: %w", err))
	}
	return sessionRefFrom(raw, "create protection group"), nil
}

// RescanProtectionGroup triggers a rescan of the PG and returns its session ref.
func (a *RESTAdapter) RescanProtectionGroup(ctx context.Context, id string) (SessionRef, error) {
	if err := a.requireConnected(); err != nil {
		return SessionRef{}, err
	}
	raw, err := a.postJSON(ctx, "/api/v1/agents/protectionGroups/"+id+"/rescan", nil)
	if err != nil {
		return SessionRef{}, redactErr(fmt.Errorf("rescan protection group: %w", err))
	}
	return sessionRefFrom(raw, "rescan protection group"), nil
}

// GetSession polls an async session's state (AB-FR-186). Protection Group
// create/rescan/delete operations return an Infrastructure session, which is
// exposed by the generic Sessions endpoint (not Automation). Field names
// follow the 1.3-rev2 SessionModel: lifecycle `state` (ESessionState), outcome
// `result` (ESessionResult) and progress `progressPercent`.
func (a *RESTAdapter) GetSession(ctx context.Context, id string) (SessionState, error) {
	if err := a.requireConnected(); err != nil {
		return SessionState{}, err
	}
	var resp struct {
		State    string          `json:"state"`
		Result   json.RawMessage `json:"result"`
		Progress int             `json:"progressPercent"`
	}
	if err := a.getJSON(ctx, "/api/v1/sessions/"+url.PathEscape(id), &resp); err != nil {
		return SessionState{}, redactErr(err)
	}
	result, message := sessionResultFields(resp.Result)
	var failures []SessionFailure
	if strings.EqualFold(result, "Failed") {
		var taskErr error
		failures, taskErr = a.getSessionTaskFailures(ctx, id)
		if taskErr != nil {
			a.log.Warn("vbr child task session failure logs unavailable", "session_id", id, "error", redactErr(taskErr))
		}
		if len(failures) > 0 {
			message = joinSessionFailureMessages(failures)
		} else if logMessage, err := a.getSessionFailureMessage(ctx, id); err != nil {
			// The status endpoint remains authoritative for terminality. Failure to
			// read the optional detail endpoint must not turn a completed VBR
			// session into an AgentBridge polling/transport error.
			a.log.Warn("vbr session failure logs unavailable", "session_id", id, "error", redactErr(err))
		} else if logMessage != "" {
			message = logMessage
		}
	}
	if (strings.EqualFold(resp.State, "Stopped") || strings.EqualFold(result, "Failed")) && a.log != nil {
		loggedMessage := message
		if a.scrubber != nil {
			loggedMessage = a.scrubber.Scrub(loggedMessage)
		}
		attrs := []any{"session_id", id, "state", resp.State, "result", result, "progress", resp.Progress, "failed_hosts", len(failures)}
		if loggedMessage != "" {
			attrs = append(attrs, "vbr_message", loggedMessage)
		}
		if strings.EqualFold(result, "Failed") {
			a.log.Warn("vbr session completed with failure", attrs...)
		} else {
			a.log.Info("vbr session completed", attrs...)
		}
	}
	return SessionState{
		State:    resp.State,
		Result:   result,
		Message:  message,
		Failures: failures,
		Progress: resp.Progress,
	}, nil
}

// getSessionTaskFailures maps each failed child task session to the machine name
// (normally its host/IP) and the exact failed log records shown by VBR.
func (a *RESTAdapter) getSessionTaskFailures(ctx context.Context, sessionID string) ([]SessionFailure, error) {
	var resp struct {
		Data []struct {
			ID     string          `json:"id"`
			Name   string          `json:"name"`
			Result json.RawMessage `json:"result"`
		} `json:"data"`
	}
	path := "/api/v1/sessions/" + url.PathEscape(sessionID) + "/taskSessions?limit=200"
	if err := a.getJSON(ctx, path, &resp); err != nil {
		return nil, err
	}

	failures := make([]SessionFailure, 0)
	var firstErr error
	for _, task := range resp.Data {
		if task.ID == "" {
			continue
		}
		result, _ := sessionResultFields(task.Result)
		if result != "" && !strings.EqualFold(result, "Failed") {
			continue
		}
		message, err := a.getFailureLogMessage(ctx, "/api/v1/taskSessions/"+url.PathEscape(task.ID)+"/logs?statusFilter=Failed")
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if message == "" {
			continue
		}
		failures = mergeSessionFailure(failures, SessionFailure{Host: task.Name, Message: message})
	}
	if len(failures) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return failures, nil
}

// getSessionFailureMessage reads the same failed session-log records VBR shows
// in its session details view. The parent SessionResultModel.message is often
// only "Rescan failed, check session log for details"; the actual host error is
// exposed by this endpoint instead.
func (a *RESTAdapter) getSessionFailureMessage(ctx context.Context, id string) (string, error) {
	return a.getFailureLogMessage(ctx, "/api/v1/sessions/"+url.PathEscape(id)+"/logs?statusFilter=Failed")
}

func (a *RESTAdapter) getFailureLogMessage(ctx context.Context, path string) (string, error) {
	var resp struct {
		Records []struct {
			Status      string `json:"status"`
			Title       string `json:"title"`
			Description string `json:"description"`
		} `json:"records"`
	}
	if err := a.getJSON(ctx, path, &resp); err != nil {
		return "", err
	}

	messages := make([]string, 0, len(resp.Records))
	seen := make(map[string]struct{}, len(resp.Records)*2)
	for _, record := range resp.Records {
		if record.Status != "" && !strings.EqualFold(record.Status, "Failed") {
			continue
		}
		for _, candidate := range []string{record.Title, record.Description} {
			if genericSessionLogText(candidate) {
				continue
			}
			if _, ok := seen[candidate]; ok {
				continue
			}
			seen[candidate] = struct{}{}
			messages = append(messages, candidate)
		}
	}
	return strings.Join(messages, "\n"), nil
}

func mergeSessionFailure(failures []SessionFailure, next SessionFailure) []SessionFailure {
	for i := range failures {
		if strings.EqualFold(strings.TrimSpace(failures[i].Host), strings.TrimSpace(next.Host)) {
			for _, existing := range strings.Split(failures[i].Message, "\n") {
				if existing == next.Message {
					return failures
				}
			}
			failures[i].Message += "\n" + next.Message
			return failures
		}
	}
	return append(failures, next)
}

func joinSessionFailureMessages(failures []SessionFailure) string {
	messages := make([]string, 0, len(failures))
	for _, failure := range failures {
		if failure.Message != "" {
			messages = append(messages, failure.Message)
		}
	}
	return strings.Join(messages, "\n")
}

// genericSessionLogText removes VBR's summary/instruction rows while retaining
// the original wording of every concrete failure record.
func genericSessionLogText(text string) bool {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return true
	}
	lower := strings.ToLower(trimmed)
	if strings.Contains(lower, "check session log for details") ||
		strings.Contains(lower, "check the session log for details") ||
		strings.HasPrefix(lower, "processing finished with error") ||
		strings.HasPrefix(lower, "job finished with error") ||
		strings.HasPrefix(lower, "session finished with error") {
		return true
	}
	return lower == "failed" || lower == "failure" || lower == "error"
}

// GetDiscoveredEntities reads the hosts discovered in a PG (AB-FR-187).
func (a *RESTAdapter) GetDiscoveredEntities(ctx context.Context, pgID string) ([]DiscoveredEntity, error) {
	if err := a.requireConnected(); err != nil {
		return nil, err
	}
	var resp struct {
		Data []struct {
			Host                string `json:"name"`
			State               string `json:"state"`
			LegacyOnline        *bool  `json:"isOnline"`
			AgentStatus         string `json:"agentStatus"`
			LegacyAgentStatus   string `json:"status"`
			AgentVersion        string `json:"agentVersion"`
			LastConnected       string `json:"lastConnected"`
			LegacyLastConnected string `json:"lastContact"`
		} `json:"data"`
	}
	if err := a.getJSON(ctx, "/api/v1/agents/protectionGroups/"+pgID+"/discoveredEntities", &resp); err != nil {
		return nil, redactErr(err)
	}
	out := make([]DiscoveredEntity, 0, len(resp.Data))
	for _, d := range resp.Data {
		online := strings.EqualFold(strings.TrimSpace(d.State), "Online")
		if d.LegacyOnline != nil {
			online = *d.LegacyOnline
		}
		agentStatus := strings.TrimSpace(d.AgentStatus)
		if agentStatus == "" {
			agentStatus = strings.TrimSpace(d.LegacyAgentStatus)
		}
		lastConnected := strings.TrimSpace(d.LastConnected)
		if lastConnected == "" {
			lastConnected = strings.TrimSpace(d.LegacyLastConnected)
		}
		out = append(out, DiscoveredEntity{
			Host:          d.Host,
			Online:        online,
			AgentStatus:   agentStatus,
			AgentVersion:  d.AgentVersion,
			LastConnected: lastConnected,
		})
		a.log.Info("vbr discovered entity decoded", "host", d.Host, "state", d.State, "online", online, "agent_status", agentStatus, "agent_version", d.AgentVersion, "last_connected", lastConnected)
	}
	return out, nil
}

// --- US2: Linux Agent package catalog (FR-007) ---

// ListLinuxAgentPackages lists the Linux Agent packages the connected VBR exposes
// (FR-007). Fields mirror the OpenAPI LinuxPackageModel
// {packageName, distributionName, packageBitness}; selected package content is
// exported by DownloadAgentPackages through the PreInstalledAgents workflow.
func (a *RESTAdapter) ListLinuxAgentPackages(ctx context.Context) ([]AgentPackage, error) {
	if err := a.requireConnected(); err != nil {
		return nil, err
	}
	var resp struct {
		Data []struct {
			Name         string `json:"packageName"`
			Distribution string `json:"distributionName"`
			Architecture string `json:"packageBitness"`
		} `json:"data"`
	}
	if err := a.getJSON(ctx, "/api/v1/agents/packages/linux", &resp); err != nil {
		return nil, redactErr(err)
	}
	out := make([]AgentPackage, 0, len(resp.Data))
	for _, p := range resp.Data {
		out = append(out, AgentPackage{
			Name: p.Name, Distribution: p.Distribution, Architecture: p.Architecture,
		})
	}
	return out, nil
}

// DownloadAgentPackages exports selected Linux Agent packages through VBR's
// PreInstalledAgents workflow. VBR does not expose a direct package URL. The
// supported REST path is:
//
//  1. create a temporary PreInstalledAgents protection group;
//  2. wait until VBR has saved that group;
//  3. POST /protectionGroups/{id}/packages with the selected package names;
//  4. delete the temporary group after the response body is closed.
//
// The returned reader owns that cleanup. Callers MUST close it, even after a
// read error. The archive can contain VBR's XML/readme metadata; the package
// store filters those files and keeps only the RPM/DEB payload.
func (a *RESTAdapter) DownloadAgentPackages(ctx context.Context, request PackageRequest) (io.ReadCloser, error) {
	if err := a.requireConnected(); err != nil {
		return nil, err
	}
	if len(request.PackageNames) == 0 {
		return nil, errors.New("vbr: download agent packages: at least one package name is required")
	}
	if len(request.PackageNames) > 200 {
		return nil, errors.New("vbr: download agent packages: too many package names")
	}
	format := strings.TrimSpace(request.Format)
	if format == "" {
		format = "Tar"
	}
	if !strings.EqualFold(format, "Tar") && !strings.EqualFold(format, "Zip") {
		return nil, fmt.Errorf("vbr: download agent packages: unsupported format %q", format)
	}
	if strings.EqualFold(format, "Tar") {
		format = "Tar"
	} else {
		format = "Zip"
	}

	name := temporaryPackageGroupName()
	a.log.Info("agent package export started", "packages", request.PackageNames, "format", format, "temporary_group", name)
	created, err := a.postJSON(ctx, "/api/v1/agents/protectionGroups", map[string]any{
		"name":        name,
		"description": "Temporary AgentBridge package source; removed after download",
		"type":        "PreInstalledAgents",
	})
	if err != nil {
		a.log.Error("agent package export failed", "stage", "create_temporary_group", "temporary_group", name, "error", err)
		return nil, redactErr(fmt.Errorf("create temporary package group: %w", err))
	}
	createRef := sessionRefFrom(created, "create temporary package group")
	if createRef.ID == "" {
		a.log.Error("agent package export failed", "stage", "create_temporary_group", "temporary_group", name, "error", "response had no session id")
		_ = a.removeTemporaryPackageGroup(name)
		return nil, errors.New("vbr: create temporary package group: response had no session id")
	}
	a.log.Info("agent package temporary group create accepted", "temporary_group", name, "session_id", createRef.ID)
	if err := a.waitSession(ctx, createRef.ID, "create temporary package group"); err != nil {
		a.log.Error("agent package export failed", "stage", "wait_create_session", "temporary_group", name, "session_id", createRef.ID, "error", err)
		_ = a.removeTemporaryPackageGroup(name)
		return nil, err
	}
	a.log.Info("agent package temporary group ready", "temporary_group", name, "session_id", createRef.ID)

	pgID, found, err := a.FindByName(ctx, name)
	if err != nil {
		a.log.Error("agent package export failed", "stage", "find_temporary_group", "temporary_group", name, "error", err)
		_ = a.removeTemporaryPackageGroup(name)
		return nil, redactErr(fmt.Errorf("find temporary package group: %w", err))
	}
	if !found || pgID == "" {
		a.log.Error("agent package export failed", "stage", "find_temporary_group", "temporary_group", name, "error", "created group was not found")
		_ = a.removeTemporaryPackageGroup(name)
		return nil, errors.New("vbr: temporary package group was created but could not be found")
	}
	a.log.Info("agent package temporary group resolved", "temporary_group", name, "protection_group_id", pgID)

	body := map[string]any{
		"format": format,
		"linuxPackages": map[string]any{
			"include":      true,
			"packageNames": request.PackageNames,
		},
	}
	stream, err := a.postBinary(ctx, "/api/v1/agents/protectionGroups/"+url.PathEscape(pgID)+"/packages", body)
	if err != nil {
		a.log.Error("agent package export failed", "stage", "download_archive", "temporary_group", name, "protection_group_id", pgID, "error", err)
		_ = a.removeTemporaryPackageGroupByID(pgID)
		return nil, redactErr(fmt.Errorf("download agent packages: %w", err))
	}
	a.log.Info("agent package archive stream opened", "temporary_group", name, "protection_group_id", pgID)

	return &cleanupReadCloser{
		body: stream,
		cleanup: func() {
			// The archive is complete at this point. Keep VBR cleanup entirely
			// outside the package read path so a slow DELETE/session poll cannot
			// delay caching or turn valid package bytes into a failed download.
			a.cleanupTemporaryPackageGroup(name, pgID)
		},
	}, nil
}

// cleanupTemporaryPackageGroup removes the temporary source PG in the
// background. Every attempt gets a fresh cleanup timeout; package bytes that
// reached EOF remain valid regardless of the remote cleanup outcome.
func (a *RESTAdapter) cleanupTemporaryPackageGroup(name, pgID string) {
	go func() {
		for attempt, delay := range []time.Duration{0, 2 * time.Second, 5 * time.Second} {
			if delay > 0 {
				time.Sleep(delay)
			}
			if attempt == 0 {
				a.log.Info("agent package temporary group cleanup started", "temporary_group", name, "protection_group_id", pgID)
			}
			err := a.removeTemporaryPackageGroupByID(pgID)
			if err == nil || temporaryProtectionGroupMissing(err) {
				a.log.Info("agent package temporary group cleanup completed", "temporary_group", name, "protection_group_id", pgID, "attempt", attempt+1)
				return
			}
			a.log.Error("agent package temporary group cleanup attempt failed", "temporary_group", name, "protection_group_id", pgID, "attempt", attempt+1, "error", err)
		}
		a.log.Error("agent package temporary group cleanup retries exhausted", "temporary_group", name, "protection_group_id", pgID)
	}()
}

func temporaryProtectionGroupMissing(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "404 not found") || strings.Contains(text, "status 404")
}

// waitSession waits for the Infrastructure session returned by create/delete
// Protection Group operations. It intentionally accepts Warning as completion;
// the package endpoint is the authoritative result for the actual download.
func (a *RESTAdapter) waitSession(ctx context.Context, id, label string) error {
	if id == "" {
		return fmt.Errorf("vbr: %s: empty session id", label)
	}
	deadline := time.Now().Add(5 * time.Minute)
	a.log.Info("vbr session polling started", "label", label, "session_id", id)
	for {
		state, err := a.GetSession(ctx, id)
		if err != nil {
			a.log.Error("vbr session polling failed", "label", label, "session_id", id, "error", err)
			return redactErr(fmt.Errorf("%s: poll session: %w", label, err))
		}
		a.log.Info("vbr session state", "label", label, "session_id", id, "state", state.State, "result", state.Result, "progress", state.Progress)
		if strings.EqualFold(state.State, "Stopped") {
			switch strings.ToLower(state.Result) {
			case "success", "warning":
				a.log.Info("vbr session polling completed", "label", label, "session_id", id, "result", state.Result)
				return nil
			default:
				a.log.Error("vbr session finished unsuccessfully", "label", label, "session_id", id, "result", state.Result)
				return fmt.Errorf("vbr: %s: session result %s", label, state.Result)
			}
		}
		if time.Now().After(deadline) {
			a.log.Error("vbr session polling timed out", "label", label, "session_id", id, "state", state.State, "progress", state.Progress)
			return fmt.Errorf("vbr: %s: session timed out (state %s)", label, state.State)
		}
		select {
		case <-ctx.Done():
			a.log.Error("vbr session polling canceled", "label", label, "session_id", id, "error", ctx.Err())
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// sessionResultFields accepts both the string-shaped result emitted by older VBR
// builds and the SessionResultModel object used by the 1.3-rev2 OpenAPI. The
// message is VBR's own operator-facing outcome and must not be discarded: for a
// failed Protection Group rescan it carries the reason shown by the VBR console.
func sessionResultFields(raw json.RawMessage) (resultText, message string) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", ""
	}
	var text string
	if raw[0] == '"' && json.Unmarshal(raw, &text) == nil {
		return text, ""
	}
	var result struct {
		Result  string `json:"result"`
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &result) == nil {
		return result.Result, result.Message
	}
	return "", ""
}

func (a *RESTAdapter) deleteProtectionGroup(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	raw, err := a.deleteJSON(ctx, "/api/v1/agents/protectionGroups/"+url.PathEscape(id))
	if err != nil {
		return redactErr(fmt.Errorf("delete temporary package group: %w", err))
	}
	if ref := sessionRefFrom(raw, "delete temporary package group"); ref.ID != "" {
		return a.waitSession(ctx, ref.ID, "delete temporary package group")
	}
	return nil
}

func (a *RESTAdapter) removeTemporaryPackageGroup(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	id, found, err := a.FindByName(ctx, name)
	if err != nil || !found || id == "" {
		return err
	}
	return a.deleteProtectionGroup(ctx, id)
}

func (a *RESTAdapter) removeTemporaryPackageGroupByID(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return a.deleteProtectionGroup(ctx, id)
}

func temporaryPackageGroupName() string {
	return fmt.Sprintf("%s%d", temporaryPackageGroupPrefix, time.Now().UTC().UnixNano())
}

// --- US2: Deployment Kit generate + download (FR-011/012/013) ---

// CreateDeploymentKit submits Kit generation and returns the async task reference
// to poll/download (FR-011). Kit generation is the single-active-per-VBR operation
// guarded by deploymentkit.Manager (R8/R9).
func (a *RESTAdapter) CreateDeploymentKit(ctx context.Context, req KitRequest) (TaskRef, error) {
	if err := a.requireConnected(); err != nil {
		return TaskRef{}, err
	}
	// Explicitly send platform flags because VBR defaults differ between builds.
	// The public AgentBridge default is a combined Windows + Linux Kit.
	if !req.IncludeWindowsPackages && !req.IncludeLinuxPackages && !req.IncludeUnixPackages {
		req.IncludeWindowsPackages = true
		req.IncludeLinuxPackages = true
	}
	body := map[string]any{
		"includeLinuxPackages":   req.IncludeLinuxPackages,
		"includeWindowsPackages": req.IncludeWindowsPackages,
		"includeUnixPackages":    req.IncludeUnixPackages,
	}
	validityHours := req.ValidityHours
	if validityHours <= 0 {
		validityHours = 720
	}
	body["validityPeriodHours"] = validityHours
	raw, err := a.postJSON(ctx, "/api/v1/deployment/generateKit", body)
	if err != nil {
		return TaskRef{}, redactErr(fmt.Errorf("create deployment kit: %w", err))
	}
	for _, key := range []string{"id", "taskId", "sessionId"} {
		if v, ok := raw[key].(string); ok && v != "" {
			return TaskRef{ID: v}, nil
		}
	}
	return TaskRef{}, redactErr(errors.New("create deployment kit: response had no task id"))
}

// WaitTask polls an async task (GET /api/v1/tasks/{id}) until it reaches a
// terminal state, then returns nil on Success/Warning or an error on
// Failed/Cancelled. Kit generation is async: downloadKit 400s if called while the
// task is still Working, so the campaign MUST wait before downloading (FR-012).
func (a *RESTAdapter) WaitTask(ctx context.Context, task TaskRef) error {
	if err := a.requireConnected(); err != nil {
		return err
	}
	if task.ID == "" {
		return errors.New("vbr: wait task: empty task id")
	}
	const (
		interval = 2 * time.Second
		timeout  = 5 * time.Minute
	)
	deadline := time.Now().Add(timeout)
	for {
		var t struct {
			ID      string `json:"id"`
			State   string `json:"state"`  // ETaskState: Starting|Working|Stopping|Stopped
			Result  string `json:"result"` // ETaskResult: None|Success|Warning|Failed|Cancelled
			Percent int    `json:"progressPercent"`
		}
		if err := a.getJSON(ctx, "/api/v1/tasks/"+task.ID, &t); err != nil {
			return redactErr(fmt.Errorf("wait task %s: %w", task.ID, err))
		}
		// ETaskState terminal = Stopped; outcome is in result.
		if strings.EqualFold(t.State, "Stopped") {
			switch strings.ToLower(t.Result) {
			case "success", "warning":
				return nil
			default:
				return redactErr(fmt.Errorf("wait task %s: result %s", task.ID, t.Result))
			}
		}
		if time.Now().After(deadline) {
			return redactErr(fmt.Errorf("wait task %s: timed out (state %s)", task.ID, t.State))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

// DownloadDeploymentKit streams the generated Kit bytes (FR-013). The caller MUST
// close the reader; deploymentkit.Manager writes it to a protected temp dir and
// deletes it on close/expire.
func (a *RESTAdapter) DownloadDeploymentKit(ctx context.Context, task TaskRef) (io.ReadCloser, error) {
	if err := a.requireConnected(); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+"/api/v1/deployment/"+task.ID+"/downloadKit", nil)
	if err != nil {
		return nil, err
	}
	a.attachAuth(req)
	resp, err := a.httpc.Do(req)
	if err != nil {
		return nil, redactErr(err)
	}
	if resp.StatusCode >= 400 {
		defer drainAndClose(resp.Body)
		return nil, fmt.Errorf("vbr download kit %s: %s", task.ID, resp.Status)
	}
	return resp.Body, nil
}

// postJSON performs an authenticated POST with a JSON body and returns the decoded
// raw response body for the caller to mine for a session/task reference.
func (a *RESTAdapter) postJSON(ctx context.Context, path string, body any) (map[string]any, error) {
	var payload io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+path, payload)
	if err != nil {
		return nil, err
	}
	a.attachAuth(req)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	started := time.Now()
	resp, err := a.httpc.Do(req)
	if err != nil {
		a.logHTTPError(http.MethodPost, path, started, err, "")
		return nil, err
	}
	raw, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		a.logHTTPError(http.MethodPost, path, started, readErr, "")
		return nil, readErr
	}
	if closeErr != nil {
		a.logHTTPError(http.MethodPost, path, started, closeErr, "")
		return nil, closeErr
	}
	if resp.StatusCode >= 400 {
		detail := a.safeResponseBody(raw)
		a.logHTTPResponse(http.MethodPost, path, started, resp.StatusCode, detail)
		if detail != "" {
			return nil, fmt.Errorf("vbr POST %s: %s: %s", path, resp.Status, detail)
		}
		return nil, fmt.Errorf("vbr POST %s: %s", path, resp.Status)
	}
	a.logHTTPResponse(http.MethodPost, path, started, resp.StatusCode, "")
	var out map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out) // best-effort; caller handles missing keys
	}
	return out, nil
}

// postBinary performs an authenticated JSON POST whose response is a binary
// stream. The caller owns the returned body and must close it.
func (a *RESTAdapter) postBinary(ctx context.Context, path string, body any) (io.ReadCloser, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	a.attachAuth(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/zip, application/x-tar, application/octet-stream")
	started := time.Now()
	resp, err := a.httpc.Do(req)
	if err != nil {
		a.logHTTPError(http.MethodPost, path, started, err, "")
		return nil, err
	}
	if resp.StatusCode >= 400 {
		raw, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil {
			a.logHTTPError(http.MethodPost, path, started, readErr, "")
			return nil, readErr
		}
		if closeErr != nil {
			a.logHTTPError(http.MethodPost, path, started, closeErr, "")
			return nil, closeErr
		}
		detail := a.safeResponseBody(raw)
		a.logHTTPResponse(http.MethodPost, path, started, resp.StatusCode, detail)
		if detail != "" {
			return nil, fmt.Errorf("vbr POST %s: %s: %s", path, resp.Status, detail)
		}
		return nil, fmt.Errorf("vbr POST %s: %s", path, resp.Status)
	}
	a.logHTTPResponse(http.MethodPost, path, started, resp.StatusCode, fmt.Sprintf(
		"stream content_type=%q content_disposition=%q content_encoding=%q content_length=%d",
		resp.Header.Get("Content-Type"),
		resp.Header.Get("Content-Disposition"),
		resp.Header.Get("Content-Encoding"),
		resp.ContentLength,
	))
	return resp.Body, nil
}

// deleteJSON performs an authenticated DELETE and decodes an optional JSON
// session response. VBR returns a deletion session for Protection Groups, but
// the helper also accepts a 204/no-body response for build compatibility.
func (a *RESTAdapter) deleteJSON(ctx context.Context, path string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, a.base+path, nil)
	if err != nil {
		return nil, err
	}
	a.attachAuth(req)
	started := time.Now()
	resp, err := a.httpc.Do(req)
	if err != nil {
		a.logHTTPError(http.MethodDelete, path, started, err, "")
		return nil, err
	}
	raw, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		a.logHTTPError(http.MethodDelete, path, started, readErr, "")
		return nil, readErr
	}
	if closeErr != nil {
		a.logHTTPError(http.MethodDelete, path, started, closeErr, "")
		return nil, closeErr
	}
	if resp.StatusCode >= 400 {
		detail := a.safeResponseBody(raw)
		a.logHTTPResponse(http.MethodDelete, path, started, resp.StatusCode, detail)
		if detail != "" {
			return nil, fmt.Errorf("vbr DELETE %s: %s: %s", path, resp.Status, detail)
		}
		return nil, fmt.Errorf("vbr DELETE %s: %s", path, resp.Status)
	}
	a.logHTTPResponse(http.MethodDelete, path, started, resp.StatusCode, "")
	var out map[string]any
	if len(raw) == 0 {
		return out, nil
	}
	_ = json.Unmarshal(raw, &out)
	return out, nil
}

// sessionRefFrom mines an async reference from a create/rescan response. VBR may
// return the reference inline (id/sessionId/taskId) or nested under a link; we
// accept any known key defensively and let the pg poll loop surface a real error
// if none resolves.
func sessionRefFrom(m map[string]any, label string) SessionRef {
	for _, key := range []string{"sessionId", "taskId", "id", "session"} {
		if v, ok := m[key].(string); ok && v != "" {
			return SessionRef{ID: v}
		}
	}
	return SessionRef{}
}

func (a *RESTAdapter) attachAuth(req *http.Request) {
	if a.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.accessToken)
	}
	req.Header.Set("Accept", "application/json")
	// x-api-version is required on every /api/v1 endpoint (OpenAPI
	// apiVersionParam). Omitting it makes VBR reject calls — this was the primary
	// cause of the 400 on Kit download.
	if a.apiVersion != "" {
		req.Header.Set("x-api-version", a.apiVersion)
	}
}

func (a *RESTAdapter) logHTTPResponse(method, path string, started time.Time, status int, detail string) {
	if a.log == nil {
		return
	}
	attrs := []any{
		"method", method,
		"path", path,
		"status", status,
		"duration_ms", time.Since(started).Milliseconds(),
	}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	if status >= 400 {
		a.log.Error("vbr response", attrs...)
		return
	}
	a.log.Info("vbr response", attrs...)
}

func (a *RESTAdapter) logHTTPError(method, path string, started time.Time, err error, detail string) {
	if a.log == nil {
		return
	}
	attrs := []any{
		"method", method,
		"path", path,
		"duration_ms", time.Since(started).Milliseconds(),
		"error", err,
	}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	a.log.Error("vbr request error", attrs...)
}

func (a *RESTAdapter) safeResponseBody(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	sanitized, err := security.SanitizeJSON(raw)
	if err != nil {
		sanitized = raw
	}
	text := strings.TrimSpace(string(sanitized))
	if len(text) > maxLoggedVBRResponseBytes {
		text = text[:maxLoggedVBRResponseBytes] + "…"
	}
	if a.scrubber != nil {
		text = a.scrubber.Scrub(text)
	}
	return text
}

// cleanupReadCloser couples the package response body to deletion of the
// temporary Protection Group. The response body is closed before cleanup and
// both actions run exactly once, including when a caller reads through EOF.
// Cleanup is deliberately best-effort: a remote PG deletion failure must not
// replace a successfully-read EOF or invalidate the downloaded package bytes.
type cleanupReadCloser struct {
	body    io.ReadCloser
	cleanup func()
	once    sync.Once
	bodyErr error
}

func (r *cleanupReadCloser) Read(p []byte) (int, error) {
	n, err := r.body.Read(p)
	if err == io.EOF {
		r.finish()
	}
	return n, err
}

func (r *cleanupReadCloser) Close() error {
	r.finish()
	return r.bodyErr
}

func (r *cleanupReadCloser) finish() {
	r.once.Do(func() {
		r.bodyErr = r.body.Close()
		if r.cleanup != nil {
			r.cleanup()
		}
	})
}

// redactErr ensures a scrubber-registered secret in an error string is masked.
func redactErr(err error) error {
	if err == nil {
		return nil
	}
	// Best-effort: the scrubber is applied at the logging boundary too; this is
	// a second line of defense for errors returned to the caller.
	return errors.New(security.NewScrubber().Scrub(err.Error()))
}

func drainAndClose(r io.ReadCloser) {
	_, _ = io.Copy(io.Discard, r)
	_ = r.Close()
}

// netJoinHostPort joins host and port without importing net (keeps deps lean).
func netJoinHostPort(host string, port int) string {
	return host + ":" + strconv.Itoa(port)
}
