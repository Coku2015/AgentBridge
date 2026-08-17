package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Coku2015/agentbridge/internal/bundle"
	"github.com/Coku2015/agentbridge/internal/executor"
	"github.com/Coku2015/agentbridge/internal/executor/templates"
	"github.com/Coku2015/agentbridge/internal/packages"
	"github.com/Coku2015/agentbridge/internal/probe"
	"github.com/Coku2015/agentbridge/internal/sshtransport"
)

// sshSession adapts *sshtransport.Client to executor.RemoteSession at the
// composition root. It lives here (not in sshtransport) so the executor never
// imports a concrete transport (frozen contract, SOLID-D).
type sshSession struct{ cl *sshtransport.Client }

func (s *sshSession) Run(ctx context.Context, cmd string) ([]byte, error) {
	return s.cl.Run(ctx, cmd)
}
func (s *sshSession) RunWithSecret(ctx context.Context, cmd string, secret []byte, requestPTY bool) ([]byte, error) {
	return s.cl.RunWithSecret(ctx, cmd, secret, requestPTY)
}
func (s *sshSession) Upload(ctx context.Context, r io.Reader, remotePath string) (string, error) {
	return s.cl.Upload(ctx, r, remotePath)
}
func (s *sshSession) Close() error { return s.cl.Close() }

// sshConnector dials a fresh client per Connect using memory-only creds + a
// pinned host key (red line 4).
type sshConnector struct{ cfg sshtransport.Config }

func (c *sshConnector) Connect(ctx context.Context) (executor.RemoteSession, error) {
	cl, err := sshtransport.Dial(ctx, c.cfg)
	if err != nil {
		return nil, err
	}
	return &sshSession{cl: cl}, nil
}

// sshAuthForCredential keeps the two Veeam credential types disjoint. When a
// private key is present, the account Password field belongs to sudo and must
// arrive through SudoPassword; it must never become an SSH password fallback.
func sshAuthForCredential(password string, privateKeyPEM []byte, passphrase string) sshtransport.Auth {
	if len(privateKeyPEM) > 0 {
		return sshtransport.Auth{PrivateKeyPEM: privateKeyPEM, Passphrase: passphrase}
	}
	return sshtransport.Auth{Password: password}
}

// registerInstall wires the SSH host-key capture + install endpoints (US4).
func registerInstall(mux *http.ServeMux, log *slog.Logger, dataDir string) {
	// POST /api/ssh/hostkey: capture the target host key WITHOUT trusting it
	// (AB-FR-121). Returns BOTH the fingerprint (shown to the operator for
	// confirmation) and the authorized-keys line (what /api/install pins after
	// confirmation — it must parse via ParseHostKey, a fingerprint does not).
	mux.HandleFunc("POST /api/ssh/hostkey", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		addr := body.Host + ":" + itoa(body.Port)
		key, err := sshtransport.CaptureHostKey(r.Context(), addr, 10*time.Second)
		if err != nil {
			writeSSHRemoteFailure(w, log, "host_key_capture", body.Host, body.Port, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"fingerprint": sshtransport.FingerprintSHA256(key),
			"hostKey":     sshtransport.AuthorizedKeyLine(key),
		})
	})

	// POST /api/ssh/probe: use the credentials currently being edited to read
	// Linux facts before the credential record is committed in the UI. The
	// response contains no secret and is immediately suitable for /api/match.
	mux.HandleFunc("POST /api/ssh/probe", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Host              string `json:"host"`
			Port              int    `json:"port"`
			User              string `json:"user"`
			Password          string `json:"password"`
			PrivateKeyPEM     string `json:"privateKeyPem"`
			Passphrase        string `json:"passphrase"`
			HostKey           string `json:"hostKey"`
			Privilege         string `json:"privilege"` // legacy root|sudo hint
			ElevatePrivileges *bool  `json:"elevatePrivileges"`
			SudoPassword      string `json:"sudoPassword"`
			AddToSudoers      bool   `json:"addToSudoers"`
			UseSuFallback     bool   `json:"useSuFallback"`
			RootPassword      string `json:"rootPassword"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if body.Host == "" || body.User == "" || body.HostKey == "" {
			http.Error(w, "host, user and confirmed host key are required", http.StatusBadRequest)
			return
		}
		pinned, err := sshtransport.ParseHostKey(body.HostKey)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid host key"})
			return
		}
		defer func() {
			body.Password = ""
			body.PrivateKeyPEM = ""
			body.Passphrase = ""
			body.SudoPassword = ""
			body.RootPassword = ""
		}()
		privateKeyPEM := []byte(body.PrivateKeyPEM)
		defer clearSecretBytes(privateKeyPEM)
		conn := &sshConnector{cfg: sshtransport.Config{
			Host:          body.Host,
			Port:          body.Port,
			User:          body.User,
			PinnedHostKey: pinned,
			Auth:          sshAuthForCredential(body.Password, privateKeyPEM, body.Passphrase),
		}}
		sess, err := conn.Connect(r.Context())
		if err != nil {
			writeSSHRemoteFailure(w, log, "system_probe_connect", body.Host, body.Port, err)
			return
		}
		defer sess.Close()
		privilege, err := executor.ResolvePrivilege(r.Context(), sess, executor.PrivilegeRequest{
			Elevate:       elevateRequested(body.Privilege, body.ElevatePrivileges),
			SudoPassword:  []byte(body.SudoPassword),
			AddToSudoers:  body.AddToSudoers,
			UseSuFallback: body.UseSuFallback,
			RootPassword:  []byte(body.RootPassword),
		})
		if err != nil {
			writeSSHRemoteFailure(w, log, "privilege_probe", body.Host, body.Port, err)
			return
		}
		res, err := probe.NewSSHProbe(sess).Probe(r.Context())
		if err != nil {
			writeSSHRemoteFailure(w, log, "system_probe", body.Host, body.Port, err)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			probe.Result
			Privilege executor.PrivilegeResult `json:"privilege"`
		}{Result: res, Privilege: privilege})
	})

	// POST /api/install: run Prepare→Install→Verify→Cleanup for one host. The
	// host key, password and private key are memory-only; the host key MUST be
	// confirmed (red line 4) — install refuses an empty one.
	mux.HandleFunc("POST /api/install", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Host              string `json:"host"`
			Port              int    `json:"port"`
			User              string `json:"user"`
			Password          string `json:"password"`      // memory-only
			PrivateKeyPEM     string `json:"privateKeyPem"` // memory-only
			Passphrase        string `json:"passphrase"`    // memory-only
			HostKey           string `json:"hostKey"`       // authorized-keys line, confirmed
			Privilege         string `json:"privilege"`     // legacy root|sudo hint
			ElevatePrivileges *bool  `json:"elevatePrivileges"`
			SudoPassword      string `json:"sudoPassword"` // connected account's sudo password
			AddToSudoers      bool   `json:"addToSudoers"`
			UseSuFallback     bool   `json:"useSuFallback"`
			RootPassword      string `json:"rootPassword"` // only sudoers/su
			KitPath           string `json:"kitPath"`      // local Deployment Kit — the install payload
			PackagePath       string `json:"packagePath"`  // cached VBR Agent artifact
			PackageID         string `json:"packageId"`    // selected VBR catalog entry
			ConfirmSelection  bool   `json:"confirmSelection"`
			DeploymentProfile string `json:"deploymentProfile"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if body.HostKey == "" {
			http.Error(w, "confirmed host key required (AB-FR-121)", http.StatusPreconditionRequired)
			return
		}
		pinned, err := sshtransport.ParseHostKey(body.HostKey)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid host key"})
			return
		}
		body.DeploymentProfile = strings.TrimSpace(body.DeploymentProfile)
		if body.DeploymentProfile == "" {
			body.DeploymentProfile = bundle.ProfileKitOnly
		}
		if !bundle.IsSupportedProfile(body.DeploymentProfile) {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":  "unsupported_deployment_profile",
				"detail": "Every supported installation profile must include Deployment Kit.",
			})
			return
		}
		if strings.TrimSpace(body.KitPath) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "deployment_kit_required"})
			return
		}
		if body.DeploymentProfile == bundle.ProfileAgentPlusKit && strings.TrimSpace(body.PackagePath) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "agent_package_required"})
			return
		}
		if body.DeploymentProfile == bundle.ProfileKitOnly && strings.TrimSpace(body.PackagePath) != "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "agent_package_not_allowed_for_kit_only"})
			return
		}
		// Clear request-body secrets immediately after extraction (memory-only).
		defer func() {
			body.Password = ""
			body.PrivateKeyPEM = ""
			body.Passphrase = ""
			body.SudoPassword = ""
			body.RootPassword = ""
		}()
		privateKeyPEM := []byte(body.PrivateKeyPEM)
		defer clearSecretBytes(privateKeyPEM)
		conn := &sshConnector{cfg: sshtransport.Config{
			Host:          body.Host,
			Port:          body.Port,
			User:          body.User,
			PinnedHostKey: pinned,
			Auth:          sshAuthForCredential(body.Password, privateKeyPEM, body.Passphrase),
		}}
		privilegeSession, err := conn.Connect(r.Context())
		if err != nil {
			writeSSHRemoteFailure(w, log, "install_connect", body.Host, body.Port, err)
			return
		}
		privilege, privilegeErr := executor.ResolvePrivilege(r.Context(), privilegeSession, executor.PrivilegeRequest{
			Elevate:       elevateRequested(body.Privilege, body.ElevatePrivileges),
			SudoPassword:  []byte(body.SudoPassword),
			AddToSudoers:  body.AddToSudoers,
			UseSuFallback: body.UseSuFallback,
			RootPassword:  []byte(body.RootPassword),
		})
		_ = privilegeSession.Close()
		if privilegeErr != nil {
			writeSSHRemoteFailure(w, log, "install_privilege", body.Host, body.Port, privilegeErr)
			return
		}
		baseConfig := executor.SSHExecutorConfig{
			Connector: conn,
			Privilege: templates.PrivRoot,
			KitPath:   body.KitPath,
		}
		base := executor.NewSSHExecutor(baseConfig)

		ctx := r.Context()
		selectedPackagePath := ""
		var selection packages.Selection
		if body.PackagePath != "" {
			probed, probeErr := base.Probe(ctx, executor.Target{Host: body.Host, Kind: executor.KindSSH})
			if probeErr != nil {
				writeSSHRemoteFailure(w, log, "package_selection_probe", body.Host, body.Port, probeErr)
				return
			}
			targetFacts, probeErr := probe.Import([]byte(probed.JSON))
			if probeErr != nil {
				writeJSON(w, http.StatusBadGateway, map[string]any{"error": "target probe decode failed", "detail": probeErr.Error()})
				return
			}
			initPackageStore(dataDir)
			if packageStoreErr != nil || packageStore == nil {
				detail := "package store unavailable"
				if packageStoreErr != nil {
					detail = packageStoreErr.Error()
				}
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "package selection unavailable", "detail": detail})
				return
			}
			selected, rec, selectErr := packageStore.SelectForTarget(body.PackagePath, body.PackageID, targetFacts)
			selection = rec
			if selectErr != nil {
				writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "no compatible Agent payload", "detail": selectErr.Error(), "probe": targetFacts, "packageSelection": selection})
				return
			}
			if selection.RequiresExplicitConfirmation && !body.ConfirmSelection {
				writeJSON(w, http.StatusConflict, map[string]any{"error": "explicit package selection confirmation required", "detail": strings.Join(selection.Warnings, "; "), "probe": targetFacts, "packageSelection": selection})
				return
			}
			selectedPackagePath = selected.Path
			defer os.Remove(selectedPackagePath)
			log.Info("target Agent package selection", "host", body.Host, "package", body.PackageID, "format", selection.TargetFormat, "architecture", selection.TargetArchitecture, "mode", selection.Mode, "selected", selection.Selected, "excluded", selection.Excluded, "warnings", selection.Warnings)
		}
		baseConfig.PackagePath = selectedPackagePath
		baseConfig.Privilege = privilege.Mode
		sudoSecret := []byte(body.SudoPassword)
		rootSecret := []byte(body.RootPassword)
		baseConfig.SudoPassword = sudoSecret
		baseConfig.RootPassword = rootSecret
		ex := executor.NewSSHExecutor(baseConfig)
		for i := range sudoSecret {
			sudoSecret[i] = 0
		}
		for i := range rootSecret {
			rootSecret[i] = 0
		}
		baseConfig.SudoPassword = nil
		baseConfig.RootPassword = nil
		defer ex.ClearSecrets()
		prep, err := ex.Prepare(ctx, executor.InstallPlan{KitPath: body.KitPath, DeploymentProfile: body.DeploymentProfile})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "prepare failed", "detail": err.Error()})
			return
		}
		// Staging cleanup is mandatory on every path after Prepare, including an
		// installer or verification failure. Use an independent bounded context
		// because the request may already have been cancelled.
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if cleanupErr := ex.Cleanup(cleanupCtx, executor.Target{Host: body.Host, Kind: executor.KindSSH}); cleanupErr != nil {
				log.Warn("install cleanup failed", "host", body.Host, "error", cleanupErr)
			}
		}()
		install, err := ex.Install(ctx, executor.InstallPlan{KitPath: body.KitPath, DeploymentProfile: body.DeploymentProfile})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "install failed", "detail": err.Error()})
			return
		}
		verify, err := ex.Verify(ctx, executor.Target{Host: body.Host, Kind: executor.KindSSH})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "verify failed", "detail": err.Error()})
			return
		}
		install.DeploymentKitReady = linuxDeploymentKitReady(verify)
		if !install.DeploymentKitReady {
			log.Warn("linux deployment kit verification failed",
				"host", body.Host,
				"package_version", verify.DeploymentKitVersion,
				"service_status", verify.DeployerStatus,
			)
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error":    "deployment_kit_verification_failed",
				"verified": verify,
			})
			return
		}
		if selectedPackagePath != "" {
			install.PackageInstalled = verify.PackageVersion != ""
			install.LocalAgentHealthy = verify.AgentStatus == "active"
			if !install.PackageInstalled {
				log.Warn("linux Agent package verification failed", "host", body.Host)
				writeJSON(w, http.StatusBadGateway, map[string]any{
					"error":    "agent_package_verification_failed",
					"verified": verify,
				})
				return
			}
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"prepared":         prep,
			"installed":        install,
			"verified":         verify,
			"packageSelection": selection,
			"privilege":        privilege,
		})
	})
}

func linuxDeploymentKitReady(verify executor.LocalVerifyResult) bool {
	return verify.DeploymentKitVersion != "" && verify.DeployerStatus == "active"
}

func clearSecretBytes(secret []byte) {
	for i := range secret {
		secret[i] = 0
	}
}

func elevateRequested(legacy string, explicit *bool) bool {
	if explicit != nil {
		return *explicit
	}
	return legacy == "sudo"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
