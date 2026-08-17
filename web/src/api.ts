// Typed API client for the AgentBridge HTTP surface.
//
// All secrets (VBR password) live only in request bodies held in memory by the
// browser; the server keeps them memory-only and never persists them
// (Constitution red line 1). No secret is ever read back from the API.

export interface ServerInfo {
  productVersion: string
  host: string
  serverTime?: string
  vbrId?: string
  patches?: string[]
  timeZone?: string
  ianaTimeZoneId?: string
  platform?: 'windows' | 'linux'
}

export type Platform = 'windows' | 'linux'

export interface RescanFailure {
  host: string
  message: string
}

export interface Capabilities {
  agentPackages: boolean
  deploymentKit: boolean
  protectionGroup: boolean
  rescan: boolean
  session: boolean
  discoveredEntities: boolean
}

export interface ApiError {
  error: string
  status?: string
  detail?: string
  detailSource?: 'vbr' | 'unavailable'
  failures?: RescanFailure[]
  actionable?: string
  capability?: string
  rpcAuthLevel?: string
  failureStage?: string
  errorCode?: string
  errorField?: string
  errorValue?: string
  errorLine?: number
  errorColumn?: number
}

// Preserve the server's stable error identifier separately from the
// user-facing detail. Callers must not have to parse translated or explanatory
// prose to decide whether a request can be retried.
export class ApiRequestError extends Error {
  readonly status: number
  readonly code: string
  readonly detail?: string
  readonly detailSource?: 'vbr' | 'unavailable'
  readonly failures?: RescanFailure[]
  readonly actionable?: string
  readonly capability?: string
  readonly resultStatus?: string
  readonly rpcAuthLevel?: string
  readonly failureStage?: string
  readonly errorCode?: string
  readonly errorField?: string
  readonly errorValue?: string
  readonly errorLine?: number
  readonly errorColumn?: number

  constructor(status: number, payload: Partial<ApiError>) {
    super(payload.actionable || payload.detail || payload.error || `request failed: ${status}`)
    this.name = 'ApiRequestError'
    this.status = status
    this.code = payload.error || ''
    this.detail = payload.detail
    this.detailSource = payload.detailSource
    this.failures = payload.failures
    this.actionable = payload.actionable
    this.capability = payload.capability
    this.resultStatus = payload.status
    this.rpcAuthLevel = payload.rpcAuthLevel
    this.failureStage = payload.failureStage
    this.errorCode = payload.errorCode
    this.errorField = payload.errorField
    this.errorValue = payload.errorValue
    this.errorLine = payload.errorLine
    this.errorColumn = payload.errorColumn
  }
}

let sessionToken = ''

// setSessionToken stores the localhost ephemeral token (memory only).
export function setSessionToken(token: string): void {
  sessionToken = token
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }
  if (sessionToken) {
    headers.Authorization = `Bearer ${sessionToken}`
  }
  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await res.text()
  const data = text ? JSON.parse(text) : {}
  if (!res.ok) {
    const err = data as ApiError
    throw new ApiRequestError(res.status, err)
  }
  return data as T
}

export function fetchSession(): Promise<{ remote: boolean; token?: string }> {
  return request('GET', '/api/session')
}

export function fetchProductVersion(): Promise<{ version: string }> {
  return request('GET', '/api/version')
}

// captureFingerprint retrieves the VBR TLS fingerprint WITHOUT trusting it.
// The operator MUST confirm it before connect (AB-FR-022).
export function captureFingerprint(server: string, port: number): Promise<{ fingerprint: string }> {
  return request('POST', '/api/vbr/capture', { server, port })
}

export function connectVBR(body: {
  server: string
  port: number
  username: string
  password: string
  fingerprint: string
}): Promise<{ serverInfo: ServerInfo; capabilities: Capabilities }> {
  return request('POST', '/api/vbr/connect', body)
}

export function fetchCapabilities(): Promise<Capabilities> {
  return request('GET', '/api/vbr/capabilities')
}

// captureHostKey retrieves the target SSH host key WITHOUT trusting it; the
// caller auto-pins it on first use (TOFU without a prompt, owner decision
// 2026-08-14). hostKey (the authorized-keys line) is what install pins — it
// is NOT interchangeable with the fingerprint.
export function captureHostKey(host: string, port: number): Promise<{ fingerprint: string; hostKey: string }> {
  return request('POST', '/api/ssh/hostkey', { host, port })
}

// probeSSH uses the same one-time SSH credentials as installation, but only
// gathers immutable Linux facts. In private-key mode, password is omitted and
// the account Password field is sent only as sudoPassword; passphrase is used
// only to decrypt the private key. The caller uses the result to select the
// matching cached Agent package before credentials are saved on the host row.
export function probeSSH(body: {
  host: string
  port: number
  user: string
  password?: string
  privateKeyPem?: string
  passphrase?: string
  hostKey: string
  privilege?: 'root' | 'sudo'
  elevatePrivileges?: boolean
  sudoPassword?: string
  addToSudoers?: boolean
  useSuFallback?: boolean
  rootPassword?: string
}): Promise<SSHProbeResult> {
  return request('POST', '/api/ssh/probe', body)
}

export interface InstallResult {
  installed: {
    packageInstalled: boolean
    localAgentHealthy: boolean
    deploymentKitReady: boolean
    rebootRequired: boolean
  }
  verified: {
    packageVersion: string
    deploymentKitVersion: string
    serviceStatus: string
    deployerStatus: string
    agentStatus: string
  }
  packageSelection?: {
    packageName: string
    targetFormat: string
    targetArchitecture: string
    targetOS: string
    targetVersion: string
    compatibilityFamily: string
    compatibilityBasis: string
    mode: 'standard' | 'nosnap'
    selected: Array<{ fileName: string; format: string; role?: string; size: number; sha256: string }>
    excluded: Array<{ fileName: string; format: string; role?: string; size: number; sha256: string }>
    warnings?: string[]
    requiresExplicitConfirmation: boolean
  }
  privilege?: LinuxPrivilegeResult
}

// install runs Prepare→Install→Verify→Cleanup. If an Agent artifact is supplied,
// the server probes the target and selects the compatible RPM/DEB role set before
// upload; otherwise it runs the Kit-only path. All secrets (password, key,
// passphrase) live only in the request body in memory; the server never persists
// them (Constitution red line 1).
export function install(body: {
  host: string
  port: number
  user: string
  password?: string
  privateKeyPem?: string
  passphrase?: string
  hostKey: string
  privilege?: 'root' | 'sudo'
  elevatePrivileges?: boolean
  sudoPassword?: string
  addToSudoers?: boolean
  useSuFallback?: boolean
  rootPassword?: string
  kitPath: string
  packagePath?: string
  packageId?: string
  confirmSelection?: boolean
  deploymentProfile?: string
}): Promise<InstallResult> {
  return request('POST', '/api/install', body)
}

export interface WindowsPreflightResult {
  status: 'ready' | 'auth_failed' | 'remote_uac_blocked' | 'admin_share_unavailable' | 'rpc_unavailable' | 'task_scheduler_access_denied' | 'task_definition_invalid' | string
  error?: string
  authentication?: string
  adminShare?: string
  taskSchedulerRpc?: string
  rpcAuthLevel?: string
  failureStage?: string
  errorCode?: string
  errorField?: string
  errorValue?: string
  errorLine?: number
  errorColumn?: number
  serviceReady?: boolean
  detail?: string
}

export interface WindowsInstallResult extends WindowsPreflightResult {
  status: 'installed' | string
}

export function windowsPreflight(body: { host: string; username: string; password: string }): Promise<WindowsPreflightResult> {
  return request('POST', '/api/windows/preflight', body)
}

export function windowsInstall(body: { host: string; username: string; password: string; campaignId?: string; kitPath?: string; kitSha256?: string }): Promise<WindowsInstallResult> {
  return request('POST', '/api/windows/install', body)
}

export interface DeploymentKitProbeResult {
  status: 'ready' | 'failed'
  host: string
  platform: Platform
  campaignId: string
  reason?: 'host_unresolved' | 'network_unreachable' | 'service_unavailable' | 'deployment_kit_campaign_invalid' | 'request_invalid' | string
  checkedAt?: string
  durationMs?: number
}

// Probe the fixed Veeam Deployment Kit service port after a manual install.
// A ready result proves the communication endpoint is reachable, not that VBR
// has completed certificate authentication.
export function probeDeploymentKit(body: { host: string; platform: Platform; campaignId: string }): Promise<DeploymentKitProbeResult> {
  return request('POST', '/api/deployment-kit/probe', body)
}

// --- US3: probe + match ---

export interface OSInfo {
  id: string
  versionId: string
  idLike: string[]
}
export interface ProbeResult {
  schemaVersion: string
  target: { hostName: string; addresses: string[]; architecture: string }
  os: OSInfo
  kernel: string
  glibc: string
  packageFormat: string
  packageManager: string
  rhelMacro: string
  secureBoot: string
  existingVeeamPackages: string[]
  availableTempBytes: number
}

export interface LinuxPrivilegeResult {
  mode: 'root' | 'sudo-nopasswd' | 'sudo-password' | 'su'
  configuredSudoers: boolean
  usedSuFallback: boolean
}

export interface SSHProbeResult extends ProbeResult {
  privilege: LinuxPrivilegeResult
}

export type RuleLevel = 'VendorSupported' | 'LabValidated' | 'CompatibilityInferred' | 'UserSelected' | 'Blocked'
export interface Recommendation {
  recommendedPackageId: string
  packageMode?: 'standard' | 'nosnap'
  compatibilityFamily?: string
  compatibilityBasis?: string
  confidence: string
  evidence: string[]
  warnings: string[]
  requiresExplicitConfirmation: boolean
}
export interface MatchResponse {
  recommendation: Recommendation
  level: RuleLevel
}

// matchProbes turns probe facts into an explanatory recommendation.
export function matchProbe(result: ProbeResult): Promise<MatchResponse> {
  return request('POST', '/api/match', result)
}

// matchOverride records an operator's manual choice (always UserSelected — never
// re-labelled, red line 11).
export function matchOverride(body: { packageId: string; reason?: string; user?: string }): Promise<MatchResponse> {
  return request('POST', '/api/match/override', body)
}

// probeLocal runs the static POSIX probe on the AgentBridge host (no SSH/root).
export function probeLocal(): Promise<ProbeResult> {
  return request('POST', '/api/probe/local', {})
}

// probeImport accepts an offline-supplied probe result (no credential held).
export function probeImport(result: unknown): Promise<ProbeResult> {
  return request('POST', '/api/probe/import', { result })
}

// --- US5: Protection Group + discovery ---

export interface DiscoveredEntity {
  host: string
  online: boolean
  agentStatus: string
  agentVersion: string
  lastConnected: string
}
export interface Enrollment {
  pgId: string
  created: boolean
  installLayer: string
  discoveryLayer: string
  entities?: DiscoveredEntity[]
  found?: Record<string, DiscoveredEntity>
  discoveryError?: string
  detail?: string
  detailSource?: 'vbr' | 'unavailable'
  failures?: RescanFailure[]
}

// enrollPG runs the full PG create + discovery for selected hosts. Existing
// names return protection_group_name_conflict and are never reused.
// hosts: the enrolled targets (matched by name in the PG's discovered set).
export function enrollPG(body: { name: string; description?: string; hosts?: string[] }): Promise<Enrollment> {
  return request('POST', '/api/pg/enroll', body)
}

// createPG creates a certificate-based Protection Group with an exclusive name.
export function createPG(body: { name: string; description?: string; hosts?: string[] }): Promise<{ pgId: string; created: boolean }> {
  return request('POST', '/api/pg/create', body)
}

// discovered rescan + read discovered entities (layered).
export function discovered(pgId: string): Promise<{ entities: DiscoveredEntity[]; found: Record<string, DiscoveredEntity> }> {
  return request('GET', `/api/pg/${encodeURIComponent(pgId)}/discovered`)
}

// --- US2: source Agent package + Deployment Kit ---

export interface AgentPackage {
  packageName: string
  distributionName: string
  packageBitness: string
}
export interface KitResult {
  path: string
  source: string
  id?: string
  campaignId?: string
  platforms?: Platform[]
  createdAt?: string
  expiresAt?: string
  sha256?: string
  previousCampaignInvalidated?: boolean
  warning: string
}

// listPackages lists the Linux Agent package catalog from the connected VBR.
export function listPackages(): Promise<{ packages: AgentPackage[] }> {
  return request('GET', '/api/packages/linux')
}

export interface AgentArtifact {
  path: string
  packageName: string
  fileName: string
  format: string
  size: number
  sha256: string
  payloads?: Array<{
    fileName: string
    format: string
    size: number
    sha256: string
  }>
}

// downloadPackages asks VBR for all selected catalog entries. The server
// exports each entry independently, preserves all RPM/DEB payloads returned
// for that entry, and discards VBR's XML/readme metadata.
export function downloadPackages(packageNames: string[]): Promise<{ artifacts: AgentArtifact[] }> {
  return request('POST', '/api/packages/download', { packageNames })
}

// generateKit generates a Deployment Kit (capability-gated). A new Kit invalidates
// any prior unpaired campaign — the response warns when that happens.
export function generateKit(body?: { platforms?: Platform[]; validityHours?: number }): Promise<KitResult> {
  return request('POST', '/api/kit/generate', body || {})
}

export interface KitFileInfo {
  name: string
  size: number
}
export interface KitInfo {
  path: string
  source: string
  id: string
  createdAt: string
  expiresAt?: string
  platforms?: Platform[]
  sha256?: string
  totalSize: number
  files: KitFileInfo[]
}

// kitInfo reads the active campaign's read-only view (archive file list,
// sizes, certificate-derived expiry) for the step-一 kit drawer.
export async function kitInfo(): Promise<KitInfo | null> {
  const data = await request<{ kit: KitInfo | null }>('GET', '/api/kit')
  return data.kit
}

// importKit admits an admin-supplied Kit file (fallback when DeploymentKit=false).
// Multipart upload; the bearer token is attached manually.
export async function importKit(file: File): Promise<KitResult> {
  const form = new FormData()
  form.append('kit', file)
  const headers: Record<string, string> = {}
  if (sessionToken) headers.Authorization = `Bearer ${sessionToken}`
  const res = await fetch('/api/kit/import', { method: 'POST', headers, body: form })
  const text = await res.text()
  const data = text ? JSON.parse(text) : {}
  if (!res.ok) {
    const err = data as ApiError
    throw new Error(err.actionable || err.detail || err.error || `request failed: ${res.status}`)
  }
  return data as KitResult
}

// --- US6: zero-credential Local/Offline bundle ---

export type DeploymentProfile = 'kit-only' | 'agent-plus-kit'
export interface BundleManifest {
  schemaVersion: string
  jobId: string
  packageId?: string
  packageSha256?: string
  packageFile?: string
  deploymentProfile: DeploymentProfile
  kitFile?: string
  generatedAt: string
}
export interface BundleInfo {
  path: string
  sha256: string
  jobId: string
  manifest: BundleManifest
}
export interface ManualInstallInfo extends BundleInfo {
  downloadUrl: string
  command: string
  expiresAt: string
}
export interface BundleResult {
  schemaVersion: string
  jobId: string
  ok: boolean
  error?: string
  deploymentProfile?: string
  target: { hostName: string; architecture: string; addresses: string[] }
  install: { packageInstalled: boolean; deploymentKitReady: boolean; rebootRequired: boolean }
  verify: { packageVersion: string; serviceStatus: string; agentStatus: string }
}

// generateBundle builds a self-contained Local/Offline bundle for the selected
// certificate-ready deployment profile (kit-only / agent-plus-kit). Every
// profile includes Deployment Kit and no credential is ever sent (FR-034).
export function generateBundle(body: {
  packagePath?: string
  packageId?: string
  packageSha256?: string
  kitPath?: string
  deploymentProfile?: DeploymentProfile
  jobId?: string
}): Promise<BundleInfo> {
  return request('POST', '/api/bundle/generate', body)
}

// generateManualInstall creates the archive and publishes a short-lived LAN
// download URL. The target host pulls the archive with curl/wget or PowerShell; no SSH
// credential is sent to AgentBridge.
export function generateManualInstall(body: {
  packagePath?: string
  packageId?: string
  packageSha256?: string
  packagePaths?: string[]
  packageIds?: string[]
  packageSha256s?: string[]
  kitPath?: string
  deploymentProfile?: DeploymentProfile
  jobId?: string
  platform?: Platform
  campaignId?: string
  kitSha256?: string
}): Promise<ManualInstallInfo> {
  return request('POST', '/api/manual-install/generate', body)
}

// importBundle decodes + verifies an offline result (job id + profile), returning
// the layered install/verify status. Discovery continues via enrollPG (FR-036).
export function importBundle(body: {
  result: string
  jobId?: string
  profile?: DeploymentProfile
}): Promise<{
  installLayer: string
  discoveryLayer: string
  result: BundleResult
  target: BundleResult['target']
}> {
  return request('POST', '/api/bundle/import', body)
}

// --- US7: batch enrollment ---

export interface HostSnapshot {
  id: string
  host: string
  state: string
  error?: string
}
export interface BatchStatus {
  id?: string
  batchId?: string
  pgId?: string
  state: string
  hosts: HostSnapshot[]
}

// startBatch enrolls many hosts against one shared idempotent Protection Group.
// Each host's discovery is independent (one failure never blocks the others,
// AB-NFR-004). Only the VBR connection is needed — no SSH credentials.
export function startBatch(body: {
  hosts: string
  pgName: string
  description?: string
  port?: number
  concurrency?: number
}): Promise<BatchStatus> {
  return request('POST', '/api/batch', body)
}

// getBatch reads the current per-host snapshot (refresh-safe; SSE also replays
// recent events, FR-038/039).
export function getBatch(id: string): Promise<BatchStatus> {
  return request('GET', `/api/batch/${encodeURIComponent(id)}`)
}

// retryHost re-runs one host's failed enrollment phase (idempotent: no reinstall,
// no PG recreate — FR-031/032).
export function retryHost(id: string, hostId: string): Promise<BatchStatus> {
  return request('POST', `/api/batch/${encodeURIComponent(id)}/retry`, { hostId })
}
