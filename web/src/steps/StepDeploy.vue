<script setup lang="ts">
// Step 二 — 安装 Agent 或 Deployment Kit (1:1 with the prototype's step 2).
//
// Hosts table with a per-row action menu (add credentials / choose component
// / push / delete), the right drawer in its three modes, and the offline
// install card. Security invariants carried over from the old cards:
//   - SSH host key is auto-TOFU: captured without trust, pinned on first
//     use, no confirmation prompt; a later change blocks.
//   - All SSH secrets live in component memory only. They remain available
//     for retries during this browser session and are never persisted.
//   - Install result layers are honest: the component column says what was
//     installed (Kit vs full Agent) — the status cell is a badge only,
//     with no inline prose.
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import CustomSelect from '../ui/CustomSelect.vue'
import Drawer from '../ui/Drawer.vue'
import HourglassIndicator from '../ui/HourglassIndicator.vue'
import { t } from '../i18n'
import { formatAgentPackageDownloadError, formatDeploymentKitProbeError, formatLinuxRemoteError, formatWindowsRemoteError } from '../errorPresentation'
import { toast } from '../ui/toast'
import {
  captureHostKey,
  downloadPackages,
  generateManualInstall,
  install,
  listPackages,
  matchProbe,
  matchOverride,
  probeDeploymentKit,
  probeSSH,
  windowsInstall,
  windowsPreflight,
  type AgentArtifact,
  type AgentPackage,
  type DeploymentProfile,
  type DeploymentKitProbeResult,
  type MatchResponse,
  type LinuxPrivilegeResult,
  type ProbeResult,
  type WindowsPreflightResult,
} from '../api'

const props = defineProps<{ kitPath: string; kitCampaignId?: string; kitSha256?: string; agentPackage?: AgentArtifact | null; agentPackages?: AgentArtifact[] }>()
const emit = defineEmits<{
  (e: 'next'): void
  (e: 'back'): void
  (e: 'host-state', host: string, platform: 'windows' | 'linux', component: string, method: InstallMethod, ready: boolean, version: string): void
  (e: 'agents-cached', artifacts: AgentArtifact[]): void
}>()

// --- hosts table --------------------------------------------------------
type InstallMethod = 'remote' | 'manual'
type InstallMode = 'manual' | 'automatic'

interface ManualCommandState {
  status: 'idle' | 'generating' | 'ready' | 'failed'
  command: string
  expiresAt: string
  detail: string
}

interface HostRow {
  host: string
  platform: 'windows' | 'linux'
  port: number
  component: '' | 'kit' | 'agent-plus-kit'
  user: string
  auth: '' | 'password' | 'key'
  credentialDescription: string
  hostKey: string // pinned authorized-keys line (set only after TOFU confirm)
  status: 'pending' | 'cred-ready' | 'pushing' | 'installed' | 'failed' | 'manual-pending' | 'manual-probing' | 'manual-ready' | 'manual-failed'
  detail: string
  version: string
  probe?: ProbeResult
  recommendation?: MatchResponse
  selectionRecommendation?: MatchResponse
  selectedPackageName?: string
  agentArtifact?: AgentArtifact
  installMode: InstallMode
  manualProfile: DeploymentProfile
  manualArtifact?: AgentArtifact
  manualCommand?: ManualCommandState
  deploymentKitProbe?: DeploymentKitProbeResult
  privilege?: LinuxPrivilegeResult
}
const hosts = reactive<HostRow[]>([])
const openMenu = ref<string | null>(null)
const addingHost = ref('')
const addingPlatform = ref<'windows' | 'linux'>('linux')
const addMode = ref(false)
const cacheSessionArtifacts = ref<AgentArtifact[]>([])

type HostGuideStep = 'method' | 'actions' | null
const HOST_GUIDE_DISMISSED_KEY = 'agentbridge.host-setup-guide.dismissed'
const hostGuideStep = ref<HostGuideStep>(null)
const hostGuideHost = ref('')
const hostGuideAutoSkipped = ref(false)

function rememberHostGuideDismissed(): void {
  hostGuideAutoSkipped.value = true
  try {
    localStorage.setItem(HOST_GUIDE_DISMISSED_KEY, '1')
  } catch {
    // A blocked storage API must not prevent the user from dismissing the guide.
  }
}

function closeHostGuide(remember: boolean): void {
  hostGuideStep.value = null
  hostGuideHost.value = ''
  if (remember) rememberHostGuideDismissed()
}

function skipAllHostGuide(): void {
  closeHostGuide(true)
}

function completeHostGuide(): void {
  closeHostGuide(true)
}

function startHostGuide(row: HostRow): void {
  openMenu.value = null
  hostGuideHost.value = row.host
  hostGuideStep.value = 'method'
}

function advanceHostGuide(row: HostRow): void {
  if (hostGuideHost.value === row.host && hostGuideStep.value === 'method') {
    hostGuideStep.value = 'actions'
  }
}

function openGuidedActionMenu(row: HostRow): void {
  openMenu.value = row.host
  completeHostGuide()
}

function toggleActionMenu(row: HostRow): void {
  const opening = openMenu.value !== row.host
  openMenu.value = opening ? row.host : null
  if (opening && hostGuideHost.value === row.host && hostGuideStep.value === 'actions') {
    completeHostGuide()
  }
}

function closeActionMenuOnPointerDown(event: PointerEvent): void {
  if (!openMenu.value) return
  const target = event.target
  if (target instanceof Element && target.closest('.action-cell.open')) return
  openMenu.value = null
}

function closeActionMenuOnKeydown(event: KeyboardEvent): void {
  if (event.key !== 'Escape' || !openMenu.value) return
  const trigger = document.querySelector<HTMLButtonElement>('.action-cell.open .action-trigger')
  openMenu.value = null
  trigger?.focus()
}

onMounted(() => {
  document.addEventListener('pointerdown', closeActionMenuOnPointerDown)
  document.addEventListener('keydown', closeActionMenuOnKeydown)
  try {
    hostGuideAutoSkipped.value = localStorage.getItem(HOST_GUIDE_DISMISSED_KEY) === '1'
  } catch {
    hostGuideAutoSkipped.value = false
  }
})

onBeforeUnmount(() => {
  document.removeEventListener('pointerdown', closeActionMenuOnPointerDown)
  document.removeEventListener('keydown', closeActionMenuOnKeydown)
  secrets.clear()
})

const availableAgentPackages = computed(() => {
  const byName = new Map<string, AgentArtifact>()
  props.agentPackages?.forEach((artifact) => byName.set(artifact.packageName, artifact))
  if (props.agentPackage?.path) byName.set(props.agentPackage.packageName, props.agentPackage)
  cacheSessionArtifacts.value.forEach((artifact) => byName.set(artifact.packageName, artifact))
  return [...byName.values()]
})

const platformSelectOptions = computed(() => [
  { value: 'windows', label: 'Windows' },
  { value: 'linux', label: 'Linux' },
])
const automaticComponentSelectOptions = computed(() => [
  { value: 'kit', label: t('deploy.deployment.kit.only') },
  { value: 'agent-plus-kit', label: t('deploy.agent.deployment.kit') },
])
const manualProfileSelectOptions = computed(() => [
  { value: 'kit-only', label: t('deploy.deployment.kit.only.2') },
  { value: 'agent-plus-kit', label: t('deploy.agent.deployment.kit.2') },
])
const manualArtifactSelectOptions = computed(() => [
  { value: '', label: t('deploy.choose.a.cached.agent.package') },
  ...availableAgentPackages.value.map((artifact) => ({ value: artifact.packageName, label: artifact.packageName })),
])

function versionMajor(value: string): string {
  return value.match(/\d+/)?.[0] || ''
}

function normalizedArchitecture(value: string): 'x64' | 'ppc64le' | '' {
  const arch = value.trim().toLowerCase()
  if (arch === 'x86_64' || arch === 'amd64' || arch === 'x64') return 'x64'
  if (arch === 'ppc64le') return 'ppc64le'
  return ''
}

function preferredCatalogTokens(probe: ProbeResult, family: string): string[] {
  const id = probe.os.id.trim().toLowerCase()
  if (id === 'rhel' || id === 'centos' || id === 'centoslinux' || id === 'centos-stream') return ['red hat']
  if (id === 'rocky') return ['rocky linux', 'red hat']
  if (id === 'almalinux') return ['almalinux', 'red hat']
  if (id === 'oracle' || id === 'ol') return ['oracle linux', 'red hat']
  if (id === 'ubuntu') return ['ubuntu', 'debian']
  if (id === 'debian') return ['debian']
  if (id === 'sles' || id === 'sles_sap') return ['sles']
  if (id === 'amzn') return ['amazon linux', 'red hat']
  if (family === 'rhel') return ['red hat']
  if (family === 'debian') return ['debian', 'ubuntu']
  if (family === 'suse') return ['sles']
  return []
}

function packageCandidateScore(packageName: string, recommendation: MatchResponse, probe: ProbeResult, exactMode: boolean): number {
  const rec = recommendation.recommendation
  const platform = packageName.split(/\s+-\s+(?=\d)/)[0].toLowerCase()
  const arch = normalizedArchitecture(probe.target.architecture)
  const major = versionMajor(probe.os.versionId)
  const family = (rec.compatibilityFamily || '').toLowerCase()
  const preferred = preferredCatalogTokens(probe, family)
  const artifactNosnap = platform.includes('nosnap')
  const wantsNosnap = rec.packageMode === 'nosnap'

  if (exactMode && artifactNosnap !== wantsNosnap) return -1
  if (arch === 'x64' && (!platform.includes('x64') || platform.includes('ppc64le'))) return -1
  if (arch === 'ppc64le' && !platform.includes('ppc64le')) return -1
  if (major && !new RegExp(`(^|\\D)${major}(\\D|$)`).test(platform)) return -1

  const familyMatch = family === 'rhel'
    ? /red hat|rhel|rocky linux|almalinux|oracle linux|amazon linux/.test(platform)
    : family === 'debian'
      ? /debian|ubuntu/.test(platform)
      : family === 'suse'
        ? /sles|suse/.test(platform)
        : true
  if (!familyMatch) return -1

  const tokenIndex = preferred.findIndex((token) => platform.includes(token))
  // Prefer the probe's closest upstream distribution before another member
  // of the same package family. Within it, the matched standard/nosnap mode
  // remains the first recommendation.
  return 100 + (artifactNosnap === wantsNosnap ? 30 : 0) + (tokenIndex >= 0 ? 80 - tokenIndex * 10 : 0)
}

// Matcher recommendations use stable internal IDs such as rhel7-x86_64,
// while VBR catalog artifacts retain display names such as
// "Red Hat 7 x64 - 13.1.1.4". Resolve them by target facts instead of
// comparing those two unrelated identifiers literally.
function artifactForRecommendation(recommendation?: MatchResponse, probe?: ProbeResult): AgentArtifact | undefined {
  if (!availableAgentPackages.value.length || !recommendation || !probe) return undefined
  const rec = recommendation.recommendation
  if (!rec.recommendedPackageId || recommendation.level === 'Blocked') return undefined

  const candidates = availableAgentPackages.value
    .map((artifact) => {
      return { artifact, score: packageCandidateScore(artifact.packageName, recommendation, probe, true) }
    })
    .filter((candidate) => candidate.score >= 0)
    .sort((a, b) => b.score - a.score || a.artifact.packageName.localeCompare(b.artifact.packageName))

  return candidates[0]?.artifact
}

function cachedArtifactByName(packageName?: string): AgentArtifact | undefined {
  if (!packageName) return undefined
  return availableAgentPackages.value.find((artifact) => artifact.packageName === packageName)
}

function artifactForRow(row?: HostRow | null): AgentArtifact | undefined {
  if (!row) return undefined
  return cachedArtifactByName(row.selectedPackageName) || row.manualArtifact || row.agentArtifact || artifactForRecommendation(row.recommendation, row.probe)
}

function canUseAgent(row: HostRow | null): boolean {
  return !!artifactForRow(row)
}

function agentChoiceHint(row: HostRow | null): string {
  if (!row?.probe || !row.recommendation) {
    return t('deploy.add.credentials.and.probe.the.system.first')
  }
  const matched = artifactForRow(row)
  if (matched) return matched.packageName
  if (row.selectedPackageName) {
    return t('deploy.is.not.cached.yet', row.selectedPackageName)
  }
  return t('deploy.recommended.but.its.package.has.not.been', row.recommendation.recommendation.recommendedPackageId || 'Agent')
}

function updateAddingPlatform(value: string): void {
  if (value === 'windows' || value === 'linux') addingPlatform.value = value
}

function addHost(): void {
  const ip = addingHost.value.trim().replace(/[<>]/g, '')
  if (!ip) {
    toast(t('deploy.missing.host.address'), t('deploy.enter.an.ip.or.resolvable.hostname'))
    return
  }
  if (hosts.some((h) => h.host === ip)) {
    toast(t('deploy.duplicate.host'), ip)
    return
  }
  hosts.push({
    host: ip,
    platform: addingPlatform.value,
    port: addingPlatform.value === 'windows' ? 445 : 22,
    component: 'kit',
    user: '',
    auth: '',
    credentialDescription: '',
    hostKey: '',
    status: 'manual-pending',
    detail: '',
    version: '',
    installMode: 'manual',
    manualProfile: 'kit-only',
  })
  const addedRow = hosts[hosts.length - 1]
  addingHost.value = ''
  addingPlatform.value = 'linux'
  addMode.value = false
  if (!hostGuideAutoSkipped.value && !hostGuideStep.value) startHostGuide(addedRow)
  toast(t('deploy.host.added'), ip + t('deploy.added.to.the.deployment.list'))
}

function deleteHost(row: HostRow): void {
  const i = hosts.indexOf(row)
  if (i >= 0) hosts.splice(i, 1)
  if (hostGuideHost.value === row.host) closeHostGuide(false)
  secrets.delete(row.host)
  emit('host-state', row.host, row.platform, row.component, row.installMode === 'manual' ? 'manual' : 'remote', false, '')
  toast(t('deploy.host.removed'), row.host + t('deploy.removed.from.the.deployment.list'))
}

const readyCount = computed(() => hosts.filter((h) => h.status === 'installed' || h.status === 'manual-ready').length)

function componentLabel(c: HostRow['component']): string {
  if (c === 'kit') return t('deploy.deployment.kit.only.3')
  if (c === 'agent-plus-kit') return t('deploy.agent.deployment.kit.3')
  return t('deploy.not.selected')
}

function statusBadge(row: HostRow): { cls: string; text: string } {
  if (row.installMode === 'manual') {
    if (row.status === 'manual-ready') return { cls: 'ready', text: t('deploy.deployment.kit.communication.ready') }
    if (row.status === 'manual-probing') return { cls: 'running', text: t('deploy.checking') }
    if (row.status === 'manual-failed') return { cls: 'failed', text: t('deploy.check.failed') }
    if (row.manualCommand?.status === 'ready') return { cls: '', text: t('deploy.ready.to.check') }
    return { cls: '', text: t('deploy.command.pending') }
  }
  switch (row.status) {
    case 'cred-ready':
      return { cls: 'ready', text: t('deploy.credentials.verified') }
    case 'pushing':
      return { cls: 'running', text: t('deploy.deploying') }
    case 'installed':
      return { cls: 'ready', text: t('deploy.installed') }
    case 'failed':
      return { cls: 'failed', text: t('deploy.failed') }
    default:
      return { cls: '', text: t('deploy.pending') }
  }
}

// --- drawer (credential / component / failure modes) ---------------------
type DrawerMode = 'credential' | 'component' | 'failure'
const drawerMode = ref<DrawerMode>('credential')
const drawerOpen = ref(false)
const current = ref<HostRow | null>(null)
const pendingComponent = ref<HostRow['component']>('')

const drawerManualCommand = reactive<ManualCommandState>({ status: 'idle', command: '', expiresAt: '', detail: '' })
const pendingManualProfile = ref<DeploymentProfile>('kit-only')
const selectedManualArtifactName = ref('')
const drawerManualBusy = ref(false)

function resetManualCommand(state: ManualCommandState): void {
  state.status = 'idle'
  state.command = ''
  state.expiresAt = ''
  state.detail = ''
}

function restoreManualCommand(state: ManualCommandState, saved?: ManualCommandState): void {
  if (!saved) {
    resetManualCommand(state)
    return
  }
  state.status = saved.status
  state.command = saved.command
  state.expiresAt = saved.expiresAt
  state.detail = saved.detail
}

const drawerMeta = computed(() => {
  switch (drawerMode.value) {
    case 'credential':
      return current.value?.platform === 'windows'
        ? { eyebrow: t('deploy.one.time.credentials'), title: t('deploy.add.windows.administrator.credentials') }
        : {
            eyebrow: '',
            title: t('deploy.credentials'),
          }
    case 'component':
      return {
        eyebrow: current.value?.installMode === 'manual' ? t('deploy.manual.install') : t('deploy.automatic.install'),
        title: current.value?.installMode === 'manual' ? t('deploy.generate.installation.command') : t('deploy.configure.automatic.deployment'),
      }
    default:
      return { eyebrow: t('deploy.deployment.failed'), title: t('deploy.failure.details') }
  }
})

// Failure detail: the error message splits into the error chain (summary) and
// the raw installer output after "; output: " — rendered line by line in the
// console-style drawer instead of one squashed table cell.
const failure = computed(() => {
  const d = current.value?.detail || ''
  const marker = '; output: '
  const i = d.indexOf(marker)
  if (i < 0) return { summary: d, lines: [] as string[] }
  const lines = d.slice(i + marker.length).split('\n')
  while (lines.length && lines[lines.length - 1].trim() === '') lines.pop()
  return { summary: d.slice(0, i), lines }
})

const failureSummary = computed(() => {
  return failure.value.summary
})

// Terminal color semantics: errors red, package-manager refusals amber.
function consoleLineClass(ln: string): string {
  if (/error:|failed|fatal|not found|refused|denied/i.test(ln)) return 'err'
  if (/Nothing to do|does not update installed package|already installed|warning/i.test(ln)) return 'warn'
  return ''
}

function openFailureDrawer(row: HostRow): void {
  current.value = row
  drawerMode.value = 'failure'
  drawerOpen.value = true
}

// Retry reuses the saved in-memory credential. If the browser session no
// longer has that secret, return to the credential drawer without replacing
// the original installation failure with a secondary credential error.
async function retryFailed(): Promise<void> {
  const row = current.value
  if (!row) return
  if (!hasSavedSecret(row)) {
    openDrawer(row, 'credential')
    toast(t('deploy.connection.credentials.required'), t('deploy.reenter.and.test.credentials.before.retrying'))
    return
  }
  closeDrawer()
  await pushHost(row)
}

// credential form — secrets stay here, memory only
const authTab = ref<'password' | 'key'>('password')
const sshUser = ref('')
const sshPort = ref(22)
const sshPassword = ref('')
const sshKeyPassphrase = ref('')
const windowsUser = ref('')
const windowsPassword = ref('')
const windowsPreflightResult = ref<WindowsPreflightResult | null>(null)
const windowsProbeBusy = ref(false)
const sshKeyText = ref('')
const sshKeyFileName = ref('')
const credentialDescription = ref('')
const passwordVisible = ref(false)
const passphraseVisible = ref(false)
const rootPasswordVisible = ref(false)
const elevatePrivileges = ref(true)
const addToSudoers = ref(false)
const useSuFallback = ref(false)
const rootPassword = ref('')
const probeBusy = ref(false)
const credentialSaving = ref(false)
const draftProbe = ref<ProbeResult | null>(null)
const draftRecommendation = ref<MatchResponse | null>(null)
const draftHostKey = ref('')
const draftPrivilege = ref<LinuxPrivilegeResult | null>(null)
const probedPort = ref<number | null>(null)
const probeError = ref('')
const keyFileInput = ref<HTMLInputElement>()
const credentialRevision = ref(0)
const probedCredentialRevision = ref<number | null>(null)

// A successful probe belongs to the exact credential and elevation draft
// that produced it. Any later change invalidates that evidence so stale
// authentication results can never be saved or used for installation.
watch(
  [sshUser, sshPort, authTab, sshPassword, sshKeyText, sshKeyPassphrase, elevatePrivileges, addToSudoers, useSuFallback, rootPassword],
  () => {
    credentialRevision.value += 1
    probedCredentialRevision.value = null
    draftProbe.value = null
    draftRecommendation.value = null
    draftPrivilege.value = null
    selectedDraftPackageName.value = ''
    draftHostKey.value = ''
    probedPort.value = null
    probeError.value = ''
  },
  { flush: 'sync' },
)

// A Windows credential test is valid only for the exact username/password
// pair that produced it. Editing either field returns the drawer to its
// untested state instead of allowing stale credentials to be saved.
watch(
  [windowsUser, windowsPassword],
  () => {
    windowsPreflightResult.value = null
    probeError.value = ''
  },
  { flush: 'sync' },
)

// Agent candidates stay attached to the probed host on the right. If a
// selected candidate is missing locally, a nested left drawer reuses the
// Step 一 catalog/download workflow without destroying the credential form.
const packageCatalog = ref<AgentPackage[]>([])
const packageCatalogBusy = ref(false)
const packageCatalogError = ref('')
const selectedDraftPackageName = ref('')
const cacheDrawerOpen = ref(false)
const cachePackageFilter = ref('')
const cacheSelectedPackageNames = ref<Set<string>>(new Set())
const cachePackageBusy = ref(false)

const candidateCatalog = computed<AgentPackage[]>(() => {
  const byName = new Map<string, AgentPackage>()
  packageCatalog.value.forEach((pkg) => byName.set(pkg.packageName, pkg))
  availableAgentPackages.value.forEach((artifact) => {
    if (!byName.has(artifact.packageName)) {
      byName.set(artifact.packageName, {
        packageName: artifact.packageName,
        distributionName: '',
        packageBitness: normalizedArchitecture(draftProbe.value?.target.architecture || '') || '',
      })
    }
  })
  return [...byName.values()]
})

const draftPackageCandidates = computed(() => {
  if (!draftProbe.value || !draftRecommendation.value || draftRecommendation.value.level === 'Blocked') return []
  return candidateCatalog.value
    .map((pkg) => ({
      pkg,
      score: packageCandidateScore(pkg.packageName, draftRecommendation.value!, draftProbe.value!, false),
    }))
    .filter((candidate) => candidate.score >= 0)
    .sort((a, b) => b.score - a.score || a.pkg.packageName.localeCompare(b.pkg.packageName))
    .slice(0, 6)
    .map((candidate) => candidate.pkg)
})

const defaultDraftPackageName = computed(() => draftPackageCandidates.value[0]?.packageName || '')
const draftSelectionIsOverride = computed(
  () => !!selectedDraftPackageName.value && !!defaultDraftPackageName.value && selectedDraftPackageName.value !== defaultDraftPackageName.value,
)
const draftIsOfficiallySupported = computed(() => draftRecommendation.value?.level === 'VendorSupported')

function packageIsCached(packageName: string): boolean {
  return !!cachedArtifactByName(packageName)
}

function syncDraftPackageSelection(preferred?: string): void {
  const desired = preferred || selectedDraftPackageName.value
  if (desired && candidateCatalog.value.some((pkg) => pkg.packageName === desired)) {
    selectedDraftPackageName.value = desired
    return
  }
  selectedDraftPackageName.value = defaultDraftPackageName.value
}

async function ensureAgentCatalog(): Promise<void> {
  if (packageCatalog.value.length || packageCatalogBusy.value) return
  packageCatalogBusy.value = true
  packageCatalogError.value = ''
  try {
    const result = await listPackages()
    packageCatalog.value = result.packages
    syncDraftPackageSelection()
  } catch (e) {
    packageCatalogError.value = (e as Error).message
  } finally {
    packageCatalogBusy.value = false
  }
}

async function refreshAgentCatalog(): Promise<void> {
  packageCatalog.value = []
  await ensureAgentCatalog()
}

function packageFilterSeed(packageName: string): string {
  const platform = packageName.split(/\s+-\s+(?=\d)/)[0]
  return platform.replace(/\s+(?:x64|ppc64le)(?:-nosnap)?$/i, '').trim()
}

function openAgentCache(packageName: string): void {
  selectedDraftPackageName.value = packageName
  cachePackageFilter.value = packageFilterSeed(packageName)
  const initialSelection = packageName.trim() && !packageIsCached(packageName) ? [packageName] : []
  cacheSelectedPackageNames.value = new Set(initialSelection)
  cacheDrawerOpen.value = true
  void ensureAgentCatalog()
}

function chooseDraftPackage(packageName: string): void {
  selectedDraftPackageName.value = packageName
  if (!packageIsCached(packageName)) openAgentCache(packageName)
}

function closeAgentCache(): void {
  cacheDrawerOpen.value = false
  cacheSelectedPackageNames.value = new Set()
}

const filteredCachePackages = computed(() => {
  const query = cachePackageFilter.value.trim().toLowerCase()
  if (!query) return packageCatalog.value
  return packageCatalog.value.filter((pkg) =>
    [pkg.packageName, pkg.distributionName, pkg.packageBitness].some((value) => value.toLowerCase().includes(query)),
  )
})

const downloadableFilteredCachePackages = computed(() => filteredCachePackages.value.filter((pkg) => !packageIsCached(pkg.packageName)))
const selectedDownloadPackageNames = computed(() => {
  const catalogNames = new Set(packageCatalog.value.map((pkg) => pkg.packageName))
  return [...cacheSelectedPackageNames.value].filter((name) => name.trim() && catalogNames.has(name) && !packageIsCached(name))
})
const cacheSelectedCount = computed(() => selectedDownloadPackageNames.value.length)
const allFilteredCacheSelected = computed(
  () => downloadableFilteredCachePackages.value.length > 0
    && downloadableFilteredCachePackages.value.every((pkg) => cacheSelectedPackageNames.value.has(pkg.packageName)),
)

function toggleCachePackage(packageName: string): void {
  if (!packageName.trim() || !packageCatalog.value.some((pkg) => pkg.packageName === packageName) || packageIsCached(packageName) || cachePackageBusy.value) return
  const next = new Set(cacheSelectedPackageNames.value)
  if (next.has(packageName)) next.delete(packageName)
  else next.add(packageName)
  cacheSelectedPackageNames.value = next
}

function toggleFilteredCachePackages(): void {
  const next = new Set(cacheSelectedPackageNames.value)
  if (allFilteredCacheSelected.value) {
    downloadableFilteredCachePackages.value.forEach((pkg) => next.delete(pkg.packageName))
  } else {
    downloadableFilteredCachePackages.value.forEach((pkg) => next.add(pkg.packageName))
  }
  cacheSelectedPackageNames.value = next
}

async function downloadSelectedCandidatePackages(): Promise<void> {
  if (!cacheSelectedCount.value || cachePackageBusy.value) return
  const names = selectedDownloadPackageNames.value
  cachePackageBusy.value = true
  try {
    const result = await downloadPackages(names)
    const byName = new Map(cacheSessionArtifacts.value.map((artifact) => [artifact.packageName, artifact]))
    result.artifacts.forEach((artifact) => byName.set(artifact.packageName, artifact))
    cacheSessionArtifacts.value = [...byName.values()]
    emit('agents-cached', result.artifacts)
    closeAgentCache()
    toast(
      t('deploy.agent.packages.cached.2'),
      t('deploy.package.s.exported.from.vbr.and.cached.2', result.artifacts.length),
    )
  } catch (e) {
    toast(t('deploy.agent.package.download.failed.2'), formatAgentPackageDownloadError(e))
  } finally {
    cachePackageBusy.value = false
  }
}

const loginIsRoot = computed(() => sshUser.value.trim().toLowerCase() === 'root')
const privilege = computed<'root' | 'sudo'>(() => (loginIsRoot.value || !elevatePrivileges.value ? 'root' : 'sudo'))
const effectiveSudoPassword = computed(() => {
  if (loginIsRoot.value || !elevatePrivileges.value) return ''
  return sshPassword.value
})
const rootPasswordRequired = computed(() => !loginIsRoot.value && elevatePrivileges.value && (addToSudoers.value || useSuFallback.value))
const privilegeInputValid = computed(() => !rootPasswordRequired.value || rootPassword.value !== '')
const privateKeyAccountPasswordMissing = computed(() => {
  if (authTab.value !== 'key' || sshPassword.value !== '' || !draftPrivilege.value) return false
  return draftPrivilege.value.mode !== 'root' && draftPrivilege.value.mode !== 'sudo-nopasswd'
})

watch(loginIsRoot, (isRoot, wasRoot) => {
  if (isRoot) {
    elevatePrivileges.value = false
    addToSudoers.value = false
    useSuFallback.value = false
    rootPassword.value = ''
  } else if (wasRoot) {
    elevatePrivileges.value = true
  }
})

const sshPortValid = computed(() => Number.isInteger(sshPort.value) && sshPort.value >= 1 && sshPort.value <= 65535)
const windowsCredValid = computed(() => !!windowsUser.value.trim() && windowsPassword.value !== '')
const credValid = computed(() => {
  if (current.value?.platform === 'windows') return windowsCredValid.value
  if (!sshUser.value.trim() || !sshPortValid.value || !privilegeInputValid.value) return false
  // Private-key Password is not an SSH authentication method. It may be
  // blank for root/NOPASSWD:ALL, which only the remote probe can establish.
  return authTab.value === 'password' ? sshPassword.value !== '' : sshKeyText.value !== ''
})

const probePortStale = computed(() => !!draftProbe.value && probedPort.value !== sshPort.value)
const draftAgentArtifact = computed(() => cachedArtifactByName(selectedDraftPackageName.value)
  || artifactForRecommendation(draftRecommendation.value || undefined, draftProbe.value || undefined))
const probeReady = computed(() => current.value?.platform === 'windows'
  ? windowsPreflightResult.value?.status === 'ready'
  : !!draftProbe.value
    && !!draftRecommendation.value
    && !!draftPrivilege.value
    && !probePortStale.value
    && probedCredentialRevision.value === credentialRevision.value)

function selectCredentialType(type: 'password' | 'key'): void {
  if (authTab.value === type) return
  authTab.value = type
  sshPassword.value = ''
  sshKeyText.value = ''
  sshKeyFileName.value = ''
  sshKeyPassphrase.value = ''
  rootPassword.value = ''
  passwordVisible.value = false
  passphraseVisible.value = false
  rootPasswordVisible.value = false
  draftProbe.value = null
  draftRecommendation.value = null
  draftPrivilege.value = null
  selectedDraftPackageName.value = ''
  draftHostKey.value = ''
  probedPort.value = null
  probeError.value = ''
}

function openDrawer(row: HostRow, mode: DrawerMode): void {
  current.value = row
  drawerMode.value = mode
  drawerOpen.value = true
  if (mode === 'credential') {
    pendingComponent.value = row.component || 'kit'
    sshUser.value = row.user || 'root'
    windowsUser.value = row.user || 'Administrator'
    sshPort.value = row.port || 22
    sshPassword.value = ''
    sshKeyPassphrase.value = ''
    windowsPassword.value = ''
    sshKeyText.value = ''
    sshKeyFileName.value = ''
    authTab.value = row.auth === 'key' ? 'key' : 'password'
    credentialDescription.value = row.credentialDescription || ''
    const root = sshUser.value.trim().toLowerCase() === 'root'
    elevatePrivileges.value = !root
    addToSudoers.value = false
    useSuFallback.value = false
    rootPassword.value = ''
    draftProbe.value = row.probe || null
    draftRecommendation.value = row.recommendation || null
    selectedDraftPackageName.value = row.selectedPackageName || row.agentArtifact?.packageName || ''
    draftHostKey.value = row.hostKey
    draftPrivilege.value = row.privilege || null
    probedPort.value = row.probe ? row.port : null
    probeError.value = ''
    windowsPreflightResult.value = null
    if (row.probe && row.recommendation) {
      void ensureAgentCatalog().then(() => syncDraftPackageSelection(row.selectedPackageName || row.agentArtifact?.packageName))
    }
  }
  if (mode === 'component') {
    pendingComponent.value = row.component || 'kit'
    // Windows only supports the common Deployment Kit. Preselect it so the
    // operator can confirm the default action immediately after saving the
    // credentials; Linux keeps its explicit component choice unchanged.
    if (row.platform === 'windows' && !pendingComponent.value) pendingComponent.value = 'kit'
    pendingManualProfile.value = row.installMode === 'manual' ? row.manualProfile : (deploymentProfileFor(row.component) || 'kit-only')
    selectedManualArtifactName.value = row.agentArtifact?.packageName || row.selectedPackageName || ''
    restoreManualCommand(drawerManualCommand, row.manualCommand)
  }
}

function closeDrawer(): void {
  closeAgentCache()
  drawerOpen.value = false
  sshPassword.value = ''
  sshKeyPassphrase.value = ''
  windowsPassword.value = ''
  sshKeyText.value = '' // clear secrets from state immediately
  sshKeyFileName.value = ''
  credentialDescription.value = ''
  passwordVisible.value = false
  passphraseVisible.value = false
  rootPasswordVisible.value = false
  rootPassword.value = ''
  draftProbe.value = null
  draftRecommendation.value = null
  selectedDraftPackageName.value = ''
  draftHostKey.value = ''
  draftPrivilege.value = null
  probedPort.value = null
  probeError.value = ''
  windowsPreflightResult.value = null
  pendingComponent.value = ''
  pendingManualProfile.value = 'kit-only'
  selectedManualArtifactName.value = ''
  drawerManualBusy.value = false
  resetManualCommand(drawerManualCommand)
}

async function probeSystem(): Promise<void> {
  const row = current.value
  if (!row || !credValid.value || probeBusy.value) return
  const probeRevision = credentialRevision.value
  probeBusy.value = true
  probeError.value = ''
  draftProbe.value = null
  draftRecommendation.value = null
  draftPrivilege.value = null
  selectedDraftPackageName.value = ''
  probedPort.value = null
  try {
    const port = sshPort.value
    const pinned = row.hostKey && row.port === port ? { hostKey: row.hostKey } : await captureHostKey(row.host, port)
    const probe = await probeSSH({
      host: row.host,
      port,
      user: sshUser.value.trim(),
      password: authTab.value === 'password' ? sshPassword.value : undefined,
      privateKeyPem: authTab.value === 'key' ? sshKeyText.value : undefined,
      passphrase: authTab.value === 'key' ? sshKeyPassphrase.value : undefined,
      hostKey: pinned.hostKey,
      privilege: privilege.value,
      elevatePrivileges: elevatePrivileges.value,
      sudoPassword: effectiveSudoPassword.value || undefined,
      addToSudoers: addToSudoers.value,
      useSuFallback: useSuFallback.value,
      rootPassword: rootPassword.value || undefined,
    })
    if (probeRevision !== credentialRevision.value) return
    const recommendation = await matchProbe(probe)
    if (probeRevision !== credentialRevision.value) return
    if (
      authTab.value === 'key'
      && sshPassword.value === ''
      && probe.privilege.mode !== 'root'
      && probe.privilege.mode !== 'sudo-nopasswd'
    ) {
      probeError.value = t('errorpresentation.sudo.requires.the.current.account.password')
      toast(t('deploy.system.probe.failed.2'), probeError.value)
      return
    }
    draftHostKey.value = pinned.hostKey
    probedPort.value = port
    draftProbe.value = probe
    draftPrivilege.value = probe.privilege
    draftRecommendation.value = recommendation
    probedCredentialRevision.value = probeRevision
    await ensureAgentCatalog()
    syncDraftPackageSelection()
    toast(
      t('deploy.system.probe.completed'),
      `${probe.os.id || 'Linux'} ${probe.os.versionId || ''} · ${recommendation.recommendation.recommendedPackageId}`,
    )
  } catch (e) {
    probeError.value = formatLinuxRemoteError(e, row.host, sshPort.value, authTab.value, 'probe')
    toast(t('deploy.system.probe.failed.2'), probeError.value)
  } finally {
    probeBusy.value = false
  }
}

async function probeWindows(): Promise<void> {
  const row = current.value
  if (!row || row.platform !== 'windows' || !windowsCredValid.value || windowsProbeBusy.value) return
  windowsProbeBusy.value = true
  probeError.value = ''
  try {
    const result = await windowsPreflight({ host: row.host, username: windowsUser.value.trim(), password: windowsPassword.value })
    windowsPreflightResult.value = result
    if (result.status !== 'ready') {
      probeError.value = formatWindowsRemoteError(result, row.host)
      return
    }
    toast(t('deploy.windows.remote.install.probe.completed'), row.host)
  } catch (e) {
    probeError.value = formatWindowsRemoteError(e, row.host)
    windowsPreflightResult.value = null
  } finally {
    windowsProbeBusy.value = false
  }
}

async function saveCredential(): Promise<void> {
  const row = current.value
  if (!row || !credentialReady.value || credentialSaving.value) return
  if (row.platform === 'windows') {
    row.user = windowsUser.value.trim()
    row.port = 445
    row.auth = 'password'
    row.component = 'kit'
    row.manualProfile = 'kit-only'
    row.manualArtifact = undefined
    row.status = 'cred-ready'
    row.detail = ''
    secrets.set(row.host, { password: windowsPassword.value, windows: true })
    const detail = `${row.user}@${row.host}`
    closeDrawer()
    toast(t('deploy.windows.connection.credentials.saved'), detail)
    return
  }
  if (!draftProbe.value || !draftRecommendation.value) return
  credentialSaving.value = true
  try {
    const selectedPackageName = selectedDraftPackageName.value || defaultDraftPackageName.value
    const selectionRecommendation = selectedPackageName && selectedPackageName !== defaultDraftPackageName.value
      ? await matchOverride({
          packageId: selectedPackageName,
          reason: `Selected after probing ${draftProbe.value.os.id || 'linux'} ${draftProbe.value.os.versionId || ''}`.trim(),
          user: sshUser.value.trim(),
        })
      : draftRecommendation.value
    row.user = sshUser.value.trim()
    row.port = sshPort.value
    row.auth = authTab.value
    row.credentialDescription = credentialDescription.value.trim()
    row.hostKey = draftHostKey.value
    row.probe = draftProbe.value
    row.recommendation = draftRecommendation.value
    row.selectionRecommendation = selectionRecommendation
    row.selectedPackageName = selectedPackageName
    row.agentArtifact = cachedArtifactByName(selectedPackageName) || draftAgentArtifact.value
    row.privilege = draftPrivilege.value || undefined
    row.component = pendingComponent.value || 'kit'
    row.manualProfile = deploymentProfileFor(row.component) || 'kit-only'
    row.manualArtifact = undefined
    row.status = 'cred-ready'
    row.detail = ''
    // Keep the secret in browser memory for this host so a failed installation
    // can be retried without forcing the operator to re-enter credentials.
    secrets.set(row.host, {
      password: authTab.value === 'password' ? sshPassword.value : undefined,
      key: authTab.value === 'key' ? sshKeyText.value : undefined,
      passphrase: authTab.value === 'key' ? sshKeyPassphrase.value : undefined,
      privilege: privilege.value,
      elevatePrivileges: elevatePrivileges.value,
      // In private-key mode, Password is kept only as the connected account's
      // sudo password. It is deliberately not copied into SSH authentication.
      sudoPassword: effectiveSudoPassword.value || undefined,
      addToSudoers: addToSudoers.value,
      useSuFallback: useSuFallback.value,
      rootPassword: rootPassword.value || undefined,
    })
    const detail = `${row.user}@${row.host}:${row.port} · ${selectedPackageName || row.recommendation.recommendation.recommendedPackageId || 'Linux'}`
    closeDrawer()
    toast(t('deploy.linux.connection.credentials.saved'), detail)
  } catch (e) {
    toast(t('deploy.credential.save.failed'), (e as Error).message)
  } finally {
    credentialSaving.value = false
  }
}

function acceptKeyFile(file: File | null): void {
  if (!file) return
  sshKeyFileName.value = file.name
  file.text().then(
    (keyText) => {
      sshKeyText.value = keyText
      toast(t('deploy.key.loaded'), file.name)
    },
    () => toast(t('deploy.cannot.read.file'), file.name),
  )
}

function privilegeModeLabel(mode?: LinuxPrivilegeResult['mode']): string {
  switch (mode) {
    case 'root': return t('deploy.direct.root')
    case 'sudo-nopasswd': return t('deploy.sudo.no.password')
    case 'sudo-password': return t('deploy.sudo.account.password')
    case 'su': return t('deploy.su.root.password')
    default: return t('deploy.not.verified')
  }
}

// Remote SSH supports two certificate-ready payload profiles. Both include the
// Deployment Kit required by the credential-free Protection Group flow.
function chooseComponent(which: 'kit' | 'agent-plus-kit'): void {
  if (!current.value) return
  if (current.value.platform === 'windows' && which !== 'kit') return
  const needsAgent = which === 'agent-plus-kit'
  const matchingArtifact = needsAgent ? artifactForRow(current.value) : undefined
  if (needsAgent && !matchingArtifact) {
    toast(
      t('deploy.matching.agent.package.is.missing'),
      t('deploy.fetch.the.agent.package.recommended.for.the'),
    )
    return
  }
  if (pendingComponent.value !== which) resetManualCommand(drawerManualCommand)
  pendingComponent.value = which
}

function updateAutomaticComponent(value: string): void {
  if (value === 'kit' || value === 'agent-plus-kit') pendingComponent.value = value
}

function profileComponent(profile: DeploymentProfile): HostRow['component'] {
  if (profile === 'agent-plus-kit') return 'agent-plus-kit'
  return 'kit'
}

const pendingManualArtifact = computed(() => cachedArtifactByName(selectedManualArtifactName.value))
const manualSelectionValid = computed(() => {
  if (!current.value || current.value.installMode !== 'manual') return false
  if (current.value.platform === 'windows') return !!props.kitPath && pendingManualProfile.value === 'kit-only'
  const needsAgent = pendingManualProfile.value === 'agent-plus-kit'
  return !!props.kitPath && (!needsAgent || !!pendingManualArtifact.value)
})

const componentAgentAvailable = computed(() => {
  if (drawerMode.value === 'credential') return !!draftAgentArtifact.value
  return canUseAgent(current.value)
})

function chooseManualProfile(profile: DeploymentProfile): void {
  if (!current.value || current.value.installMode !== 'manual') return
  if (current.value.platform === 'windows' && profile !== 'kit-only') return
  const changed = current.value.manualProfile !== profile
  pendingManualProfile.value = profile
  pendingComponent.value = profileComponent(profile)
  selectedManualArtifactName.value = profile === 'kit-only' ? '' : selectedManualArtifactName.value
  resetManualCommand(drawerManualCommand)
  if (changed) {
    current.value.manualCommand = undefined
    current.value.manualArtifact = undefined
    current.value.deploymentKitProbe = undefined
    current.value.status = 'manual-pending'
    current.value.detail = ''
    emit('host-state', current.value.host, current.value.platform, current.value.component, 'manual', false, '')
  }
}

function updateManualProfile(value: string): void {
  if (value === 'kit-only' || value === 'agent-plus-kit') chooseManualProfile(value)
}

function updateManualArtifact(value: string): void {
  selectedManualArtifactName.value = value
  invalidateManualArtifactSelection()
}

function invalidateManualArtifactSelection(): void {
  const row = current.value
  if (!row || row.installMode !== 'manual') return
  if (row.manualArtifact?.packageName === selectedManualArtifactName.value) return
  row.manualCommand = undefined
  row.manualArtifact = undefined
  row.deploymentKitProbe = undefined
  row.status = 'manual-pending'
  row.detail = ''
  resetManualCommand(drawerManualCommand)
  emit('host-state', row.host, row.platform, row.component, 'manual', false, '')
}

const componentSelectionValid = computed(() => {
  if (!current.value || !pendingComponent.value) return false
  if (current.value.platform === 'windows') return pendingComponent.value === 'kit' && !!props.kitPath
  if (pendingComponent.value === 'kit') return !!props.kitPath
  return !!props.kitPath && componentAgentAvailable.value
})

const credentialReady = computed(() => {
  if (!credValid.value || !probeReady.value || privateKeyAccountPasswordMissing.value) return false
  return componentSelectionValid.value
})

function confirmComponent(): void {
  const row = current.value
  if (!row) return

  if (row.installMode === 'manual') {
    if (!manualSelectionValid.value) return
    row.manualProfile = pendingManualProfile.value
    row.component = profileComponent(pendingManualProfile.value)
    row.manualArtifact = pendingManualArtifact.value
    row.agentArtifact = pendingManualArtifact.value
    row.selectedPackageName = pendingManualArtifact.value?.packageName || ''
    row.manualCommand = drawerManualCommand.status === 'ready' ? { ...drawerManualCommand } : row.manualCommand
    row.deploymentKitProbe = undefined
    row.status = 'manual-pending'
    row.detail = ''
    secrets.delete(row.host)
    emit('host-state', row.host, row.platform, row.component, 'manual', false, '')
    closeDrawer()
    toast(t('deploy.manual.install.configuration.saved'), row.host)
    return
  }

  if (!componentSelectionValid.value || !pendingComponent.value) return
  const which = pendingComponent.value
  const needsAgent = which === 'agent-plus-kit'
  row.component = which
  row.agentArtifact = needsAgent ? artifactForRow(row) : undefined
  row.manualArtifact = undefined
  row.manualCommand = undefined
  row.deploymentKitProbe = undefined
  if (row.status === 'installed') {
    emit('host-state', row.host, row.platform, which, 'remote', true, row.version)
  } else {
    // Manual mode intentionally destroys the SSH secret. If the operator
    // switches this host back to remote mode, metadata such as the username
    // may still be visible, but it must not masquerade as a usable credential.
    row.status = row.auth && secrets.has(row.host) ? 'cred-ready' : 'pending'
    emit('host-state', row.host, row.platform, which, 'remote', false, '')
  }
  closeDrawer()
  toast(
    t('deploy.component.selected'),
    row.host + ` · ${componentLabel(which)}`,
  )
}

function setInstallMode(row: HostRow, mode: InstallMode): void {
  if (row.installMode === mode) {
    advanceHostGuide(row)
    return
  }
  row.installMode = mode
  row.deploymentKitProbe = undefined
  row.manualCommand = undefined
  row.detail = ''
  row.agentArtifact = undefined
  row.selectedPackageName = undefined
  row.probe = undefined
  row.recommendation = undefined
  row.selectionRecommendation = undefined
  row.hostKey = ''
  if (mode === 'manual') {
    row.component = 'kit'
    row.manualProfile = 'kit-only'
    row.manualArtifact = undefined
    row.status = 'manual-pending'
    row.user = ''
    row.auth = ''
    row.credentialDescription = ''
    secrets.delete(row.host)
  } else {
    row.component = ''
    row.manualProfile = 'kit-only'
    row.manualArtifact = undefined
    row.status = secrets.has(row.host) ? 'cred-ready' : 'pending'
  }
  emit('host-state', row.host, row.platform, row.component, mode === 'manual' ? 'manual' : 'remote', false, '')
  advanceHostGuide(row)
}

function manualProbeMessage(result: DeploymentKitProbeResult): string {
  return formatDeploymentKitProbeError(result, result.host)
}

async function probeManualHost(row: HostRow): Promise<void> {
  if (row.installMode !== 'manual' || !row.manualCommand?.command || row.status === 'manual-probing') return
  if (!props.kitCampaignId) {
    row.status = 'manual-failed'
    row.detail = formatDeploymentKitProbeError({ reason: 'deployment_kit_campaign_invalid' }, row.host)
    return
  }
  row.status = 'manual-probing'
  row.detail = ''
  row.deploymentKitProbe = undefined
  try {
    const result = await probeDeploymentKit({ host: row.host, platform: row.platform, campaignId: props.kitCampaignId })
    row.deploymentKitProbe = result
    if (result.status === 'ready') {
      row.status = 'manual-ready'
      emit('host-state', row.host, row.platform, row.component, 'manual', true, '')
      toast(t('deploy.deployment.kit.communication.is.ready.you.can'), row.host)
      return
    }
    row.status = 'manual-failed'
    row.detail = manualProbeMessage(result)
    emit('host-state', row.host, row.platform, row.component, 'manual', false, '')
    toast(t('deploy.deployment.kit.check.failed'), row.detail)
  } catch (e) {
    row.status = 'manual-failed'
    row.detail = formatDeploymentKitProbeError(e, row.host)
    row.deploymentKitProbe = undefined
    emit('host-state', row.host, row.platform, row.component, 'manual', false, '')
    toast(t('deploy.deployment.kit.check.failed.2'), row.detail)
  }
}

watch(() => props.kitCampaignId, (campaignId, previousCampaignId) => {
  if (campaignId === previousCampaignId) return
  hosts.forEach((row) => {
    if (row.installMode !== 'manual') return
    row.deploymentKitProbe = undefined
    row.status = row.manualCommand?.status === 'ready' ? 'manual-pending' : 'manual-pending'
    row.detail = ''
    emit('host-state', row.host, row.platform, row.component, 'manual', false, '')
  })
})

// --- push flow (auto-TOFU host key → install) ----------------------------
async function pushHost(row: HostRow): Promise<void> {
  if (row.platform === 'windows') {
    if (row.component !== 'kit') {
      toast(t('deploy.only.deployment.kit.is.deployed.to.windows'), t('deploy.vbr.deploys.veeam.agent.during.the.protection'))
      return
    }
    await runWindowsInstall(row)
    return
  }
  if (!hasSavedSecret(row)) {
    openDrawer(row, 'credential')
    toast(t('deploy.connection.credentials.required'), t('deploy.reenter.and.test.credentials.before.retrying'))
    return
  }
  const wantsAgent = row.component === 'agent-plus-kit'
  if (!props.kitPath) {
    toast(t('deploy.deployment.kit.missing'), t('deploy.fetch.the.deployment.kit.in.step.1'))
    return
  }
  const packageArtifact = artifactForRow(row)
  if (wantsAgent && !packageArtifact?.path) {
    toast(t('deploy.agent.package.missing'), t('deploy.export.and.cache.the.agent.package.that'))
    return
  }
  row.status = 'pushing'
  row.detail = ''
  if (!row.hostKey) {
    // Auto-TOFU (owner decision 2026-08-14): capture the host key WITHOUT
    // trusting it and pin on first use — no confirmation dialog. The pin is
    // enforced from then on; a later key change blocks the connection.
    try {
      const res = await captureHostKey(row.host, row.port)
      row.hostKey = res.hostKey
    } catch (e) {
      row.status = 'failed'
      row.detail = formatLinuxRemoteError(e, row.host, row.port, row.auth, 'probe')
      toast(t('deploy.cannot.retrieve.host.key'), row.detail)
      return
    }
  }
  await runInstall(row)
}

async function runWindowsInstall(row: HostRow): Promise<void> {
  const secret = secrets.get(row.host)
  if (!secret?.windows || !secret.password) {
    toast(t('deploy.windows.administrator.credentials.missing'), t('deploy.save.credentials.and.complete.the.remote.installation'))
    return
  }
  if (!props.kitPath) {
    toast(t('deploy.deployment.kit.missing.2'), t('deploy.fetch.the.deployment.kit.in.step.1.2'))
    return
  }
  row.status = 'pushing'
  row.detail = ''
  try {
    const res = await windowsInstall({ host: row.host, username: row.user, password: secret.password, campaignId: props.kitCampaignId, kitPath: props.kitPath, kitSha256: props.kitSha256 })
    if (res.status !== 'installed') {
      row.status = 'failed'
      row.detail = formatWindowsRemoteError(res, row.host)
      toast(t('deploy.windows.remote.install.failed'), row.detail)
      return
    }
    row.status = 'installed'
    row.installMode = 'automatic'
    row.version = ''
    emit('host-state', row.host, row.platform, row.component || 'kit', 'remote', true, '')
    toast(t('deploy.windows.deployment.kit.installed'), row.host)
  } catch (e) {
    row.status = 'failed'
    row.detail = formatWindowsRemoteError(e, row.host)
    toast(t('deploy.windows.remote.install.failed.2'), row.detail)
  }
}

async function runInstall(row: HostRow): Promise<void> {
  row.status = 'pushing'
  row.detail = ''
  try {
    const wantsAgent = row.component === 'agent-plus-kit'
    const packageArtifact = artifactForRow(row)
    const res = await install({
      host: row.host,
      port: row.port,
      user: row.user,
      password: row.auth === 'password' ? sshPasswordFor(row) : undefined,
      privateKeyPem: row.auth === 'key' ? keyFor(row) : undefined,
      passphrase: row.auth === 'key' ? secretFor(row)?.passphrase : undefined,
      hostKey: row.hostKey,
      privilege: privilegeFor(row),
      elevatePrivileges: secretFor(row)?.elevatePrivileges,
      sudoPassword: secretFor(row)?.sudoPassword,
      addToSudoers: secretFor(row)?.addToSudoers,
      useSuFallback: secretFor(row)?.useSuFallback,
      rootPassword: secretFor(row)?.rootPassword,
      kitPath: props.kitPath,
      packagePath: wantsAgent ? packageArtifact?.path : undefined,
      packageId: wantsAgent ? packageArtifact?.packageName : undefined,
      // An Agent component can only reach this path after the operator chose
      // it in the component drawer and clicked "Confirm selection". Carry
      // that acknowledgement into the backend selection step, including for
      // community rebuilds and hosts with an existing Agent installation.
      confirmSelection: wantsAgent,
      deploymentProfile: row.component === 'agent-plus-kit' ? 'agent-plus-kit' : 'kit-only',
    })
    row.status = 'installed'
    row.installMode = 'automatic'
    row.manualCommand = undefined
    row.version = res.verified?.packageVersion || ''
    row.detail = '' // Keep the table status badge-only.
    emit('host-state', row.host, row.platform, row.component || 'kit', 'remote', true, row.version)
    const selected = res.packageSelection?.selected?.map((p) => p.fileName).join(', ')
    toast(t('deploy.deployment.complete'), selected ? `${row.host} · ${selected}` : row.host + t('deploy.passed.component.verification'))
  } catch (e) {
    row.status = 'failed'
    row.detail = formatLinuxRemoteError(e, row.host, row.port, row.auth, 'install')
    toast(t('deploy.deployment.failed.2'), row.detail)
  }
}

// Per-host secrets remain only in this component's memory for the current
// browser session so retries can reuse them. They are deleted when the host is
// removed, switched to manual mode, or the component is unmounted; they are
// never persisted by AgentBridge.
interface HostSecret {
  password?: string
  key?: string
  passphrase?: string
  privilege?: 'root' | 'sudo'
  elevatePrivileges?: boolean
  sudoPassword?: string
  addToSudoers?: boolean
  useSuFallback?: boolean
  rootPassword?: string
  windows?: boolean
}
const secrets = new Map<string, HostSecret>()
function secretFor(row: HostRow): HostSecret | undefined {
  return secrets.get(row.host)
}
function sshPasswordFor(row: HostRow): string | undefined {
  return secretFor(row)?.password
}
function keyFor(row: HostRow): string | undefined {
  return secretFor(row)?.key
}
function privilegeFor(row: HostRow): 'root' | 'sudo' {
  return secretFor(row)?.privilege || 'root'
}

function hasSavedSecret(row: HostRow): boolean {
  const secret = secrets.get(row.host)
  if (!secret) return false
  if (row.platform === 'windows') return !!secret.windows && !!secret.password
  if (row.auth === 'password') return !!secret.password
  if (row.auth === 'key') return !!secret.key
  return false
}

function deploymentProfileFor(component: HostRow['component']): DeploymentProfile | '' {
  if (component === 'kit') return 'kit-only'
  if (component === 'agent-plus-kit') return 'agent-plus-kit'
  return ''
}

// --- manual install (zero-credential pull path) --------------------------
const drawerManualCanGenerate = computed(() => {
  if (!current.value || current.value.installMode !== 'manual' || !manualSelectionValid.value) return false
  return true
})

async function generateHostManualCommand(): Promise<void> {
  const row = current.value
  const profile = pendingManualProfile.value
  if (!row || !profile || !drawerManualCanGenerate.value || drawerManualBusy.value) return

  const component = profileComponent(profile)
  const wantsAgent = component === 'agent-plus-kit'
  const artifact = wantsAgent ? pendingManualArtifact.value : undefined
  if (wantsAgent && !artifact?.path) {
    drawerManualCommand.status = 'failed'
    drawerManualCommand.detail = t('deploy.the.agent.package.matching.this.host.is')
    return
  }

  drawerManualBusy.value = true
  drawerManualCommand.status = 'generating'
  drawerManualCommand.detail = ''
  try {
    const result = await generateManualInstall({
      packagePath: wantsAgent ? artifact?.path : undefined,
      packageId: wantsAgent ? artifact?.packageName : undefined,
      packageSha256: wantsAgent ? artifact?.sha256 : undefined,
      kitPath: props.kitPath,
      deploymentProfile: profile,
      platform: row.platform,
      campaignId: props.kitCampaignId,
      kitSha256: props.kitSha256,
    })
    drawerManualCommand.command = result.command
    drawerManualCommand.expiresAt = result.expiresAt
    drawerManualCommand.status = 'ready'
    row.manualProfile = profile
    row.component = profileComponent(profile)
    row.manualArtifact = artifact
    row.agentArtifact = artifact
    row.selectedPackageName = artifact?.packageName || ''
    row.manualCommand = { ...drawerManualCommand }
    row.deploymentKitProbe = undefined
    row.status = 'manual-pending'
    row.detail = ''
    emit('host-state', row.host, row.platform, row.component, 'manual', false, '')
    toast(t('deploy.host.install.command.ready'), row.host)
  } catch (e) {
    drawerManualCommand.status = 'failed'
    drawerManualCommand.detail = (e as Error).message
    toast(t('deploy.command.generation.failed'), drawerManualCommand.detail)
  } finally {
    drawerManualBusy.value = false
  }
}

async function copyHostManualCommand(): Promise<void> {
  if (!drawerManualCommand.command) return
  try {
    await navigator.clipboard.writeText(drawerManualCommand.command)
    toast(t('deploy.command.copied'), current.value?.host || '')
  } catch {
    toast(t('deploy.copy.failed'), t('deploy.select.and.copy.the.command.manually'))
  }
}
</script>

<template>
  <div class="table-wrap">
    <div class="table-toolbar">
      <div>
        <strong>{{ t('deploy.target.hosts') }}</strong>
        <div class="step-summary">{{ hosts.length }} {{ t('deploy.hosts') }} · {{ readyCount }} {{ t('deploy.ready') }}</div>
      </div>
      <div class="row">
        <button v-if="hosts.length && !addMode" class="btn small host-guide-replay" @click="startHostGuide(hosts[0])">
          <span class="host-guide-help" aria-hidden="true">?</span>
          {{ t('deploy.operation.guide') }}
        </button>
        <div v-if="addMode" class="row">
          <input v-model="addingHost" class="fieldbox mono" type="text" style="width:190px" :placeholder="t('deploy.ip.or.hostname')" @keyup.enter="addHost" />
          <CustomSelect
            class="platform-select"
            compact
            :model-value="addingPlatform"
            :options="platformSelectOptions"
            :ariaLabel="t('deploy.operating.system')"
            @update:model-value="updateAddingPlatform"
          />
          <button class="btn small primary" @click="addHost">{{ t('deploy.confirm') }}</button>
          <button class="btn small" @click="addMode = false; addingHost = ''">{{ t('deploy.cancel') }}</button>
        </div>
        <button v-else class="btn small" @click="addMode = true">＋ {{ t('deploy.add.host') }}</button>
      </div>
    </div>
    <table class="table host-table">
      <colgroup>
        <col class="host-column" />
        <col class="os-column" />
        <col class="mode-column" />
        <col class="component-column" />
        <col class="credential-column" />
        <col class="status-column" />
        <col class="action-column" />
      </colgroup>
      <thead>
        <tr>
          <th>{{ t('deploy.host.ip') }}</th>
          <th>{{ t('deploy.operating.system.2') }}</th>
          <th>{{ t('deploy.install.method') }}</th>
          <th>{{ t('deploy.component') }}</th>
          <th>{{ t('deploy.connection.credentials') }}</th>
          <th>{{ t('deploy.status') }}</th>
          <th>{{ t('deploy.actions') }}</th>
        </tr>
      </thead>
      <tbody>
        <tr v-if="!hosts.length">
          <td colspan="7" style="text-align:center">{{ t('deploy.no.hosts.yet.click.add.host.to') }}</td>
        </tr>
        <template v-for="row in hosts" :key="row.host">
          <tr>
            <td class="host">{{ row.host }}<span v-if="row.platform === 'linux' && row.port !== 22">:{{ row.port }}</span></td>
            <td class="os-cell"><span class="badge">{{ row.platform === 'windows' ? 'Windows · SMB/RPC' : 'Linux · SSH' }}</span></td>
            <td class="mode-cell">
              <div class="install-mode-inline" :class="{ 'guide-target': hostGuideHost === row.host && hostGuideStep === 'method' }" role="group" :aria-label="t('deploy.install.method.2', row.host)">
                <button type="button" class="mode-chip manual" :class="{ active: row.installMode === 'manual' }" :title="t('deploy.m.manual.install')" :aria-label="t('deploy.switch.to.manual.install')" :aria-pressed="row.installMode === 'manual'" @click="setInstallMode(row, 'manual')">M</button>
                <button type="button" class="mode-chip automatic" :class="{ active: row.installMode === 'automatic' }" :title="t('deploy.a.automatic.install')" :aria-label="t('deploy.switch.to.automatic.install')" :aria-pressed="row.installMode === 'automatic'" @click="setInstallMode(row, 'automatic')">A</button>
              </div>
              <div v-if="hostGuideHost === row.host && hostGuideStep === 'method'" class="host-guide-popover host-guide-method" role="dialog" :aria-label="t('deploy.install.method.guide')">
                <span class="host-guide-eyebrow">{{ t('deploy.step.1.of.2') }}</span>
                <strong>{{ t('deploy.confirm.the.install.method') }}</strong>
                <p>{{ t('deploy.m.is.manual.install.a.is.automatic') }}</p>
                <div class="host-guide-actions">
                  <button class="btn" @click="skipAllHostGuide">{{ t('deploy.skip.all.guide.steps') }}</button>
                  <button class="btn primary" @click="advanceHostGuide(row)">{{ t('deploy.next.guide.step') }}</button>
                </div>
              </div>
            </td>
            <td class="component-cell" :title="componentLabel(row.component)">{{ componentLabel(row.component) }}</td>
            <td class="credential-cell">
              <span v-if="row.user" class="badge ready" :title="row.credentialDescription || row.user">{{ row.user }}<template v-if="row.credentialDescription"> ({{ row.credentialDescription }})</template> · {{ row.platform === 'windows' ? t('deploy.administrator.password') : row.auth === 'key' ? t('deploy.ssh.private.key') : t('deploy.ssh.credentials') }}<template v-if="row.platform === 'linux' && row.port !== 22"> · :{{ row.port }}</template></span>
              <span v-else>{{ t('deploy.not.configured') }}</span>
            </td>
            <td class="status-cell">
              <span class="badge" :class="statusBadge(row).cls">
                <HourglassIndicator v-if="row.status === 'pushing' || row.status === 'manual-probing'" />
                {{ statusBadge(row).text }}
              </span>
              <button
                v-if="row.installMode === 'manual' && row.manualCommand?.status === 'ready' && row.status !== 'manual-ready'"
                class="btn small failure-link"
                :disabled="row.status === 'manual-probing'"
                @click="probeManualHost(row)"
              >
                {{ row.status === 'manual-failed' ? t('deploy.retry.check') : t('deploy.check') }}
              </button>
              <button v-if="row.status === 'failed' || row.status === 'manual-failed'" class="btn small failure-link" @click="openFailureDrawer(row)">
                {{ t('deploy.details') }}
              </button>
            </td>
            <td class="action-cell" :class="{ open: openMenu === row.host, 'menu-up': hosts[hosts.length - 1] === row }">
              <button class="btn small action-trigger" :class="{ 'guide-target': hostGuideHost === row.host && hostGuideStep === 'actions' }" :aria-expanded="openMenu === row.host" aria-haspopup="menu" @click.stop="toggleActionMenu(row)">
                <svg width="16" viewBox="0 0 24 24" fill="currentColor"><circle cx="5" cy="12" r="1.6" /><circle cx="12" cy="12" r="1.6" /><circle cx="19" cy="12" r="1.6" /></svg>
              </button>
              <div v-if="hostGuideHost === row.host && hostGuideStep === 'actions'" class="host-guide-popover host-guide-actions-menu" role="dialog" :aria-label="t('deploy.actions.guide')">
                <span class="host-guide-eyebrow">{{ t('deploy.step.2.of.2') }}</span>
                <strong>{{ t('deploy.continue.from.the.actions.menu') }}</strong>
                <p>{{ row.installMode === 'manual' ? t('deploy.manual.action.guide') : t('deploy.automatic.action.guide') }}</p>
                <div class="host-guide-actions">
                  <button class="btn" @click="skipAllHostGuide">{{ t('deploy.skip.all.guide.steps') }}</button>
                  <button class="btn primary" @click="openGuidedActionMenu(row)">{{ t('deploy.open.actions.menu') }}</button>
                </div>
              </div>
              <div class="action-menu" role="menu" :aria-label="t('deploy.actions.2', row.host)">
                <template v-if="row.installMode === 'manual'">
                  <button class="menu-action" role="menuitem" @click="openMenu = null; openDrawer(row, 'component')">{{ t('deploy.generate.installation.command.2') }}</button>
                </template>
                <template v-else>
                  <button class="menu-action" role="menuitem" @click="openMenu = null; openDrawer(row, 'credential')">{{ t('deploy.configure.automatic.deployment.2') }}</button>
                  <button class="menu-action" role="menuitem" :disabled="!row.user || !hasSavedSecret(row) || !['kit', 'agent-plus-kit'].includes(row.component) || row.status === 'pushing'" @click="openMenu = null; pushHost(row)">{{ row.platform === 'windows' ? t('deploy.deploy.deployment.kit') : t('deploy.start.deployment') }}</button>
                </template>
                <button class="menu-action danger" role="menuitem" @click="openMenu = null; deleteHost(row)">{{ t('deploy.delete.host') }}</button>
              </div>
            </td>
          </tr>
        </template>
      </tbody>
    </table>
  </div>

  <div class="actions">
    <button class="btn" @click="emit('back')">{{ t('deploy.back.to.connection') }}</button>
    <div class="actions-right">
      <button class="btn primary" :disabled="!readyCount" @click="emit('next')">
        {{ t('deploy.confirm.hosts.and.continue') }}
      </button>
    </div>
  </div>

  <Drawer :open="drawerOpen" :eyebrow="drawerMeta.eyebrow" :title="drawerMeta.title" @close="closeDrawer">
    <template #default>
      <!-- credential mode -->
      <div v-if="drawerMode === 'credential'">
        <div class="credential-component-box">
          <strong>{{ t('deploy.install.profile') }}</strong>
          <p v-if="current?.platform === 'windows'" class="step-summary">{{ t('deploy.deployment.kit.only.description') }}</p>
          <CustomSelect
            v-else
            :model-value="pendingComponent"
            :options="automaticComponentSelectOptions"
            :ariaLabel="t('deploy.install.profile.2')"
            @update:model-value="updateAutomaticComponent"
          />
          <p v-if="current?.platform !== 'windows' && pendingComponent !== 'kit' && !componentAgentAvailable" class="error-text">{{ t('deploy.select.or.cache.a.matching.agent.package') }}</p>
        </div>
        <div v-if="current?.platform === 'windows'">
          <div class="field">
            <label>{{ t('deploy.administrator.username') }}</label>
            <input v-model.trim="windowsUser" class="fieldbox" type="text" :placeholder="t('deploy.e.g.administrator.or.contoso.admin')" />
          </div>
          <div class="field">
            <label>{{ t('deploy.administrator.password.2') }}</label>
            <input v-model="windowsPassword" class="fieldbox" type="password" :placeholder="t('deploy.windows.administrator.password')" />
          </div>
          <div v-if="windowsProbeBusy || windowsPreflightResult || probeError" class="probe-result" :class="{ failed: !!probeError }" role="status">
            <div class="probe-result-head">
              <strong v-if="windowsProbeBusy"><HourglassIndicator />{{ t('deploy.testing.credentials') }}</strong>
              <strong v-else-if="windowsPreflightResult?.status === 'ready'">{{ t('deploy.credentials.are.valid') }}</strong>
              <strong v-else>{{ t('deploy.credential.test.failed') }}</strong>
            </div>
            <p v-if="probeError" class="error-text">{{ probeError }}</p>
          </div>
        </div>
        <div v-else>
        <div class="tabs credential-type-tabs" role="tablist" :aria-label="t('deploy.credentials')">
          <button class="tab" :class="{ active: authTab === 'password' }" role="tab" :aria-selected="authTab === 'password'" @click="selectCredentialType('password')">{{ t('deploy.ssh.credentials') }}</button>
          <button class="tab" :class="{ active: authTab === 'key' }" role="tab" :aria-selected="authTab === 'key'" @click="selectCredentialType('key')">{{ t('deploy.ssh.private.key') }}</button>
        </div>
        <div class="veeam-credential-form">
          <div class="field">
            <label for="ssh-username">{{ t('deploy.username.2') }}</label>
            <input id="ssh-username" v-model.trim="sshUser" class="fieldbox" type="text" autocomplete="username" />
          </div>
          <div class="field">
            <label for="ssh-password">{{ t('deploy.password.2') }}</label>
            <div class="secret-fieldbox">
              <input id="ssh-password" v-model="sshPassword" class="fieldbox" :type="passwordVisible ? 'text' : 'password'" autocomplete="current-password" />
              <button type="button" :aria-label="t('deploy.show.password')" @pointerdown.prevent="passwordVisible = true" @pointerup="passwordVisible = false" @pointerleave="passwordVisible = false" @pointercancel="passwordVisible = false">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" /><circle cx="12" cy="12" r="2.6" /></svg>
              </button>
            </div>
          </div>
          <template v-if="authTab === 'key'">
            <div class="field">
              <label for="ssh-private-key-name">{{ t('deploy.private.key') }}</label>
              <div class="credential-file-row">
                <input id="ssh-private-key-name" class="fieldbox" type="text" :value="sshKeyFileName" readonly />
                <button type="button" class="btn credential-browse" @click="keyFileInput?.click()">{{ t('deploy.browse') }}</button>
              </div>
              <input ref="keyFileInput" type="file" accept=".pem,.key" class="hidden" @change="acceptKeyFile(keyFileInput?.files?.[0] || null)" />
            </div>
            <div class="field">
              <label for="ssh-key-passphrase">{{ t('deploy.passphrase') }}</label>
              <div class="secret-fieldbox">
                <input id="ssh-key-passphrase" v-model="sshKeyPassphrase" class="fieldbox" :type="passphraseVisible ? 'text' : 'password'" autocomplete="off" />
                <button type="button" :aria-label="t('deploy.show.passphrase')" @pointerdown.prevent="passphraseVisible = true" @pointerup="passphraseVisible = false" @pointerleave="passphraseVisible = false" @pointercancel="passphraseVisible = false">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" /><circle cx="12" cy="12" r="2.6" /></svg>
                </button>
              </div>
              <p class="credential-field-help">{{ t('deploy.private.key.passphrase.rule') }}</p>
            </div>
          </template>
          <div class="field ssh-port-row">
            <label for="ssh-port">{{ authTab === 'key' ? t('deploy.ssh.port.private.key') : t('deploy.ssh.port') }}</label>
            <input id="ssh-port" v-model.number="sshPort" class="fieldbox mono ssh-port-field" type="number" inputmode="numeric" min="1" max="65535" step="1" />
            <p v-if="!sshPortValid" class="error-text" role="alert">{{ t('deploy.enter.a.valid.port.between.1.and') }}</p>
          </div>
          <section class="privilege-box" :aria-labelledby="'non-root-account-title'">
            <strong id="non-root-account-title">{{ t('deploy.non.root.account') }}</strong>
            <label class="check-row">
              <input v-model="elevatePrivileges" type="checkbox" :disabled="loginIsRoot" />
              <span>{{ t('deploy.elevate.account.privileges.automatically') }}</span>
            </label>
            <div v-if="!loginIsRoot && elevatePrivileges" class="privilege-details">
              <label class="check-row nested">
                <input v-model="addToSudoers" type="checkbox" />
                <span>{{ t('deploy.add.account.to.the.sudoers.file') }}</span>
              </label>
              <label class="check-row nested">
                <input v-model="useSuFallback" type="checkbox" />
                <span>{{ t('deploy.use.su.if.sudo.fails') }}</span>
              </label>
            </div>
            <div v-if="rootPasswordRequired" class="field root-password-field">
              <label for="ssh-root-password">{{ t('deploy.root.password') }}</label>
              <div class="secret-fieldbox">
                <input id="ssh-root-password" v-model="rootPassword" class="fieldbox" :type="rootPasswordVisible ? 'text' : 'password'" autocomplete="off" />
                <button type="button" :aria-label="t('deploy.show.root.password')" @pointerdown.prevent="rootPasswordVisible = true" @pointerup="rootPasswordVisible = false" @pointerleave="rootPasswordVisible = false" @pointercancel="rootPasswordVisible = false">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" /><circle cx="12" cy="12" r="2.6" /></svg>
                </button>
              </div>
            </div>
          </section>
          <div class="field credential-description-field">
            <label for="credential-description">{{ t('deploy.description') }}</label>
            <textarea id="credential-description" v-model="credentialDescription" class="fieldbox tall" />
          </div>
        </div>
        <div class="probe-result" :class="{ failed: !!probeError }">
          <div class="probe-result-head">
            <strong>{{ t('deploy.system.probe') }}</strong>
            <span v-if="probeBusy" class="badge running"><HourglassIndicator />{{ t('deploy.probing.2') }}</span>
            <span v-else-if="draftProbe && draftRecommendation && !probePortStale" class="badge ready">{{ t('deploy.completed.2') }}</span>
            <span v-else-if="probePortStale" class="badge">{{ t('deploy.probe.again') }}</span>
            <span v-else-if="probeError" class="badge failed">{{ t('deploy.failed.3') }}</span>
            <span v-else class="badge">{{ t('deploy.not.probed.2') }}</span>
          </div>
          <div v-if="draftProbe && draftRecommendation && !probePortStale" class="probe-result-grid">
            <div class="probe-result-item">
              <span>{{ t('deploy.system') }}</span>
              <strong>{{ draftProbe.os.id || 'Linux' }} {{ draftProbe.os.versionId }}</strong>
            </div>
            <div class="probe-result-item">
              <span>{{ t('deploy.architecture.2') }}</span>
              <strong>{{ draftProbe.target.architecture }}</strong>
            </div>
            <div class="probe-result-item">
              <span>{{ t('deploy.privilege') }}</span>
              <strong>{{ privilegeModeLabel(draftPrivilege?.mode) }}</strong>
            </div>
            <div v-if="!draftIsOfficiallySupported" class="compatibility-warning" role="note">
              <strong>{{ t('deploy.compatibility.match') }}</strong>
              <span>{{ t('deploy.this.match.is.based.on.system.compatibility') }}</span>
            </div>
            <div class="agent-candidates">
              <div class="agent-candidates-head">
                <strong>{{ t('deploy.agent.package') }}</strong>
                <span v-if="packageCatalogBusy" class="inline-wait"><HourglassIndicator />{{ t('deploy.loading.catalog') }}</span>
              </div>
              <div v-if="draftPackageCandidates.length" class="agent-candidate-list">
                <button
                  v-for="pkg in draftPackageCandidates"
                  :key="pkg.packageName"
                  type="button"
                  class="agent-candidate"
                  :class="{ selected: selectedDraftPackageName === pkg.packageName }"
                  @click="chooseDraftPackage(pkg.packageName)"
                >
                  <span class="agent-candidate-mark" aria-hidden="true" />
                  <span class="agent-candidate-copy">
                    <strong>{{ pkg.packageName }}</strong>
                    <span v-if="pkg.packageName === defaultDraftPackageName">{{ t('deploy.best.match') }}</span>
                    <span v-else>{{ t('deploy.other.match') }}</span>
                  </span>
                  <span class="badge" :class="{ ready: packageIsCached(pkg.packageName) }">
                    {{ packageIsCached(pkg.packageName) ? t('deploy.cached') : t('deploy.cache') }}
                  </span>
                </button>
              </div>
              <p v-else-if="!packageCatalogBusy" class="error-text probe-package-warning">
                {{ t('deploy.no.agent.package.close.to.the.probe') }}
              </p>
              <p v-if="packageCatalogError" class="error-text probe-package-warning">{{ packageCatalogError }}</p>
              <p v-if="draftSelectionIsOverride" class="step-summary agent-override-note">
                {{ t('deploy.a.non.default.agent.was.explicitly.selected') }}
              </p>
            </div>
          </div>
          <p v-else-if="probePortStale" class="step-summary">{{ t('deploy.the.ssh.port.changed.probe.the.system') }}</p>
          <p v-else-if="probeError" class="error-text">{{ probeError }}</p>
          <p v-else class="step-summary">{{ t('deploy.enter.credentials.then.probe.the.target.system') }}</p>
        </div>
        </div>
      </div>

      <!-- component mode -->
      <div v-else-if="drawerMode === 'component'">
        <p class="step-summary">{{ t('deploy.choose.what.to.deploy.to') }} <strong>{{ current?.host }}</strong> {{ t('deploy.text') }}</p>
        <div v-if="current?.installMode === 'automatic'" class="choice-list">
          <label class="choice" :class="{ selected: pendingComponent === 'kit', disabled: !props.kitPath }" @click="props.kitPath && chooseComponent('kit')">
            <span class="choice-mark" />
            <span>
              <strong>{{ t('deploy.install.deployment.kit.only') }}</strong>
              <span>{{ current?.platform === 'windows' ? t('deploy.deploy.the.deployment.kit.over.smb.rpc') : t('deploy.deploy.the.deployment.kit.over.ssh.vbr') }}</span>
            </span>
          </label>
          <label v-if="current?.platform !== 'windows'" class="choice" :class="{ selected: pendingComponent === 'agent-plus-kit', disabled: !props.kitPath || !canUseAgent(current) }" @click="props.kitPath && canUseAgent(current) && chooseComponent('agent-plus-kit')">
            <span class="choice-mark" />
            <span>
              <strong>{{ t('deploy.install.agent.deployment.kit') }}</strong>
              <span>{{ agentChoiceHint(current) }}</span>
            </span>
          </label>
        </div>
        <div v-else class="drawer-manual-block">
          <div class="manual-profile-box">
            <strong>{{ t('deploy.install.profile.3') }}</strong>
            <span class="badge">{{ current?.platform === 'windows' || pendingManualProfile === 'kit-only' ? t('deploy.deployment.kit.only.4') : componentLabel(profileComponent(pendingManualProfile)) }}</span>
          </div>
          <details v-if="current?.platform === 'linux'" class="manual-advanced" :open="pendingManualProfile !== 'kit-only'">
            <summary>{{ t('deploy.advanced.mode') }}<span>{{ t('deploy.optional.agent.or.full.package') }}</span></summary>
            <div class="manual-advanced-body">
              <label class="field">
                <span>{{ t('deploy.install.profile.4') }}</span>
                <CustomSelect
                  :model-value="pendingManualProfile"
                  :options="manualProfileSelectOptions"
                  :ariaLabel="t('deploy.install.profile.5')"
                  @update:model-value="updateManualProfile"
                />
              </label>
            </div>
          </details>
          <div v-if="current?.platform === 'linux' && pendingManualProfile !== 'kit-only'" class="field manual-agent-select">
            <label>{{ t('deploy.agent.package.2') }} <span>{{ t('deploy.choose.from.cache') }}</span></label>
            <CustomSelect
              :model-value="selectedManualArtifactName"
              :options="manualArtifactSelectOptions"
              :ariaLabel="t('deploy.agent.package.3')"
              @update:model-value="updateManualArtifact"
            />
            <button class="btn small" @click="openAgentCache('')">{{ t('deploy.get.more.packages') }}</button>
          </div>
          <div class="drawer-manual-content">
            <button class="btn primary" :disabled="!drawerManualCanGenerate || drawerManualBusy" @click="generateHostManualCommand">
              <HourglassIndicator v-if="drawerManualBusy" />
              {{ drawerManualBusy ? t('deploy.generating.2') : drawerManualCommand.status === 'ready' ? t('deploy.regenerate.command') : t('deploy.generate.manual.install.command') }}
            </button>
            <div v-if="drawerManualCommand.status === 'ready'" class="manual-inline-command">
              <div class="code manual-command-code">
                {{ drawerManualCommand.command }}
                <button class="copy" :aria-label="t('deploy.copy.command')" @click="copyHostManualCommand">
                  <svg width="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M15 9V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h3" /></svg>
                </button>
              </div>
              <p class="step-summary manual-expiry">{{ t('deploy.valid.until.2') }} {{ new Date(drawerManualCommand.expiresAt).toLocaleString() }}</p>
            </div>
            <p v-if="drawerManualCommand.status === 'failed'" class="error-text">{{ drawerManualCommand.detail }}</p>
          </div>
        </div>
      </div>

      <!-- failure detail mode: terminal-style line-by-line log -->
      <div v-else>
        <p class="error-text" style="margin-bottom:12px">{{ failureSummary }}</p>
        <div v-if="failure.lines.length" class="console">
          <div class="console-bar">
            <span class="dot rd" /><span class="dot yl" /><span class="dot gn" />
            <span class="console-title">{{ t('deploy.installer.output') }} · {{ current?.host }}</span>
          </div>
          <div class="console-body">
            <div v-for="(ln, i) in failure.lines" :key="i" class="console-line" :class="consoleLineClass(ln)">{{ ln || ' ' }}</div>
          </div>
        </div>
        <p v-else class="step-summary" style="margin-top:8px">{{ current?.platform === 'windows' ? t('deploy.the.failure.occurred.before.installer.output.was') : t('deploy.this.failure.carries.no.installer.output') }}</p>
      </div>
    </template>
    <template #foot>
      <button v-if="drawerMode === 'credential'" class="btn" :disabled="!credValid || probeBusy || windowsProbeBusy" @click="current?.platform === 'windows' ? probeWindows() : probeSystem()">
        <HourglassIndicator v-if="probeBusy || windowsProbeBusy" />
        {{ probeBusy || windowsProbeBusy ? t('deploy.testing.credentials') : t('deploy.test.credentials') }}
      </button>
      <button v-if="drawerMode === 'credential'" class="btn primary" :disabled="!credentialReady || credentialSaving || probeBusy || windowsProbeBusy" @click="saveCredential">
        <HourglassIndicator v-if="credentialSaving" />
        {{ credentialSaving ? t('deploy.saving') : t('deploy.save.credentials') }}
      </button>
      <button v-if="drawerMode === 'component'" class="btn primary" :disabled="current?.installMode === 'manual' ? !manualSelectionValid : !componentSelectionValid" @click="confirmComponent">{{ current?.installMode === 'manual' ? t('deploy.save.configuration') : t('deploy.confirm.selection') }}</button>
      <button v-if="drawerMode === 'failure' && current?.installMode === 'automatic'" class="btn primary" :disabled="!current?.user || !current?.component || current?.status === 'pushing'" @click="retryFailed">
        {{ current && hasSavedSecret(current) ? t('deploy.retry.install') : t('deploy.reenter.credentials') }}
      </button>
    </template>
  </Drawer>

  <Drawer
    :open="cacheDrawerOpen"
    :eyebrow="t('deploy.agent.packages')"
    :title="t('deploy.export.from.vbr.and.cache')"
    side="left"
    nested
    @close="closeAgentCache"
  >
    <template #default>
      <div class="package-catalog-head">
        <label>{{ t('deploy.agent.package.catalog.2') }}</label>
        <button class="btn small" :disabled="packageCatalogBusy || cachePackageBusy" @click="refreshAgentCatalog">
          <HourglassIndicator v-if="packageCatalogBusy" />
          {{ packageCatalogBusy ? t('deploy.loading.2') : t('deploy.refresh.catalog.2') }}
        </button>
      </div>
      <div v-if="packageCatalog.length" class="package-filter">
        <input v-model="cachePackageFilter" class="fieldbox" type="search" :placeholder="t('deploy.filter.package.distribution.or.bitness.2')" />
        <button class="btn small package-filter-select" :disabled="!downloadableFilteredCachePackages.length || cachePackageBusy" @click="toggleFilteredCachePackages">
          {{ allFilteredCacheSelected ? t('deploy.clear.visible.2') : t('deploy.select.visible.2') }}
        </button>
        <button class="btn primary small package-filter-download" :disabled="!cacheSelectedCount || cachePackageBusy" @click="downloadSelectedCandidatePackages">
          <HourglassIndicator v-if="cachePackageBusy" />
          {{ cachePackageBusy ? t('deploy.exporting.2') : `${t('deploy.export.and.cache.2')} (${cacheSelectedCount})` }}
        </button>
      </div>
      <div v-if="packageCatalog.length" class="table-wrap agent-cache-table">
        <table class="table">
          <thead>
            <tr>
              <th class="package-check"><input type="checkbox" :checked="allFilteredCacheSelected" :disabled="!downloadableFilteredCachePackages.length || cachePackageBusy" :aria-label="t('deploy.select.visible.packages.2')" @change="toggleFilteredCachePackages" /></th>
              <th>{{ t('deploy.package') }}</th>
              <th>{{ t('deploy.distribution.2') }}</th>
              <th>{{ t('deploy.architecture.3') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="pkg in filteredCachePackages" :key="`${pkg.packageName}-${pkg.distributionName}-${pkg.packageBitness}`">
              <td class="package-check"><input type="checkbox" :checked="cacheSelectedPackageNames.has(pkg.packageName) || packageIsCached(pkg.packageName)" :disabled="cachePackageBusy || packageIsCached(pkg.packageName)" :aria-label="`${t('deploy.select.2')} ${pkg.packageName}`" @change="toggleCachePackage(pkg.packageName)" /></td>
              <td class="host">
                <span>{{ pkg.packageName }}</span>
                <span v-if="packageIsCached(pkg.packageName)" class="badge ready cache-inline-badge">{{ t('deploy.cached.2') }}</span>
              </td>
              <td>{{ pkg.distributionName }}</td>
              <td>{{ pkg.packageBitness }}</td>
            </tr>
            <tr v-if="!filteredCachePackages.length"><td colspan="4" class="package-empty">{{ t('deploy.no.agent.packages.match.this.filter.2') }}</td></tr>
          </tbody>
        </table>
      </div>
      <p v-else-if="packageCatalogBusy" class="step-summary inline-wait"><HourglassIndicator />{{ t('deploy.loading.the.vbr.agent.package.catalog') }}</p>
      <p v-else-if="packageCatalogError" class="error-text">{{ packageCatalogError }}</p>
    </template>
  </Drawer>
</template>
