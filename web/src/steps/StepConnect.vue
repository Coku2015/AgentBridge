<script setup lang="ts">
// Step 一 — 连接 VBR 并获取组件 (1:1 with the prototype's step 1).
//
// Left panel: one click does everything. The VBR REST API port is fixed at
// 9419 (never asked of the operator); the TLS fingerprint is captured WITHOUT
// trust and auto-pinned on first connect — no confirmation prompt and no
// fingerprint display. The pin is enforced and any later fingerprint change
// blocks the connection. The password lives only in component state for
// the duration of the request.
//
// Right panel: deployment components. The Deployment Kit is the Windows/Linux
// install payload (generated from VBR in the same click, or imported from an
// admin-supplied ZIP). Linux Agent packages are exported through VBR's
// temporary PreInstalledAgents Protection Group. VBR may return several RPM/DEB
// payloads for one catalog selection, so each selection is cached as one
// complete install set.
import { computed, ref } from 'vue'
import Drawer from '../ui/Drawer.vue'
import HourglassIndicator from '../ui/HourglassIndicator.vue'
import { t } from '../i18n'
import { formatAgentPackageDownloadError } from '../errorPresentation'
import { toast } from '../ui/toast'
import {
  captureFingerprint,
  connectVBR,
  downloadPackages,
  generateKit,
  kitInfo,
  listPackages,
  type AgentPackage,
  type AgentArtifact,
  type Capabilities,
  type KitInfo,
  type KitResult,
  type ServerInfo,
} from '../api'

const emit = defineEmits<{
  (e: 'connected', info: ServerInfo, caps: Capabilities, server: string): void
  (e: 'sourced', kitPath: string): void
  (e: 'kit-meta', campaignId: string, sha256: string): void
  (e: 'agent-sourced', artifact: AgentArtifact): void
  (e: 'agents-sourced', artifacts: AgentArtifact[]): void
  (e: 'next'): void
}>()

const props = defineProps<{ connected: boolean; info: ServerInfo | null; caps: Capabilities | null; kitPath: string }>()

// --- VBR connection -----------------------------------------------------
// The VBR REST API always listens on 9419 — it is not operator input.
const VBR_PORT = 9419

const server = ref('')
const username = ref('veeamadmin')
const password = ref('')

// 'idle' → 'capturing' → 'connecting' → 'fetching' (one click does the whole
// chain, no intermediate clicks).
const phase = ref<'idle' | 'capturing' | 'connecting' | 'fetching'>('idle')
const fingerprint = ref('')
const errorMsg = ref('')

// The connect button is enabled once the form can produce a connection, or
// immediately when already connected (it then only tops up missing
// components). Advancing is the separate 「下一步」 button.
const canPrimary = computed(
  () =>
    phase.value === 'idle' &&
    (props.connected || (server.value.trim() !== '' && username.value.trim() !== '' && password.value !== '')),
)

const actionLabel = computed(() => {
  switch (phase.value) {
    case 'capturing':
      return t('connect.retrieving.tls.certificate')
    case 'connecting':
      return t('connect.connecting')
    case 'fetching':
      return t('connect.preparing.components')
    default:
      return t('connect.connect.and.prepare.components')
  }
})

// Primary action: connect (if needed) + fetch components. Advancing to step 二
// is the separate 「下一步」 button. Already-connected invocations only top up
// missing components.
async function onPrimaryAction(): Promise<void> {
  if (!canPrimary.value) return
  if (props.connected) {
    if (!props.kitPath) {
      phase.value = 'fetching'
      const jobs: Promise<void>[] = [onListPackages()]
      if (props.caps?.deploymentKit) jobs.push(generateKitNow(props.caps))
      await Promise.allSettled(jobs)
      phase.value = 'idle'
    }
    return
  }
  errorMsg.value = ''
  phase.value = 'capturing'
  try {
    // TOFU without interruption: capture without trusting, pin on first
    // connect, display nothing. A later fingerprint change still blocks
    // (pin enforced server-side).
    const cap = await captureFingerprint(server.value.trim(), VBR_PORT)
    fingerprint.value = cap.fingerprint
    phase.value = 'connecting'
    const res = await connectVBR({
      server: server.value.trim(),
      port: VBR_PORT,
      username: username.value.trim(),
      password: password.value,
      fingerprint: cap.fingerprint,
    })
    password.value = '' // memory-only: cleared the moment the request ends
    emit('connected', res.serverInfo, res.capabilities, server.value.trim())
    // Same click fetches the components: Kit (install payload, capability-
    // gated, skipped when one is already sourced — generating would
    // invalidate the active campaign, red line 9) + Agent catalog.
    phase.value = 'fetching'
    const jobs: Promise<void>[] = [onListPackages()]
    if (!props.kitPath && res.capabilities.deploymentKit) jobs.push(generateKitNow(res.capabilities))
    await Promise.allSettled(jobs)
    toast(t('connect.connected.to.vbr'), t('connect.credentials.were.used.for.this.session.only'))
  } catch (e) {
    password.value = ''
    errorMsg.value = (e as Error).message
  } finally {
    phase.value = 'idle'
  }
}

// --- components (Deployment Kit + Agent catalog) ------------------------
const kit = ref<KitResult | null>(null)
const kitBusy = ref(false)
const packages = ref<AgentPackage[]>([])
const listBusy = ref(false)
const agentArtifact = ref<AgentArtifact | null>(null)
const downloadedArtifacts = ref<AgentArtifact[]>([])
const packageBusy = ref(false)
const packageFilter = ref('')
const selectedPackageNames = ref<Set<string>>(new Set())
const kitDetail = ref<KitInfo | null>(null)
const kitInfoBusy = ref(false)

const filteredPackages = computed(() => {
  const query = packageFilter.value.trim().toLowerCase()
  if (!query) return packages.value
  return packages.value.filter((pkg) =>
    [pkg.packageName, pkg.distributionName, pkg.packageBitness].some((value) => value.toLowerCase().includes(query)),
  )
})
const selectedCount = computed(() => selectedPackageNames.value.size)
const allFilteredSelected = computed(
  () => filteredPackages.value.length > 0 && filteredPackages.value.every((pkg) => selectedPackageNames.value.has(pkg.packageName)),
)

const kitBadge = computed(() =>
  props.kitPath ? t('connect.ready') : t('connect.pending'),
)

async function generateKitNow(caps: Capabilities | null): Promise<void> {
  if (!caps?.deploymentKit) {
    toast(
      t('connect.cannot.create.deployment.kit'),
      t('connect.this.vbr.version.does.not.support.this'),
    )
    return
  }
  kitBusy.value = true
  try {
    kit.value = await generateKit()
    emit('sourced', kit.value.path)
    if (kit.value.campaignId) emit('kit-meta', kit.value.campaignId, kit.value.sha256 || '')
    toast(
      t('connect.deployment.kit.ready'),
      kit.value.warning || t('connect.the.original.veeam.zip.is.cached.in'),
    )
  } catch (e) {
    toast(t('connect.kit.generation.failed'), (e as Error).message)
  } finally {
    kitBusy.value = false
  }
}

// fmtSize renders a byte count in the file table (B / KB / MB / GB).
function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB']
  let v = n
  let i = -1
  do {
    v /= 1024
    i++
  } while (v >= 1024 && i < units.length - 1)
  return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[i]}`
}

// fmtDate renders an ISO timestamp as YYYY-MM-DD HH:mm (local).
function fmtDate(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const p = (x: number): string => String(x).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

async function onListPackages(): Promise<void> {
  listBusy.value = true
  try {
    const res = await listPackages()
    packages.value = res.packages
    const available = new Set(packages.value.map((pkg) => pkg.packageName))
    selectedPackageNames.value = new Set([...selectedPackageNames.value].filter((name) => available.has(name)))
  } catch (e) {
    toast(t('connect.catalog.unavailable'), (e as Error).message)
  } finally {
    listBusy.value = false
  }
}

function togglePackage(packageName: string): void {
  const next = new Set(selectedPackageNames.value)
  if (next.has(packageName)) next.delete(packageName)
  else next.add(packageName)
  selectedPackageNames.value = next
}

function toggleFilteredPackages(): void {
  const next = new Set(selectedPackageNames.value)
  if (allFilteredSelected.value) {
    filteredPackages.value.forEach((pkg) => next.delete(pkg.packageName))
  } else {
    filteredPackages.value.forEach((pkg) => next.add(pkg.packageName))
  }
  selectedPackageNames.value = next
}

async function onDownloadSelected(): Promise<void> {
  if (packageBusy.value) return
  const names = [...selectedPackageNames.value]
  if (!names.length) return
  packageBusy.value = true
  try {
    const res = await downloadPackages(names)
    const byName = new Map(downloadedArtifacts.value.map((artifact) => [artifact.packageName, artifact]))
    res.artifacts.forEach((artifact) => byName.set(artifact.packageName, artifact))
    downloadedArtifacts.value = [...byName.values()]
    // Step 二 consumes one Agent artifact at a time. Keep the first selected
    // artifact as the default, while all selected package sets remain cached
    // and can be explicitly chosen below.
    agentArtifact.value = res.artifacts[0] || agentArtifact.value
    if (agentArtifact.value) emit('agent-sourced', agentArtifact.value)
    emit('agents-sourced', downloadedArtifacts.value)
    toast(
      t('connect.agent.packages.cached'),
      t('connect.package.s.exported.from.vbr.and.cached', res.artifacts.length),
    )
  } catch (e) {
    toast(t('connect.agent.package.download.failed'), formatAgentPackageDownloadError(e))
  } finally {
    packageBusy.value = false
  }
}

// --- package preview drawer (the prototype's packageMode) ---------------
const drawerOpen = ref(false)
const drawerPackage = ref<'kit' | 'agent'>('kit')

function openPackage(which: 'kit' | 'agent'): void {
  drawerPackage.value = which
  drawerOpen.value = true
  if (which === 'kit') {
    // Info-only drawer: refresh the read-only campaign view each open.
    kitInfoBusy.value = true
    kitInfo()
      .then((info) => {
        kitDetail.value = info
      })
      .catch((e: Error) => toast(t('connect.kit.info.unavailable'), e.message))
      .finally(() => {
        kitInfoBusy.value = false
      })
  }
  if (which === 'agent' && !packages.value.length) onListPackages()
}

function fmtServerTime(iso?: string): string {
  if (!iso) return '—'
  // Keep the offset returned by VBR instead of converting it to the browser's
  // local timezone; this is the actual VBR server clock the operator asked for.
  return iso.replace('T', ' ').replace(/\.\d+(?=[+-]\d\d:\d\d$|Z$)/, '')
}
</script>

<template>
  <div class="grid-2">
    <div class="panel">
      <h3>{{ t('connect.connect.to.vbr.2') }}</h3>
      <div class="field">
        <label>{{ t('connect.vbr.server') }}</label>
        <input v-model.trim="server" class="fieldbox mono" type="text" :disabled="connected || phase !== 'idle'" :placeholder="t('connect.e.g.vbr.company.internal')" />
      </div>
      <div v-if="!connected" class="grid-2">
        <div class="field">
          <label>{{ t('connect.username') }} <span>{{ t('connect.required') }}</span></label>
          <input v-model.trim="username" class="fieldbox" type="text" :disabled="phase !== 'idle'" :placeholder="t('connect.e.g.administrator')" />
        </div>
        <div class="field">
          <label>{{ t('connect.password') }} <span>{{ t('connect.this.connection.only') }}</span></label>
          <input v-model="password" class="fieldbox" type="password" :disabled="phase !== 'idle'" :placeholder="t('connect.vbr.password')" @keyup.enter="onPrimaryAction" />
        </div>
      </div>
      <div v-if="connected && info" class="connection">
        <div class="connection-icon">
          <svg width="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m5 12 4 4L19 6" /></svg>
        </div>
        <div>
          <strong>{{ t('connect.connected') }}</strong>
          <span class="connection-meta">Veeam Backup &amp; Replication</span>
          <span class="connection-meta">{{ t('connect.version') }} {{ info.productVersion || '?' }} · {{ t('connect.host') }} {{ info.host || '?' }}</span>
          <span class="connection-meta">{{ t('connect.server.time') }} {{ fmtServerTime(info.serverTime) }}</span>
        </div>
      </div>
      <p v-if="errorMsg" class="error-text">{{ errorMsg }}</p>
    </div>

    <div class="panel">
      <h3>{{ t('connect.deployment.components') }}</h3>
      <p>{{ t('connect.select.a.component.to.view.its.files') }}</p>
      <div class="package-list">
        <button class="package" @click="openPackage('kit')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3 4 7l8 4 8-4-8-4Zm-8 9 8 4 8-4M4 17l8 4 8-4" /></svg>
          <div>
            <strong>Veeam Deployment Kit</strong>
            <span v-if="!props.kitPath">{{ t('connect.windows.and.linux.pending') }}</span>
            <span v-else>{{ t('connect.for.windows.and.linux') }}</span>
          </div>
          <span class="badge" :class="{ ready: props.kitPath, running: kitBusy }">
            <HourglassIndicator v-if="kitBusy" />
            {{ kitBusy ? t('connect.generating') : kitBadge }}
          </span>
        </button>
        <button class="package" @click="openPackage('agent')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 4h16v16H4zM8 8h8v8H8z" /></svg>
          <div>
            <strong>Veeam Agent for Linux</strong>
            <span>{{ downloadedArtifacts.length ? t('connect.package.s.cached', downloadedArtifacts.length) : t('connect.for.direct.installation.on.linux') }}</span>
          </div>
          <span class="badge" :class="{ ready: downloadedArtifacts.length > 0, running: packageBusy }">
            <HourglassIndicator v-if="packageBusy" />
            {{ packageBusy ? t('connect.caching') : downloadedArtifacts.length ? t('connect.cached') : t('connect.export') }}
          </span>
        </button>
      </div>
    </div>
  </div>

  <div class="actions">
    <span class="step-summary">{{ t('connect.connection.credentials.are.retained.for.this.session') }}</span>
    <div class="actions-right">
      <button class="btn primary" :disabled="!canPrimary" @click="onPrimaryAction">
        <HourglassIndicator v-if="phase !== 'idle'" />
        {{ actionLabel }}
        <svg v-if="phase === 'idle'" width="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m9 18 6-6-6-6" /></svg>
      </button>
      <button class="btn" :disabled="!connected" @click="emit('next')">
        {{ t('connect.next') }}
        <svg width="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m9 18 6-6-6-6" /></svg>
      </button>
    </div>
  </div>

  <Drawer
    :open="drawerOpen"
    :eyebrow="t('connect.veeam.component')"
    :title="drawerPackage === 'kit' ? 'Veeam Deployment Kit' : 'Veeam Agent for Linux'"
    @close="drawerOpen = false"
  >
    <template #default>
      <div v-if="drawerPackage === 'kit'">
        <div v-if="kitInfoBusy" class="wait-state" role="status" aria-live="polite" style="margin-top:0">
          <HourglassIndicator size="medium" />
          <div>
            <strong>{{ t('connect.loading.deployment.kit.details') }}</strong>
            <span>{{ t('connect.retrieving.the.active.kit.platforms.validity.and') }}</span>
          </div>
        </div>
        <div class="review kit-review" style="margin:0">
          <div class="review-item">
            <span>{{ t('connect.valid.until') }}</span>
            <strong>{{ kitDetail?.expiresAt ? fmtDate(kitDetail.expiresAt) : '—' }}</strong>
          </div>
          <div class="review-item">
            <span>{{ t('connect.platforms') }}</span>
            <strong>{{ kitDetail?.platforms?.join(' · ') || 'Windows · Linux' }}</strong>
          </div>
        </div>
        <div class="table-wrap" style="margin-top:18px">
          <table class="table">
            <thead><tr><th>{{ t('connect.file') }}</th><th>{{ t('connect.size') }}</th></tr></thead>
            <tbody>
              <tr v-for="f in kitDetail?.files || []" :key="f.name">
                <td class="host">{{ f.name }}</td>
                <td>{{ fmtSize(f.size) }}</td>
              </tr>
            </tbody>
            <tfoot v-if="kitDetail">
              <tr>
                <td>{{ t('connect.total.size') }}</td>
                <td>{{ fmtSize(kitDetail.totalSize) }}</td>
              </tr>
            </tfoot>
          </table>
        </div>
        <p v-if="kit?.warning" class="error-text" style="margin-top:14px">{{ kit.warning }}</p>
      </div>
      <div v-else>
        <div class="package-catalog-head" style="margin-top:18px">
          <label>{{ t('connect.agent.package.catalog') }} <span>{{ t('connect.exportable') }}</span></label>
          <button class="btn small" :disabled="listBusy" @click="onListPackages">
            <HourglassIndicator v-if="listBusy" />
            {{ listBusy ? t('connect.loading') : t('connect.refresh.catalog') }}
          </button>
        </div>
        <div v-if="packages.length" class="package-filter">
          <input v-model="packageFilter" class="fieldbox" type="search" :placeholder="t('connect.filter.package.distribution.or.bitness')" />
          <button class="btn small package-filter-select" :disabled="!filteredPackages.length || packageBusy" @click="toggleFilteredPackages">
            {{ allFilteredSelected ? t('connect.clear.visible') : t('connect.select.visible') }}
          </button>
          <button class="btn primary small package-filter-download" :disabled="!selectedCount || packageBusy" @click="onDownloadSelected">
            <HourglassIndicator v-if="packageBusy" />
            {{ packageBusy ? t('connect.exporting') : `${t('connect.export.and.cache')} (${selectedCount})` }}
          </button>
        </div>
        <div v-if="packages.length" class="table-wrap">
          <table class="table">
            <thead><tr><th class="package-check"><input type="checkbox" :checked="allFilteredSelected" :disabled="!filteredPackages.length || packageBusy" :aria-label="t('connect.select.visible.packages')" @change="toggleFilteredPackages" /></th><th>{{ t('connect.package.name') }}</th><th>{{ t('connect.distribution') }}</th><th>{{ t('connect.architecture') }}</th></tr></thead>
            <tbody>
              <tr v-for="p in filteredPackages" :key="`${p.packageName}-${p.distributionName}-${p.packageBitness}`">
                <td class="package-check"><input type="checkbox" :checked="selectedPackageNames.has(p.packageName)" :disabled="packageBusy" :aria-label="`${t('connect.select')} ${p.packageName}`" @change="togglePackage(p.packageName)" /></td>
                <td class="host">{{ p.packageName }}</td>
                <td>{{ p.distributionName }}</td>
                <td>{{ p.packageBitness }}</td>
              </tr>
              <tr v-if="!filteredPackages.length"><td colspan="4" class="package-empty">{{ t('connect.no.agent.packages.match.this.filter') }}</td></tr>
            </tbody>
          </table>
        </div>
        <div v-if="downloadedArtifacts.length" class="downloaded-artifacts">
          <p class="step-summary">{{ t('connect.cached.packages') }} · {{ downloadedArtifacts.length }}</p>
          <div v-for="artifact in downloadedArtifacts" :key="artifact.path" class="downloaded-artifact">
            <span class="host">{{ artifact.packageName }}</span>
            <span>{{ artifact.payloads?.length ? `${artifact.payloads.length} ${t('connect.rpm.deb.payloads')}` : artifact.fileName }} · {{ fmtSize(artifact.size) }}</span>
            <span class="artifact-hash">{{ `SHA-256 ${artifact.sha256.slice(0, 16)}…` }}</span>
          </div>
        </div>
      </div>
    </template>
  </Drawer>
</template>
