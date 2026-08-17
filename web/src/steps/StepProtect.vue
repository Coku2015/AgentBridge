<script setup lang="ts">
// Step 三 — 创建 Veeam Protection Group (1:1 with the prototype's step 3).
//
// Selects the hosts that reached a configured state in step 2 (verified SSH
// install or operator-confirmed manual install) and submits one idempotent
// certificate-based PG create + discovery. Protection Group creation and
// discovery remain independent layers (Principle IV), but both are rendered
// in place: the form stays visible and the discovery table updates below it.
import { computed, ref } from 'vue'
import { t } from '../i18n'
import { toast } from '../ui/toast'
import HourglassIndicator from '../ui/HourglassIndicator.vue'
import { ApiRequestError, enrollPG, discovered, type DiscoveredEntity, type Enrollment, type RescanFailure } from '../api'

const props = defineProps<{ hosts: { host: string; platform: 'windows' | 'linux'; component: string; ready: boolean; method: 'remote' | 'manual'; version: string }[] }>()
const emit = defineEmits<{ (e: 'back'): void; (e: 'done'): void }>()

const pgName = ref('')
const description = ref('')
const selected = ref<string[]>([])
const busy = ref(false)
const busyOperation = ref<'idle' | 'creating' | 'rescanning'>('idle')
const created = ref<Enrollment | null>(null)
const createdName = ref('')

const selectable = computed(() => props.hosts.filter((h) => h.ready))

const canCreate = computed(() => pgName.value.trim() !== '' && selected.value.length > 0 && !busy.value && !created.value)

function toggle(host: string): void {
  if (created.value) return
  const i = selected.value.indexOf(host)
  if (i >= 0) selected.value.splice(i, 1)
  else selected.value.push(host)
}

const allChecked = computed(() => selectable.value.length > 0 && selected.value.length === selectable.value.length)

function toggleAll(): void {
  if (created.value) return
  selected.value = allChecked.value ? [] : selectable.value.map((h) => h.host)
}

function componentLabel(c: string): string {
  if (c === 'kit') return t('protect.deployment.kit.only.5')
  if (c === 'agent-plus-kit') return t('protect.agent.deployment.kit.4')
  return '—'
}

function agentStatusLabel(status: string): string {
  switch (status.trim().toLowerCase()) {
    case 'installed':
      return t('protect.installed.2')
    case 'notinstalled':
      return t('protect.not.installed')
    case 'upgradeavailable':
      return t('protect.upgrade.available')
    case 'failed':
      return t('protect.failed.4')
    case 'unsupportedoperatingsystem':
    case 'unsupportedos':
      return t('protect.unsupported.operating.system')
    default:
      return status || '—'
  }
}

// VBR's own result message is shown verbatim. Anything else (including older
// AgentBridge UUID-shaped errors) becomes one concise localized fallback.
function discoveryFailureDetail(detail?: string, source?: 'vbr' | 'unavailable'): string {
  if (source === 'vbr' && detail?.trim()) return detail
  return t('protect.vbr.did.not.return.detailed.information.for')
}

const failureRows = computed<RescanFailure[]>(() => {
  if (!created.value || created.value.discoveryLayer !== 'failed') return []
  if (created.value.failures?.length) {
    return created.value.failures.map((failure) => ({
      host: failure.host || (selected.value.length === 1 ? selected.value[0] : '—'),
      message: failure.message,
    }))
  }
  return [{
    host: selected.value.length === 1 ? selected.value[0] : '—',
    message: created.value.detail || discoveryFailureDetail(),
  }]
})

async function onCreate(): Promise<void> {
  busy.value = true
  busyOperation.value = 'creating'
  try {
    const requestedName = pgName.value.trim()
    created.value = await enrollPG({
      name: requestedName,
      description: description.value.trim() || undefined,
      hosts: selected.value,
    })
    createdName.value = requestedName
    if (created.value.discoveryLayer === 'failed') {
      if (!created.value.failures?.length) {
        created.value.detail = discoveryFailureDetail(created.value.detail, created.value.detailSource)
      }
      toast(t('protect.rescan.incomplete'), t('protect.review.the.host.errors.below'))
    } else {
      toast(t('protect.protection.group.created'), createdName.value)
      emit('done')
    }
  } catch (e) {
    if (e instanceof ApiRequestError && e.code === 'protection_group_name_conflict') {
      toast(t('protect.protection.group.name.already.exists'), t('protect.choose.another.name.or.edit.the.existing'))
    } else {
      toast(t('protect.creation.failed'), (e as Error).message)
    }
  } finally {
    busy.value = false
    busyOperation.value = 'idle'
  }
}

async function onRediscover(): Promise<void> {
  if (!created.value) return
  busy.value = true
  busyOperation.value = 'rescanning'
  try {
    const d = await discovered(created.value.pgId)
    if (created.value) {
      created.value.entities = d.entities
      created.value.found = d.found
      created.value.discoveryLayer = 'succeeded'
      created.value.detail = ''
      created.value.failures = []
    }
    toast(t('protect.rescan.completed'), t('protect.host.and.agent.status.has.been.updated'))
  } catch (e) {
    const failures = e instanceof ApiRequestError ? (e.failures || []) : []
    const detail = e instanceof ApiRequestError
      ? discoveryFailureDetail(e.detail, e.detailSource)
      : discoveryFailureDetail()
    if (created.value) {
      created.value.discoveryLayer = 'failed'
      created.value.failures = failures
      created.value.detail = failures.length ? '' : detail
    }
    toast(t('protect.rescan.failed'), t('protect.review.the.host.errors.below.2'))
  } finally {
    busy.value = false
    busyOperation.value = 'idle'
  }
}

const busyTitle = computed(() => busyOperation.value === 'rescanning'
  ? t('protect.waiting.for.vbr.to.complete.the.rescan')
  : t('protect.creating.and.rescanning.the.protection.group'))

const busyDetail = computed(() => busyOperation.value === 'rescanning'
  ? t('protect.vbr.is.refreshing.host.discovery.and.agent')
  : t('protect.vbr.will.create.and.rescan.the.protection'))

const rescanResultClass = computed(() => busyOperation.value === 'rescanning'
  ? 'running'
  : created.value?.discoveryLayer === 'succeeded' ? 'ready' : 'failed')

const rescanResultLabel = computed(() => {
  if (busyOperation.value === 'rescanning') return t('protect.scanning')
  return created.value?.discoveryLayer === 'succeeded'
    ? t('protect.completed.3')
    : t('protect.incomplete')
})
</script>

<template>
  <div>
    <div class="grid-2">
      <div class="field">
        <label>{{ t('protect.protection.group.name') }} <span>{{ t('protect.required.6') }}</span></label>
        <input v-model.trim="pgName" class="fieldbox" type="text" :disabled="Boolean(created)" :placeholder="t('protect.e.g.production.mixed.hosts')" />
      </div>
      <div class="field">
        <label>{{ t('protect.description') }} <span>{{ t('protect.optional') }}</span></label>
        <input v-model.trim="description" class="fieldbox" type="text" :disabled="Boolean(created)" />
      </div>
    </div>

    <div class="table-wrap">
      <div class="table-toolbar">
        <strong>{{ t('protect.select.hosts.to.add') }}</strong>
        <div class="select-all">
          <button class="check" :class="{ checked: allChecked }" :disabled="Boolean(created)" :aria-label="t('protect.select.all')" @click="toggleAll">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="m5 12 4 4L19 6" /></svg>
          </button>
          {{ t('protect.select.all') }}
        </div>
      </div>
      <table class="table">
        <thead>
          <tr>
            <th style="width:48px">{{ t('protect.select.3') }}</th>
            <th>{{ t('protect.host.ip.2') }}</th>
            <th>{{ t('protect.operating.system.3') }}</th>
            <th>{{ t('protect.component.2') }}</th>
            <th>{{ t('protect.readiness') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!selectable.length">
            <td colspan="5" style="text-align:center">{{ t('protect.no.hosts.are.ready.return.to.step') }}</td>
          </tr>
          <tr v-for="h in selectable" :key="h.host">
            <td>
              <button class="check" :class="{ checked: selected.includes(h.host) }" :disabled="Boolean(created)" :aria-label="t('protect.select.host', h.host)" @click="toggle(h.host)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="m5 12 4 4L19 6" /></svg>
              </button>
            </td>
            <td class="host">{{ h.host }}</td>
            <td>{{ h.platform === 'windows' ? 'Windows' : 'Linux' }}</td>
            <td>{{ componentLabel(h.component) }}</td>
            <td>
              <span class="badge ready">
                {{ h.method === 'manual' ? t('protect.manual.install.2') : t('protect.verified') }}{{ h.version ? ` · ${h.version}` : '' }}
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="review protect-review">
      <div class="review-item">
        <span>{{ t('protect.selected.hosts') }}</span>
        <strong>{{ selected.length }} {{ t('protect.text.2') }}</strong>
      </div>
      <div class="review-item">
        <span>{{ t('protect.authentication') }}</span>
        <strong>{{ t('protect.certificate') }}</strong>
      </div>
    </div>

    <div class="actions">
      <button class="btn" @click="emit('back')">{{ t('protect.back.to.hosts') }}</button>
      <button class="btn primary" :disabled="!canCreate" @click="onCreate">
        <HourglassIndicator v-if="busyOperation === 'creating'" />
        {{ created ? t('protect.protection.group.created.2') : busyOperation === 'creating' ? t('protect.creating.and.rescanning') : t('protect.create.protection.group.2') }}
      </button>
    </div>

    <div v-if="busy" class="wait-state" role="status" aria-live="polite">
      <HourglassIndicator size="medium" />
      <div>
        <strong>{{ busyTitle }}</strong>
        <span>{{ busyDetail }}</span>
      </div>
    </div>

    <!-- In-place Protection Group result: no separate success screen. -->
    <div v-if="created" class="pg-result">
      <div class="pg-result-header">
        <dl class="pg-result-summary">
          <div>
            <dt>{{ t('protect.protection.group.name.2') }}</dt>
            <dd>{{ createdName }}</dd>
          </div>
          <div>
            <dt>{{ t('protect.rescan.result') }}</dt>
            <dd>
              <span class="badge" :class="rescanResultClass">
                <HourglassIndicator v-if="busyOperation === 'rescanning'" />
                {{ rescanResultLabel }}
              </span>
            </dd>
          </div>
        </dl>
        <button class="btn small" :disabled="busy" @click="onRediscover">
          <HourglassIndicator v-if="busyOperation === 'rescanning'" />
          {{ busyOperation === 'rescanning' ? t('protect.rescanning') : t('protect.rescan') }}
        </button>
      </div>
      <div v-if="created.discoveryLayer === 'failed'" class="table-wrap pg-result-table">
        <table class="table">
          <thead>
            <tr>
              <th>{{ t('protect.host.ip.3') }}</th>
              <th>{{ t('protect.error') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="failure in failureRows" :key="`${failure.host}-${failure.message}`">
              <td class="host">{{ failure.host }}</td>
              <td class="error-text" style="white-space:pre-wrap">{{ failure.message }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="(created.entities?.length || 0) > 0" class="table-wrap pg-result-table">
        <table class="table">
          <thead>
            <tr>
              <th>{{ t('protect.host.2') }}</th>
              <th>{{ t('protect.online') }}</th>
              <th>{{ t('protect.agent.status') }}</th>
              <th>{{ t('protect.version.2') }}</th>
              <th>{{ t('protect.last.seen') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="e in (created.entities as DiscoveredEntity[])" :key="e.host">
              <td class="host">{{ e.host }}</td>
              <td>{{ e.online ? t('protect.yes') : t('protect.no') }}</td>
              <td>{{ agentStatusLabel(e.agentStatus) }}</td>
              <td>{{ e.agentVersion || '—' }}</td>
              <td>{{ e.lastConnected || '—' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-else-if="created.discoveryLayer === 'succeeded'" class="step-summary" style="margin-top:10px">
        {{ t('protect.the.rescan.completed.but.the.target.host') }}
      </p>
    </div>

    <details class="pg-notes">
      <summary>
        <span class="pg-notes-title">
          <strong>{{ t('protect.notes') }}</strong>
          <span>{{ t('protect.expand.to.view.protection.group.defaults') }}</span>
        </span>
        <svg class="pg-notes-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="m6 9 6 6 6-6" /></svg>
      </summary>
      <p>
        {{ t('protect.agentbridge.creates.an.individual.computers.protection.group') }}
      </p>
    </details>
  </div>
</template>
