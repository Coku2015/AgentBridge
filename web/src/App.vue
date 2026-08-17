<script setup lang="ts">
// AgentBridge — Veeam Agent 安装器.
// Shell follows the approved AgentBridge workspace, page head, three-step
// progress navigation, language switch, and accordion layout.
//
// Capability-driven gating (red line 8): steps 二/三 stay closed until the
// VBR connection (and at least one installed host for 三) exists — the UI
// path is disabled up front instead of failing mid-flow.
import { computed, onMounted, ref } from 'vue'
import { fetchProductVersion, fetchSession, setSessionToken, type AgentArtifact, type Capabilities, type ServerInfo } from './api'
import { L, t, lang, setLang, stepNum } from './i18n'
import { toast } from './ui/toast'
import ToastRegion from './ui/ToastRegion.vue'
import HourglassIndicator from './ui/HourglassIndicator.vue'
import StepConnect from './steps/StepConnect.vue'
import StepDeploy from './steps/StepDeploy.vue'
import StepProtect from './steps/StepProtect.vue'

const booting = ref(true)
const bootError = ref('')
const productVersion = ref('')

const activeStep = ref(1)
const connected = ref(false)
const info = ref<ServerInfo | null>(null)
const caps = ref<Capabilities | null>(null)
const vbrServer = ref('')

// The on-disk Kit path sourced in step 一 flows down as the install payload —
// the operator never re-types a server-side path anywhere.
const kitPath = ref('')
const kitCampaignId = ref('')
const kitSHA256 = ref('')
const agentArtifact = ref<AgentArtifact | null>(null)
const agentArtifacts = ref<AgentArtifact[]>([])

function onAgentsCached(artifacts: AgentArtifact[]): void {
  const byName = new Map(agentArtifacts.value.map((artifact) => [artifact.packageName, artifact]))
  artifacts.forEach((artifact) => byName.set(artifact.packageName, artifact))
  agentArtifacts.value = [...byName.values()]
  if (!agentArtifact.value && artifacts[0]) agentArtifact.value = artifacts[0]
}

// Hosts that are ready to continue from step 二. A host is ready after a
// verified SSH install or after the operator confirms the manual-install path.
interface ProcessedHost {
  host: string
  platform: 'windows' | 'linux'
  component: string
  ready: boolean
  method: 'remote' | 'manual'
  version: string
}
const processedHosts = ref<ProcessedHost[]>([])

const cachedAgentCount = computed(() => agentArtifacts.value.length || (agentArtifact.value?.path ? 1 : 0))
const step1Done = computed(() => connected.value && kitPath.value !== '')
const step2Done = computed(() => processedHosts.value.some((h) => h.ready))

const step1Summary = computed(() => {
  if (!step1Done.value || activeStep.value === 1) {
    return t('app.connect.to.the.veeam.backup.server.and')
  }
  const host = info.value?.host || vbrServer.value || 'VBR'
  return t('app.connected.to.deployment.kit.ready.agent.package', host, cachedAgentCount.value)
})

const step2Summary = computed(() => {
  if (!step2Done.value || activeStep.value === 2) {
    return t('app.deploy.automatically.or.generate.a.manual.installation')
  }
  const count = processedHosts.value.filter((h) => h.ready).length
  const windows = processedHosts.value.filter((h) => h.ready && h.platform === 'windows').length
  const linux = processedHosts.value.filter((h) => h.ready && h.platform === 'linux').length
  return t('app.host.s.ready.windows.linux', count, windows, linux)
})

function onHostState(host: string, platform: 'windows' | 'linux', component: string, method: 'remote' | 'manual', ready: boolean, version: string): void {
  const found = processedHosts.value.find((h) => h.host === host)
  if (!ready) {
    if (found) processedHosts.value.splice(processedHosts.value.indexOf(found), 1)
    return
  }
  if (found) {
    found.ready = true
    found.platform = platform
    found.component = component
    found.method = method
    found.version = version
  } else {
    processedHosts.value.push({ host, platform, component, ready: true, method, version })
  }
}

function goStep(n: number | string): void {
  const target = Number(n)
  if (target >= 2 && !connected.value) {
    toast(t('app.connect.to.vbr.first'), t('app.finish.the.connection.in.step.1.to'))
    return
  }
  if (target >= 3 && !step2Done.value) {
    toast(t('app.no.hosts.are.ready'), t('app.complete.deployment.for.at.least.one.host'))
    return
  }
  activeStep.value = target
}

function stepClass(n: number): string {
  if (n === activeStep.value) return n === 3 && successDone.value ? 'step active complete' : 'step active'
  if ((n === 1 && step1Done.value) || (n === 2 && step2Done.value)) return 'step complete'
  return 'step'
}

function progressClass(n: number): string {
  if (n < activeStep.value || (n === activeStep.value && n === 3 && successDone.value)) return 'progress-item done'
  if (n === activeStep.value) return 'progress-item active'
  if ((n === 1 && step1Done.value) || (n === 2 && step2Done.value)) return 'progress-item done'
  return 'progress-item'
}

const successDone = ref(false)

onMounted(async () => {
  try {
    const s = await fetchSession()
    if (s.token) setSessionToken(s.token)
    try {
      const build = await fetchProductVersion()
      productVersion.value = build.version
    } catch {
      // Version metadata must never block access to the deployment workflow.
    }
  } catch (e) {
    bootError.value = (e as Error).message
  } finally {
    booting.value = false
  }
})
</script>

<template>
  <div class="app">
    <main class="workspace">
      <div class="content">
        <section class="page-head">
          <div class="page-head-copy">
            <div class="eyebrow">AgentBridge · {{ t('app.protection.for.windows.and.linux.hosts') }}</div>
            <h1>{{ t('app.veeam.agent.deployment') }}</h1>
            <p>{{ t('app.connect.to.the.veeam.backup.server.deploy') }}</p>
          </div>
          <div class="head-tools">
            <div class="progress-nav" :aria-label="t('app.progress')">
              <div :class="progressClass(1)">
                <span class="progress-dot">{{ L(stepNum[0]) }}</span>
                <span>{{ t('app.connect.to.vbr') }}</span>
              </div>
              <div :class="progressClass(2)">
                <span class="progress-dot">{{ L(stepNum[1]) }}</span>
                <span>{{ t('app.deploy.hosts') }}</span>
              </div>
              <div :class="progressClass(3)">
                <span class="progress-dot">{{ L(stepNum[2]) }}</span>
                <span>{{ t('app.create.protection.group') }}</span>
              </div>
            </div>
            <div class="language-switch" :aria-label="t('app.language')">
              <button class="lang-btn" :class="{ active: lang === 'zh' }" @click="setLang('zh')">{{ t('app.language.chinese') }}</button>
              <button class="lang-btn" :class="{ active: lang === 'en' }" @click="setLang('en')">{{ t('app.language.english') }}</button>
            </div>
          </div>
        </section>

        <p v-if="bootError" class="error-text">{{ bootError }}</p>
        <div v-if="booting" class="panel wait-state" role="status" aria-live="polite">
          <HourglassIndicator size="medium" />
          <div>
            <strong>{{ t('app.starting.agentbridge') }}</strong>
            <span>{{ t('app.preparing.this.configuration.session') }}</span>
          </div>
        </div>

        <template v-else>
          <section :class="stepClass(1)">
            <button class="step-head" @click="goStep(1)">
              <span class="step-num">{{ L(stepNum[0]) }}</span>
              <span>
                <span class="step-title">{{ t('app.connect.to.vbr.and.prepare.components') }}</span>
                <span class="step-summary">{{ step1Summary }}</span>
              </span>
              <svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m6 9 6 6 6-6" /></svg>
            </button>
            <div class="step-body">
              <StepConnect
                :connected="connected"
                :info="info"
                :caps="caps"
                :kit-path="kitPath"
                @agent-sourced="(a) => (agentArtifact = a)"
                @agents-sourced="(as) => { agentArtifacts = as; agentArtifact = as[0] || null }"
                @connected="(i, c, s) => { info = i; caps = c; connected = true; vbrServer = s }"
                @sourced="(p) => (kitPath = p)"
                @kit-meta="(id, sha) => { kitCampaignId = id; kitSHA256 = sha }"
                @next="goStep(2)"
              />
            </div>
          </section>

          <section :class="stepClass(2)">
            <button class="step-head" @click="goStep(2)">
              <span class="step-num">{{ L(stepNum[1]) }}</span>
              <span>
                <span class="step-title">{{ t('app.deploy.host.components') }}</span>
                <span class="step-summary">{{ step2Summary }}</span>
              </span>
              <svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m6 9 6 6 6-6" /></svg>
            </button>
            <div class="step-body">
              <StepDeploy :kit-path="kitPath" :kit-campaign-id="kitCampaignId" :kit-sha256="kitSHA256" :agent-package="agentArtifact" :agent-packages="agentArtifacts" @next="goStep(3)" @back="goStep(1)" @host-state="(h, p, c, m, r, v) => onHostState(h, p, c, m, r, v)" @agents-cached="onAgentsCached" />
            </div>
          </section>

          <section :class="stepClass(3)">
            <button class="step-head" @click="goStep(3)">
              <span class="step-num">{{ L(stepNum[2]) }}</span>
              <span>
                <span class="step-title">{{ t('app.create.a.protection.group') }}</span>
                <span class="step-summary">{{ t('app.select.ready.hosts.and.add.them.to') }}</span>
              </span>
              <svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m6 9 6 6 6-6" /></svg>
            </button>
            <div class="step-body">
              <StepProtect :hosts="processedHosts" @back="goStep(2)" @done="successDone = true" />
            </div>
          </section>
        </template>
      </div>
      <footer class="arcami-footer" :aria-label="t('app.produced.by.arcami.cloud')">
        <div class="arcami-footer-inner">
          <div v-if="productVersion" class="arcami-footer-version">{{ t('app.version', productVersion) }}</div>
          <div class="arcami-footer-copy">
            <strong>{{ t('app.produced.by.arcami.cloud.2') }}</strong>
          </div>
          <a
            class="arcami-footer-link"
            href="https://www.arcamicloud.com/"
            target="_blank"
            rel="noopener noreferrer"
            :aria-label="t('app.visit.the.arcami.cloud.website')"
          >
            {{ t('app.learn.more.at') }} https://www.arcamicloud.com
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M7 17 17 7M8 7h9v9" /></svg>
          </a>
        </div>
      </footer>
    </main>
  </div>
  <ToastRegion />
</template>
