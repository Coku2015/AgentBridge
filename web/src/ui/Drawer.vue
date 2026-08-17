<script setup lang="ts">
// Drawers normally enter from the right. A nested package-cache drawer can
// enter from the left while preserving the host configuration on the right.
// ESC closes only the topmost nested drawer; clicking its center backdrop
// returns to the host drawer without losing that form.
import { onBeforeUnmount, onMounted } from 'vue'

const props = withDefaults(defineProps<{
  open: boolean
  eyebrow?: string
  title: string
  side?: 'left' | 'right'
  nested?: boolean
}>(), {
  side: 'right',
  nested: false,
})
const emit = defineEmits<{ (e: 'close'): void }>()

function onKey(e: KeyboardEvent): void {
  if (e.key !== 'Escape' || !props.open) return
  const nestedOpen = document.querySelector('.drawer-layer.nested.open')
  if (props.nested || !nestedOpen) emit('close')
}

onMounted(() => document.addEventListener('keydown', onKey))
onBeforeUnmount(() => document.removeEventListener('keydown', onKey))
</script>

<template>
  <div class="drawer-layer" :class="[side, { open, nested }]" @click.self="emit('close')">
    <aside class="drawer" role="dialog" :aria-modal="nested ? 'false' : 'true'">
      <div class="drawer-head">
        <div>
          <div v-if="eyebrow" class="eyebrow">{{ eyebrow }}</div>
          <h2>{{ title }}</h2>
        </div>
      </div>
      <div class="drawer-body"><slot /></div>
      <div v-if="$slots.foot" class="drawer-foot"><slot name="foot" /></div>
    </aside>
  </div>
</template>
