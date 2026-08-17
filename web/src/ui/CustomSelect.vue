<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'

interface SelectOption {
  value: string
  label: string
  disabled?: boolean
}

const props = withDefaults(defineProps<{
  modelValue: string
  options: SelectOption[]
  ariaLabel: string
  placeholder?: string
  disabled?: boolean
  compact?: boolean
}>(), {
  placeholder: '',
  disabled: false,
  compact: false,
})

const emit = defineEmits<{
  (e: 'update:modelValue', value: string): void
  (e: 'change', value: string): void
}>()

const root = ref<HTMLElement | null>(null)
const trigger = ref<HTMLButtonElement | null>(null)
const open = ref(false)
const listboxId = `agentbridge-select-${Math.random().toString(36).slice(2)}`

const selected = computed(() => props.options.find((option) => option.value === props.modelValue))
const displayLabel = computed(() => selected.value?.label || props.placeholder)

function availableOptionButtons(): HTMLButtonElement[] {
  return root.value ? [...root.value.querySelectorAll<HTMLButtonElement>('.select-option:not(:disabled)')] : []
}

function focusOption(index: number): void {
  const options = availableOptionButtons()
  if (!options.length) return
  options[(index + options.length) % options.length]?.focus()
}

function openMenu(): void {
  if (props.disabled) return
  open.value = true
  void nextTick(() => {
    const options = availableOptionButtons()
    const selectedIndex = options.findIndex((option) => option.dataset.value === props.modelValue)
    focusOption(selectedIndex >= 0 ? selectedIndex : 0)
  })
}

function toggleMenu(): void {
  if (open.value) {
    open.value = false
    return
  }
  openMenu()
}

function selectOption(option: SelectOption): void {
  if (option.disabled) return
  emit('update:modelValue', option.value)
  emit('change', option.value)
  open.value = false
  void nextTick(() => trigger.value?.focus())
}

function onOptionKeydown(event: KeyboardEvent): void {
  const options = availableOptionButtons()
  const currentIndex = options.indexOf(event.currentTarget as HTMLButtonElement)
  if (event.key === 'ArrowDown') {
    event.preventDefault()
    focusOption(currentIndex + 1)
  } else if (event.key === 'ArrowUp') {
    event.preventDefault()
    focusOption(currentIndex - 1)
  } else if (event.key === 'Home') {
    event.preventDefault()
    focusOption(0)
  } else if (event.key === 'End') {
    event.preventDefault()
    focusOption(options.length - 1)
  } else if (event.key === 'Escape') {
    event.preventDefault()
    event.stopPropagation()
    open.value = false
    trigger.value?.focus()
  }
}

function onDocumentPointerDown(event: PointerEvent): void {
  if (root.value && !root.value.contains(event.target as Node)) open.value = false
}

watch(() => props.disabled, (disabled) => {
  if (disabled) open.value = false
})

onMounted(() => document.addEventListener('pointerdown', onDocumentPointerDown))
onBeforeUnmount(() => document.removeEventListener('pointerdown', onDocumentPointerDown))
</script>

<template>
  <div ref="root" class="custom-select" :class="{ open, compact, disabled }">
    <button
      ref="trigger"
      type="button"
      class="select-trigger fieldbox"
      role="combobox"
      aria-haspopup="listbox"
      :aria-label="ariaLabel"
      :aria-expanded="open"
      :aria-controls="listboxId"
      :disabled="disabled"
      @click="toggleMenu"
      @keydown.down.prevent="openMenu"
      @keydown.up.prevent="openMenu"
      @keydown.esc.stop.prevent="open = false"
    >
      <span class="select-label" :class="{ placeholder: !selected }">{{ displayLabel }}</span>
      <svg class="select-chevron" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
        <path d="m4 6 4 4 4-4" stroke-linecap="round" stroke-linejoin="round" />
      </svg>
    </button>
    <div v-if="open" :id="listboxId" class="select-menu" role="listbox" :aria-label="ariaLabel">
      <button
        v-for="option in options"
        :key="option.value"
        type="button"
        class="select-option"
        :class="{ selected: option.value === modelValue }"
        role="option"
        :aria-selected="option.value === modelValue"
        :data-value="option.value"
        :disabled="option.disabled"
        @click="selectOption(option)"
        @keydown="onOptionKeydown"
      >
        <span>{{ option.label }}</span>
        <svg v-if="option.value === modelValue" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true">
          <path d="m3.5 8.5 2.8 2.8 6.2-6.2" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
      </button>
    </div>
  </div>
</template>
