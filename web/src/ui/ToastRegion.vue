<script setup lang="ts">
// Toast region — fixed to the viewport's bottom center so transient feedback
// stays clear of the wizard's right-aligned action buttons.
import { toasts } from './toast'
</script>

<template>
  <div class="toast-region" aria-live="polite">
    <div v-for="t in toasts" :key="t.id" class="toast">
      <strong>{{ t.title }}</strong>
      <span>{{ t.message }}</span>
    </div>
  </div>
</template>
