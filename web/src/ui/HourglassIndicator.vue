<script setup lang="ts">
withDefaults(defineProps<{
  size?: 'small' | 'medium' | 'large'
}>(), {
  size: 'small',
})
</script>

<template>
  <span class="hourglass-indicator" :class="`hourglass-${size}`" aria-hidden="true">
    <svg class="hourglass-icon" viewBox="0 0 24 24" fill="none">
      <path class="hourglass-frame" d="M6.5 3.5h11M6.5 20.5h11M7.5 4c0 3.7 1.2 5.6 4.5 8-3.3 2.4-4.5 4.3-4.5 8M16.5 4c0 3.7-1.2 5.6-4.5 8 3.3 2.4 4.5 4.3 4.5 8" />
      <path class="hourglass-sand hourglass-sand-top" d="M9 6.2h6l-3 3.5z" />
      <path class="hourglass-sand hourglass-sand-bottom" d="m9 18 3-3.5 3 3.5z" />
      <path class="hourglass-stream" d="M12 9.4v5.2" />
    </svg>
  </span>
</template>
