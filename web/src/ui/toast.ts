// Toast region state — 1:1 with the prototype's toast-region/toast classes.
// Toasts are transient notifications only; nothing secret is ever surfaced.
import { reactive } from 'vue'

export interface ToastItem {
  id: number
  title: string
  message: string
}

export const toasts = reactive<ToastItem[]>([])

let nextID = 1

// toast shows a notification for 3.6s (the prototype's timing).
export function toast(title: string, message: string): void {
  const item = { id: nextID++, title, message }
  toasts.push(item)
  setTimeout(() => {
    const i = toasts.findIndex((t) => t.id === item.id)
    if (i >= 0) toasts.splice(i, 1)
  }, 3600)
}
