// Bilingual label support — mirrors the prototype's 中文/EN language switch.
// Labels are declared inline as {zh, en} pairs next to their markup and
// resolved through L(), so the two languages never drift apart structurally.
import { ref, type Ref } from 'vue'
import { messages, stepNumerals, type Bi } from './messages'

export type { Bi } from './messages'

export const lang: Ref<'zh' | 'en'> = ref('zh')

// L resolves a bilingual pair for the active language.
export function L(s: Bi): string {
  return s[lang.value]
}

// t resolves a message resource and substitutes positional placeholders.
export function t(key: string, ...values: unknown[]): string {
  const message = messages[key]
  if (!message) return key
  return L(message).replace(/\{(\d+)\}/g, (_, index: string) => String(values[Number(index)] ?? ''))
}

// setLang switches the whole UI (progress numerals follow the same convention
// as the prototype: 一/二/三 in zh, I/II/III in en).
export function setLang(next: 'zh' | 'en'): void {
  lang.value = next
  document.documentElement.lang = next === 'en' ? 'en' : 'zh-CN'
}

// Step numerals for the progress dots and step badges.
export const stepNum = stepNumerals
