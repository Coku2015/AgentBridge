import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const apiProxyTarget = process.env.AGENTBRIDGE_API_PROXY_TARGET || 'http://127.0.0.1:8787'

// Build output is the go:embed source for the embedded Web UI
// (internal/httpserver/web/dist). During `vite dev`, API and SSE requests are
// proxied to the Go server started by `make run` (127.0.0.1:8787).
export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: '../internal/httpserver/web/dist',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: apiProxyTarget, changeOrigin: true },
      '/events': { target: apiProxyTarget, changeOrigin: true }, // SSE stream
    },
  },
})
