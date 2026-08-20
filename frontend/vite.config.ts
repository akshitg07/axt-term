// defineConfig comes from vitest/config rather than vite so the `test` block is
// typed; it is a superset of vite's own.
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'

// The build output goes straight into the Go module that embeds it, so `make
// build` produces one binary containing the UI. Nothing is fetched at runtime:
// air-gapped operation is a requirement, and the CSP has no external host in it.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: '../backend/internal/web/dist',
    emptyOutDir: true,
    sourcemap: false,
    target: 'es2022',
    rollupOptions: {
      output: {
        // Monaco and xterm dominate the bundle. Splitting them keeps the initial
        // parse small so the terminal appears quickly, and lets the editor load
        // only when a file is actually opened.
        manualChunks: {
          xterm: ['@xterm/xterm', '@xterm/addon-fit', '@xterm/addon-webgl', '@xterm/addon-search'],
          monaco: ['monaco-editor', '@monaco-editor/react'],
          vendor: ['react', 'react-dom', 'zustand', '@tanstack/react-query'],
        },
      },
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    // The dev server proxies to the Go backend so the browser sees one origin,
    // which keeps cookies, CSRF, and the WebSocket origin check behaving exactly
    // as they do in production.
    proxy: {
      '/api': { target: 'http://localhost:8080', changeOrigin: false },
      '/ws': { target: 'ws://localhost:8080', ws: true, changeOrigin: false },
      '/healthz': 'http://localhost:8080',
      '/readyz': 'http://localhost:8080',
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
  },
})
