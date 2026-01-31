/// <reference types="vitest" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    host: '0.0.0.0',
    allowedHosts: true,
    proxy: {
      '/health': {
        target: process.env.VITE_API_URL || 'http://localhost:9080',
        changeOrigin: true,
      },
      '/ready': {
        target: process.env.VITE_API_URL || 'http://localhost:9080',
        changeOrigin: true,
      },
      '/metrics': {
        target: process.env.VITE_API_URL || 'http://localhost:9080',
        changeOrigin: true,
      },
      '/api': {
        target: process.env.VITE_API_URL || 'http://localhost:9080',
        changeOrigin: true,
      },
      '/v2': {
        target: process.env.VITE_API_URL || 'http://localhost:9080',
        changeOrigin: true,
      },
      '/npm': {
        target: process.env.VITE_API_URL || 'http://localhost:9080',
        changeOrigin: true,
      },
      '/maven': {
        target: process.env.VITE_API_URL || 'http://localhost:9080',
        changeOrigin: true,
      },
      '/cargo': {
        target: process.env.VITE_API_URL || 'http://localhost:9080',
        changeOrigin: true,
      },
      '/gems': {
        target: process.env.VITE_API_URL || 'http://localhost:9080',
        changeOrigin: true,
      },
      '/debian': {
        target: process.env.VITE_API_URL || 'http://localhost:9080',
        changeOrigin: true,
      },
      '/pypi': {
        target: process.env.VITE_API_URL || 'http://localhost:9080',
        changeOrigin: true,
      },
      '/nuget': {
        target: process.env.VITE_API_URL || 'http://localhost:9080',
        changeOrigin: true,
      },
      '/rpm': {
        target: process.env.VITE_API_URL || 'http://localhost:9080',
        changeOrigin: true,
      },
      '/go': {
        target: process.env.VITE_API_URL || 'http://localhost:9080',
        changeOrigin: true,
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: ['src/test/**', '**/*.d.ts'],
    },
  },
})
