import { defineConfig } from 'vite'
import { resolve } from 'path'

export default defineConfig({
  server: {
    port: 5173,
    host: '0.0.0.0',
    allowedHosts: true,
    proxy: {
      '^/api/': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '^/ws': {
        target: 'ws://127.0.0.1:8000',
        ws: true,
      }
    }
  },
  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        login: resolve(__dirname, 'zerotrust.html'),
        dashboard: resolve(__dirname, 'dashboard.html'),
        threats: resolve(__dirname, 'threat-center.html'),
        traffic: resolve(__dirname, 'api-traffic.html'),
        policies: resolve(__dirname, 'policies.html'),
        simulator: resolve(__dirname, 'attack-simulator.html'),
        warroom: resolve(__dirname, 'simulation-warroom.html'),
        settings: resolve(__dirname, 'settings.html'),
        protector: resolve(__dirname, 'api-protector.html'),
        presentation: resolve(__dirname, 'presentation.html'),
      }
    }
  }
})
