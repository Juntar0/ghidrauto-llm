import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Proxy API to backend
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://localhost:5555',
    },
  },
})
