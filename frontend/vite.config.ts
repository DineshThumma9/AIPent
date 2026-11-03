import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // 8000 is often taken by another local project; override with VITE_API_TARGET.
    proxy: { '/api': process.env.VITE_API_TARGET ?? 'http://127.0.0.1:8000' },
  },
})
