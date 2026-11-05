import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: true, // binds to 0.0.0.0, enabling both 127.0.0.1 and localhost
    port: Number(process.env.VITE_PORT ?? 5173),
    strictPort: false, // if 5173 is taken, Vite picks the next free port
    open: true, // automatically opens the browser on server start
    // Backend runs on 8010 (see backend/.env and `uv run uvicorn app.main:app --port 8010`).
    // Override with VITE_API_TARGET if your backend lives elsewhere.
    proxy: { '/api': process.env.VITE_API_TARGET ?? 'http://127.0.0.1:8010' },
  },
})
