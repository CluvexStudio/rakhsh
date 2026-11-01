import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { viteSingleFile } from 'vite-plugin-singlefile'
import path from 'node:path'

// One self-contained index.html (JS + CSS + fonts inlined) so the panel renders fully offline —
// essential for a tool used during an internet shutdown.
export default defineConfig({
  plugins: [react(), tailwindcss(), viteSingleFile()],
  resolve: { alias: { '@': path.resolve(import.meta.dirname, 'src') } },
  build: {
    target: 'es2022',
    cssMinify: true,
    assetsInlineLimit: 100000000,
    chunkSizeWarningLimit: 20000,
  },
})
