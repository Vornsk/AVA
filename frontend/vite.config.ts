import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// 프론트(별도 루트)의 빌드 산출물을 백엔드 embed 디렉터리로 출력 → 단일 바이너리.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: { '/api': 'http://127.0.0.1:8090' }, // 개발 중 API는 Go 백엔드로 프록시
  },
  build: {
    outDir: '../backend/internal/webui/dist',
    emptyOutDir: true,
  },
})
