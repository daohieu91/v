import { defineConfig } from 'vite';
export default defineConfig({
  base: '/v/',
  build: { manifest: true, target: 'es2022', rollupOptions: { input: { index: 'index.html', l2: 'l2.html' } } },
});
