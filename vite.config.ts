import { defineConfig } from 'vite';
export default defineConfig({
  base: '/v/',
  // A classic (iife) worker: works in every engine that passes the BigInt guard, without module-worker support.
  worker: { format: 'iife' },
  build: { manifest: true, target: 'es2022', rollupOptions: { input: { index: 'index.html', l2: 'l2.html' } } },
});
