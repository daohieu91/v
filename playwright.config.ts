import { defineConfig, devices } from '@playwright/test';
export default defineConfig({
  testDir: 'e2e', webServer: { command: 'npx vite build --mode e2e --outDir dist-e2e --emptyOutDir && npx vite preview --outDir dist-e2e --port 4173 --strictPort', port: 4173, reuseExistingServer: false },
  use: { baseURL: 'http://localhost:4173/v/' },
  projects: [{ name: 'chromium', use: devices['Desktop Chrome'] }, { name: 'webkit', use: devices['Desktop Safari'] }, { name: 'firefox', use: devices['Desktop Firefox'] },
             { name: 'mobile-chrome', use: devices['Pixel 7'] }],
});
