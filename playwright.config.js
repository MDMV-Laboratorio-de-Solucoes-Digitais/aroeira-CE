import { defineConfig } from "@playwright/test";

export default defineConfig({
  webServer: {
    command: "npm run build && npm run preview -- --port 4173 --strictPort",
    cwd: "apps/desktop",
    port: 4173,
    reuseExistingServer: !process.env.CI,
    timeout: 120 * 1000,
  },
  testDir: "e2e",
});
