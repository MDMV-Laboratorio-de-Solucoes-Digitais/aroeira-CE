import { sveltekit } from "@sveltejs/kit/vite";
import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [sveltekit()],
  test: {
    name: "desktop",
    root: resolve(__dirname),
    include: ["src/**/*.{test,spec}.{js,ts}"],
    environment: "jsdom",
    globals: true,
    setupFiles: ["src/setupTests.ts"],
    coverage: {
      exclude: [
        "src/lib/components/ui/**",
        "src/routes/**/layout.ts", // SvelteKit boilerplate
        "src/routes/**/page.ts", // SvelteKit boilerplate
        "**/*.d.ts",
        "build/**",
        "src/app.html",
      ],
    },
  },
  resolve: {
    alias: {
      $lib: resolve(__dirname, "./src/lib"),
      $app: resolve(__dirname, "../../tests/mocks/sveltekit"),
    },
    conditions: ["browser", "development"],
  },
});
