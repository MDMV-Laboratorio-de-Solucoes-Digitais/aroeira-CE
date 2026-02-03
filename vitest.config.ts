import { defineConfig } from "vitest/config";
import { svelte, vitePreprocess } from "@sveltejs/vite-plugin-svelte";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Plugin to aggressively redirect props.svelte.js to a plain JS mock
const patchTestingLibrary = {
  name: "patch-testing-library",
  enforce: "pre", // Run before other plugins
  resolveId(source, importer) {
    if (source.includes("props.svelte.js")) {
      // Redirect to plain JS file to avoid Svelte compilation logic
      return resolve(__dirname, "tests/mocks/testing-library-props.js");
    }
    if (
      source.endsWith("box.svelte.js") &&
      (source.includes("svelte-toolbelt") ||
        importer?.includes("svelte-toolbelt"))
    ) {
      return resolve(__dirname, "tests/mocks/svelte-toolbelt-box.js");
    }
    if (
      source.endsWith("box-extras.svelte.js") &&
      (source.includes("svelte-toolbelt") ||
        importer?.includes("svelte-toolbelt"))
    ) {
      return resolve(__dirname, "tests/mocks/svelte-toolbelt-box-extras.js");
    }
    if (
      source.endsWith("use-ref-by-id.svelte.js") &&
      (source.includes("svelte-toolbelt") ||
        importer?.includes("svelte-toolbelt"))
    ) {
      return resolve(__dirname, "tests/mocks/svelte-toolbelt-use-ref-by-id.js");
    }
  },
};

export default defineConfig({
  plugins: [
    patchTestingLibrary,
    svelte({
      preprocess: [vitePreprocess()],
      compilerOptions: {
        dev: true,
      },
      extensions: [".svelte", ".svelte.js", ".svelte.ts"],
    }),
  ],
  test: {
    include: ["apps/desktop/src/**/*.{test,spec}.{js,ts}"],
    exclude: ["**/node_modules/**", "**/dist/**", "e2e/**"],
    environment: "jsdom",
    globals: true,
    setupFiles: [resolve(__dirname, "apps/desktop/src/setupTests.ts")],
    alias: {
      "$app/navigation": resolve(
        __dirname,
        "tests/mocks/sveltekit/navigation.ts",
      ),
      "$app/stores": resolve(__dirname, "tests/mocks/sveltekit/stores.ts"),
      "$app/paths": resolve(__dirname, "tests/mocks/sveltekit/paths.ts"),
      $lib: resolve(__dirname, "apps/desktop/src/lib"),
      $app: resolve(__dirname, "apps/desktop/.svelte-kit/runtime/app"),
    },
    server: {
      deps: {
        inline: [
          "@testing-library/svelte",
          "@testing-library/svelte-core",
          "bits-ui",
          "lucide-svelte",
          "svelte-toolbelt",
        ],
      },
    },
  },
  resolve: {
    conditions: ["browser", "development"],
  },
});
