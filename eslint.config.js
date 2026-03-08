import { fileURLToPath } from "node:url";
import { includeIgnoreFile } from "@eslint/compat";
import js from "@eslint/js";
import globals from "globals";
import tsParser from "@typescript-eslint/parser";

const gitignorePath = fileURLToPath(new URL("./.gitignore", import.meta.url));

/** @type {import('eslint').Linter.Config[]} */
export default [
  {
    ignores: ["**/*.svelte"],
  },
  includeIgnoreFile(gitignorePath),

  // Base JavaScript configuration
  js.configs.recommended,

  // Browser globals for frontend files (JavaScript/TypeScript - excluding .svelte)
  {
    files: ["apps/desktop/src/**/*.{js,ts}"],
    languageOptions: {
      parser: tsParser,
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.browser,
      },
    },
    rules: {
      "no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
    },
  },

  // Node globals for config files, scripts, and tests
  {
    files: [
      "*.config.{js,ts}",
      "**/*.config.{js,ts}",
      "e2e/**/*.{js,ts}",
      "**/*.test.{js,ts}",
      "**/*.spec.{js,ts}",
      "tests/**/*.js",
    ],
    languageOptions: {
      parser: tsParser,
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.node,
        document: "readonly",
      },
    },
    rules: {
      "no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
    },
  },
];
