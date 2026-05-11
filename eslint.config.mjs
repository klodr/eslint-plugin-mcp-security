/**
 * Copyright 2026 klodr
 * SPDX-License-Identifier: Apache-2.0
 */

import prettierConfig from "eslint-config-prettier";
import mcpSecurity from "./src/index.js";

export default [
  {
    ignores: ["node_modules/", "coverage/", "dist/"],
  },
  // Apply our own rule to ourselves (dogfooding) — excluded for test/
  // which intentionally contain encoded strings as fixtures.
  {
    files: ["src/**/*.js"],
    plugins: { "security-mcp": mcpSecurity },
    rules: {
      "security-mcp/no-encoded-prompt-injection": "error",
    },
  },
  {
    files: ["**/*.{js,mjs,cjs}"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",
      globals: {
        Buffer: "readonly",
        console: "readonly",
        process: "readonly",
        module: "writable",
        require: "readonly",
        __dirname: "readonly",
        __filename: "readonly",
      },
    },
    rules: {
      "no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "no-undef": "error",
    },
  },
  // Must come last: disables ESLint rules that would conflict with Prettier.
  prettierConfig,
];
