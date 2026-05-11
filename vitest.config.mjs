/**
 * Copyright 2026 klodr
 * SPDX-License-Identifier: Apache-2.0
 */

import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.{js,mjs}"],
    globals: false,
    coverage: {
      provider: "v8",
      // `lcov` for codecov-action's primary upload; `json` (v8 native)
      // carries the full branch + statement detail that codecov needs
      // to compute indirect-changes accurately. `text` keeps the
      // human-readable per-file summary in CI logs. Mirrors the 4 MCP
      // klodr/* repos.
      reporter: ["text", "lcov", "json"],
      // Include every source file so untested ones show as 0% rather
      // than being silently omitted from the v8 coverage report.
      include: ["src/**/*.js"],
      exclude: ["src/**/*.test.js"],
    },
  },
});
