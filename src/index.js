/**
 * Copyright 2026 klodr
 * SPDX-License-Identifier: Apache-2.0
 */

"use strict";

const pkg = require("../package.json");
const noEncodedPromptInjection = require("./rules/no-encoded-prompt-injection.js");

const plugin = {
  meta: {
    name: pkg.name,
    version: pkg.version,
  },
  rules: {
    "no-encoded-prompt-injection": noEncodedPromptInjection,
  },
};

// Recommended config (flat-config style)
plugin.configs = {
  recommended: {
    plugins: { "security-mcp": plugin },
    rules: {
      "security-mcp/no-encoded-prompt-injection": "error",
    },
  },
};

module.exports = plugin;
