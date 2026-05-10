# eslint-plugin-security-mcp

[![CI](https://github.com/klodr/eslint-plugin-security-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/klodr/eslint-plugin-security-mcp/actions/workflows/ci.yml)
[![CodeQL](https://github.com/klodr/eslint-plugin-security-mcp/actions/workflows/codeql.yml/badge.svg)](https://github.com/klodr/eslint-plugin-security-mcp/actions/workflows/codeql.yml)
[![Tested with Vitest](https://img.shields.io/badge/tested%20with-vitest-yellow?logo=vitest&labelColor=black)](https://vitest.dev)
[![codecov](https://codecov.io/gh/klodr/eslint-plugin-security-mcp/branch/main/graph/badge.svg)](https://codecov.io/gh/klodr/eslint-plugin-security-mcp)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/klodr/eslint-plugin-security-mcp/badge)](https://scorecard.dev/viewer/?uri=github.com/klodr/eslint-plugin-security-mcp)
[![Socket Security](https://socket.dev/api/badge/npm/package/eslint-plugin-security-mcp)](https://socket.dev/npm/package/eslint-plugin-security-mcp)
[![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/klodr/eslint-plugin-security-mcp?labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)](https://coderabbit.ai)
[![npm version](https://img.shields.io/npm/v/eslint-plugin-security-mcp.svg)](https://www.npmjs.com/package/eslint-plugin-security-mcp)
[![npm downloads](https://img.shields.io/npm/dm/eslint-plugin-security-mcp.svg)](https://www.npmjs.com/package/eslint-plugin-security-mcp)
[![Node.js Version](https://img.shields.io/node/v/eslint-plugin-security-mcp.svg)](https://nodejs.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/klodr/eslint-plugin-security-mcp/pulls)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

ESLint rules to detect prompt-injection vectors hidden in
[Model Context Protocol](https://modelcontextprotocol.io) server code.

## Threat model

Strings that an MCP server exposes to an LLM client (tool descriptions,
parameter docstrings, error messages, resource contents, prompts) are a
prompt-injection surface. An attacker who slips encoded instructions into
that surface — via a malicious dependency, a compromised commit, or a
copy-paste from an untrusted source — can hijack the client LLM at decode
time.

This plugin lints the source code of MCP servers to catch two of the most
common encoding tricks:

- **Base64-encoded text** that decodes to printable ASCII (a hand-rolled
  detector with round-trip validation, plain text scoring, and a keyword
  list for known injection phrases like *"ignore previous instructions"*).
- **Invisible Unicode characters** — zero-width spaces, BOMs, and
  Unicode tag characters (U+E0000–U+E007F) that LLMs read but humans don't.

It is **not** a secret scanner. For secrets (API keys, tokens, SRI hashes
that look like high-entropy blobs), use [gitleaks](https://github.com/gitleaks/gitleaks).
The two tools are complementary: gitleaks catches high-entropy blobs,
this plugin catches low-entropy encoded prose.

## Install

```bash
npm install --save-dev eslint-plugin-security-mcp
```

Requires ESLint 10+ and Node 22.22.2+.

## Usage (flat config)

```js
// eslint.config.js
import mcpSecurity from 'eslint-plugin-security-mcp';

export default [
  // ... your other config blocks
  {
    plugins: { 'security-mcp': mcpSecurity },
    rules: {
      'security-mcp/no-encoded-prompt-injection': 'error',
    },
  },
];
```

## Rules

### `no-encoded-prompt-injection`

Reports string literals and template-literal segments that contain:

1. **Invisible Unicode characters** — always reported as `error`.
2. **Base64 strings that decode to printable text** — reported as `error`.
   When the decoded text matches a known prompt-injection phrase, the
   message is escalated with a `HIGH RISK` prefix.

Hashes following the SRI convention (`sha256-…`, `sha384-…`, `sha512-…`)
are explicitly excluded.

#### Allowing intentional cases

If you have a legitimate base64 fixture (a test vector, a small embedded
asset), opt out per-line:

```ts
// eslint-disable-next-line security-mcp/no-encoded-prompt-injection
const fixture = 'aGVsbG8gd29ybGQgdGhpcyBpcyBhIGZpeHR1cmU=';
```

For test files in particular, you can also disable the rule at the file
or directory level via your `eslint.config.js`.

#### Limitations

- Only detects strings present as literals at lint time. Runtime
  concatenation (`String.fromCharCode(...)`, template assembly across
  multiple `${}` interpolations) is not detected — that is by design;
  static analysis cannot follow arbitrary runtime construction.
- JSON files are not linted unless you configure `eslint-plugin-jsonc`
  or similar.
- Invisible characters in identifiers are caught only if they appear
  inside string literals.

## How it complements other tooling

| Tool | Catches | Misses |
|------|---------|--------|
| **This plugin** | Base64 prose, invisible Unicode | High-entropy secrets, runtime injection |
| **gitleaks** | API keys, tokens, SRI-shaped blobs | Low-entropy encoded prose |
| **CodeQL** | Taint flows, dataflow vulnerabilities | Encoding-layer tricks |
| **OSV-Scanner** | Known CVEs in dependencies | Source-level threats |

Recommended layered defense for an MCP repo:

```
IDE (eslint extension)        → real-time feedback
Pre-commit (husky + lint-staged) → eslint on staged files
CI                            → eslint full scan + gitleaks + OSV-Scanner + ...
```

## Contributing

See [CONTRIBUTING.md](.github/CONTRIBUTING.md). All contributions are
licensed under Apache-2.0 via [DCO](https://developercertificate.org/)
sign-off.

## License

Copyright 2026 klodr

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the [LICENSE](./LICENSE) file for details.
