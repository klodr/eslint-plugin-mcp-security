# Roadmap

Public-facing plan for `eslint-plugin-mcp-security`. Items here are
indicative — actual prioritisation depends on real-world MCP server
threat reports and user feedback.

## v0.1.0 (current)

- Rule `no-encoded-prompt-injection` (base64-as-text + invisible
  Unicode + injection-keyword escalation)
- `recommended` config exposing the rule at `error`
- Apache-2.0 license, NOTICE file
- 0 runtime dependencies
- Test coverage on the detection logic

## v0.2.0 (next minor)

- **Configurable rule options**:
  - `minBase64Length` (default 24)
  - `printableTextRatio` (default 0.9)
  - `extraInvisibleCodepoints` (extension list)
  - `customInjectionKeywords` (regex array, merged with built-ins)
  - `whitelistPatterns` (regex array of strings to never report)
- **Better message context**: byte offset + column inside the literal
  for invisible Unicode, not only character index.
- **JSON file support** documented as a plugin recipe (using
  `eslint-plugin-jsonc`).

## v0.3.0

- New rule `no-untrusted-tool-description` — flag string literals
  passed to MCP `Tool.description` / `Prompt.description` /
  `Resource.description` that are not local string literals (i.e.
  read from `fs.readFile`, env, or fetch). Heuristic, opt-in.
- New rule `require-zod-input-schema` — flag MCP tool handlers whose
  `inputSchema` is not a Zod object (or is `z.any()`). Helps enforce
  the strict input validation pattern used in `klodr/*` MCPs.

## v0.4.0

- New rule `no-eval-in-mcp-handler` — flag `eval`,
  `new Function(...)`, dynamic `require` inside MCP tool handlers.
- New rule `no-shell-out-without-allowlist` — flag `child_process.exec`
  / `spawn` with non-literal first arg in MCP handlers.

## v1.0.0 milestone

Lock the plugin export contract per `CONTINUITY.md`. Targeted when
the rule set covers what `klodr/*` MCPs and the broader public MCP
ecosystem actually need (driven by issues filed on this repo and
adoption metrics on npm).

## Out of scope (will not happen here)

- Runtime taint analysis — that's CodeQL territory.
- Secret scanning (API keys, tokens) — use `gitleaks`.
- Known-CVE detection in dependencies — use OSV-Scanner / Dependabot.
- Cross-file dataflow analysis — beyond what an ESLint rule can
  reasonably do without a full project graph.
- Detection of injection at runtime (a malicious user passing an
  injected payload as tool input) — the plugin only reasons about
  source code.

## How to influence this roadmap

Open a feature request issue. Real-world examples (a CVE, a public
MCP server caught with a vector this plugin would have caught, a
false positive with a high-volume codebase) move items up the list.
