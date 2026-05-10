# Assurance case

## Goal

Detect, at lint time, **encoded prompt-injection vectors** hidden in
the source code of Model Context Protocol (MCP) server implementations
written in JavaScript / TypeScript.

The plugin is a defense-in-depth layer alongside `gitleaks`,
OSV-Scanner, CodeQL, and code review. It is **not** a complete MCP
security solution.

## In-scope threat model

The strings an MCP server exposes to an LLM client (tool descriptions,
parameter docstrings, error messages, resource contents, prompts) are
a prompt-injection surface. An attacker who slips encoded instructions
into that surface — via a malicious dependency, a compromised commit,
or a copy-paste from an untrusted source — can hijack the client LLM
at decode time without any human reviewer noticing.

The `no-encoded-prompt-injection` rule covers the two encoding tricks
most observed in published MCP-injection PoCs:

### 1. Base64-encoded text decoding to printable ASCII

- Round-trip validation eliminates non-base64 high-density strings
  that happen to match the alphabet (Buffer.from is lenient and
  silently swallows invalid characters).
- `looksLikeText` heuristic (≥90 % printable + ≥95 % ASCII) rejects
  random binary that happens to have some printable bytes.
- Minimum length 24 chars prevents flagging short tokens that match
  the alphabet by chance (`abc123abc123abc123abc123`).
- SRI hash prefix `sha(256|384|512)-` is excluded — every lockfile
  would otherwise generate hundreds of false positives.
- Both standard base64 and base64url alphabets are recognised
  (`+/_-`).

### 2. Invisible Unicode characters

- U+200B (zero-width space), U+200C (zero-width non-joiner),
  U+200D (zero-width joiner)
- U+FEFF (zero-width no-break space, BOM)
- U+E0000–U+E007F (Tags block) — the vector documented in the
  Riley Goodside / SimonW posts on hidden LLM instructions

### 3. Severity escalation

When the decoded base64 matches a phrase from `INJECTION_KEYWORDS`
(an extensible regex list seeded with patterns like
`ignore (previous|prior|above|all)`, `act as`, `jailbreak`,
`<\|.*?\|>`, `\[INST\]`), the rule message is prefixed with
`HIGH RISK:` so reviewers can prioritise.

## Detection guarantees

For any string literal or template-literal segment present at lint
time and matching the rule patterns, the plugin **will** report it
unless excluded by an opt-out comment or whitelisted SRI prefix.

For invisible Unicode the false-positive rate is essentially zero
(the chance of legitimate U+200B in source is negligible). For
base64-as-text the false-positive rate is bounded by the
`looksLikeText` heuristic plus the SRI exclusion.

## Out of scope (explicitly)

The plugin does **not** detect:

- **Runtime concatenation.** `String.fromCharCode(...)`, template
  assembly across multiple `${}` interpolations, computed property
  reads, or any string built at runtime escapes static analysis. By
  design — static analysis cannot follow arbitrary runtime
  construction.
- **Strings inside JSON / YAML / Markdown files.** Only literals
  visited by ESLint are checked. JSON files require
  `eslint-plugin-jsonc` or equivalent. YAML and Markdown are not
  covered.
- **Identifiers carrying invisible characters** unless they appear
  inside string literals.
- **High-entropy secrets.** Use `gitleaks` for API keys, tokens, SRI
  blobs in lockfiles.
- **Known-CVE dependencies.** Use OSV-Scanner.
- **Taint flow / dataflow vulnerabilities.** Use CodeQL.
- **Runtime / deployment-time prompt injection** (an attacker
  injecting via tool input at runtime). The plugin only reasons about
  source code.

## Layered defense recommendation

| Layer | Tool | Catches |
|---|---|---|
| IDE | ESLint extension + this plugin | Encoded prose at type time |
| Pre-commit | husky + lint-staged | Encoded prose on staged files |
| CI | this plugin (full scan) + gitleaks + OSV-Scanner + CodeQL | Encoded prose, secrets, CVEs, taint |
| Code review | Human + CodeRabbit/Qodo | Logical / semantic injection |

No single layer is sufficient.

## False-negative responsibility

Documented false negatives (a vector the rule was supposed to catch
but missed) are treated as security issues — see `SECURITY.md` for
disclosure. New vectors not yet covered by the rule are feature
requests, not security issues.
