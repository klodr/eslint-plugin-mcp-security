# AGENTS.md

This repository is **eslint-plugin-security-mcp** — an ESLint plugin
that lints the source code of Model Context Protocol servers for
prompt-injection vectors hidden in encoded strings (base64) and
invisible Unicode characters.

This file is the **canonical source of truth** for any AI agent that
edits the code in this repository. Read it before making changes. It
encodes the conventions the maintainers actually enforce — not
aspirations.

## Audience boundary

| Audience                                           | Source of truth                                |
| -------------------------------------------------- | ---------------------------------------------- |
| Edits this repo's code                             | **`AGENTS.md`** (you are here)                 |
| Uses the plugin in their own MCP repo              | `README.md`                                    |
| Vulnerability reporting / supply-chain story       | `SECURITY.md`                                  |
| Contributor PR checklist                           | `CONTRIBUTING.md`                              |

Do not duplicate what those documents say. Reference them.

## Setup

Node `>= 22.22.2` is enforced via `engines` in `package.json`. CI runs
the matrix on Node 22 and 24.

```bash
npm install
```

This repo uses **npm**, not pnpm. Lockfile is `package-lock.json`.

Husky hooks install via the `prepare` script.

## Build, test, lint

This package ships `src/` as-is — there is no build step. The exact npm
scripts (see `package.json`):

| Command                | What it does                                       |
| ---------------------- | -------------------------------------------------- |
| `npm run lint`         | ESLint on the whole repo (dogfooding the rule)     |
| `npm test`             | `vitest run` (RuleTester specs)                    |
| `npm run test:watch`   | `vitest` (interactive)                             |

Run `npm run lint && npm test` before every push. Husky's `pre-push`
hook will do it for you, but failing locally before push is faster than
failing in CI.

## Code style

- CommonJS in `src/` (`"type": "commonjs"` at package level), ESM in
  `tests/` and `eslint.config.mjs` (the `.mjs` extension overrides the
  package type).
- ESLint flat config in `eslint.config.mjs`. The plugin lints itself
  on `src/**` (dogfooding) — `tests/**` are excluded because they
  intentionally contain encoded fixtures.
- 2-space indent, LF line endings, UTF-8 (enforced by `.editorconfig`
  + EditorConfig CI check).
- `no-unused-vars` with `^_` exemption for prefixed args.

## Tests

- Framework: **vitest** (`vitest run`).
- Lives in `tests/`, name pattern `*.test.mjs` (ESM).
- Tests use ESLint's built-in `RuleTester` from
  `eslint/use-at-your-own-risk`. Each rule must have BOTH `valid` and
  `invalid` cases, and invalid cases must assert the `messageId`
  (not just a substring of the rendered message).

## Commits

- **Conventional commits** (`feat:`, `fix:`, `docs:`, `chore:`,
  `refactor:`, `test:`, `ci:`, `build:`).
- **Signed commits required.** Configure SSH commit signing or set
  `commit.gpgsign=true`.
- **Subject ≤72 characters.** The pre-push hook counts unicode code
  points (not bytes) so emoji and accented characters count correctly.
- **DCO sign-off required.** Use `git commit -s` (or `-S -s`) so the
  commit carries `Signed-off-by:`.
- **No `Co-Authored-By:` trailers.** This repo's maintainer does not
  use co-authorship attribution on AI-assisted commits.

## Pre-push gate (`.husky/pre-push`)

For every new commit being pushed:

1. Signature is `G`/`U`/`E`.
2. Subject ≤72 chars (unicode-aware).

Then once per push:

1. `npm run lint`
2. `npm test`
3. `npm audit --audit-level=high`

Bypass with `git push --no-verify` only when the hook itself is wrong
(rare). The bypass is recorded in the local reflog.

## PR workflow

- Open the PR against `main`.
- Wait for CodeRabbit review (assertive profile). Drain every
  comment thread before re-pinging — never spam `@coderabbitai
  review` while threads are unresolved.
- CodeRabbit commands are posted **bare**, no surrounding prose
  (e.g. a comment whose entire body is `@coderabbitai review`).
- Do not let CodeRabbit push commits — this repo is solo-maintained
  and a bot commit would block merge under branch protection.
- Auto-merge: `gh pr merge --squash --auto`. Branch protection waits
  on CI + CodeRabbit + Scorecard.
- Maintainers do not self-approve their own PRs. Approvals only from
  external bots (release-please-app, dependabot, CodeRabbit).

## Source layout

```text
src/
  index.js                              plugin entrypoint (CommonJS)
  rules/
    no-encoded-prompt-injection.js      first rule
tests/
  no-encoded-prompt-injection.test.mjs  RuleTester spec
.github/
  workflows/                            CI, CodeQL, Scorecard, release...
  dependabot.yml                        dep update bot config
eslint.config.mjs                       repo's own ESLint config
                                        (plugin dogfoods itself on src/)
```

## Adding a new rule

1. Create `src/rules/<rule-name>.js` with the standard ESLint rule shape
   (`meta` + `create`). `meta.docs.url` must point to the README anchor
   for that rule.
2. Wire it up in `src/index.js` under the exported `rules` map AND
   under `plugin.configs.recommended.rules`.
3. Add tests in `tests/<rule-name>.test.mjs` using `RuleTester`.
   Cover both `valid` and `invalid`. Assert `messageId` on invalid.
4. Document the rule in `README.md` under the **Rules** section.
5. Update `CHANGELOG.md` under `[Unreleased]` -> `Added`.

## Security guards encoded in the code

The full security posture is described in `SECURITY.md`. What follows
is the minimum an editor must know to avoid regressing it:

- **Stateless rules**: the `create()` function may capture per-file
  state, but the module itself must not hold state across files.
- **No I/O in rules**: ESLint runs rules in-process against the AST.
  Never `require('fs')` from a rule. Never call out to the network.
- **Round-trip validation in `tryDecodeBase64AsText`**: we re-encode
  the candidate buffer and compare to the original to eliminate false
  positives from `Buffer.from`'s lenient input handling. Do not
  remove this check.
- **SRI prefix exclusion**: `sha256-…` / `sha384-…` / `sha512-…`
  strings are explicitly excluded from base64 detection. This is
  load-bearing — most package-lock entries carry SRI hashes that
  decode to high-entropy noise.

## Before opening a PR — checklist

1. `npm run lint && npm test` (both green).
2. New behaviour has a test. New error path has a test.
3. Commit subject ≤72 chars, signed, conventional, no Co-Authored-By.
4. If you touched a security guard listed above: also re-read the
   matching section in `SECURITY.md` and update it if the threat model
   shifted.
5. If you changed user-facing behaviour: update `README.md` and the
   relevant `CHANGELOG.md` section.
