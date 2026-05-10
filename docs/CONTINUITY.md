# Continuity policy

This plugin follows **semantic versioning** with the conventions below.

## Stable API surface (semver-protected)

Across minor releases the following surface is guaranteed stable —
breaking changes require a major bump:

- **Plugin export shape**: `plugin.rules`, `plugin.configs.recommended`,
  `plugin.meta.{name,version}`.
- **Rule names**: `mcp-security/no-encoded-prompt-injection` will not
  be renamed in a non-major release.
- **Rule severities in `recommended`**: a rule won't be downgraded
  from `error` to `warn` (or vice versa) in a minor — it requires a
  major.
- **Message IDs**: `base64Text`, `base64Injection`, `invisibleUnicode`
  are part of the public contract (consumers may key off them in
  `eslint-disable-next-line` comments and CI parsers).

## Detector logic — semver semantics

| Change type | Bump |
|---|---|
| Bug fix in detection (false positive removed, edge case handled) | patch |
| New keyword added to `INJECTION_KEYWORDS` | minor |
| New invisible-Unicode codepoint added to detection set | minor |
| New rule added to the plugin | minor |
| New option added to a rule (default = current behavior) | minor |
| Breaking exclusion behavior (e.g. SRI rule changes) | major |
| Default of an existing option flipped | major |
| Rule promoted to `recommended` | minor |
| Rule removed from `recommended` | major |
| Rule deleted entirely | major |

## Node / ESLint compatibility

- **Node.js**: ≥ 20 (active LTS) — drops align with the official
  Node release schedule.
- **ESLint**: ≥ 9 (flat-config era). ESLint 8 legacy `.eslintrc` is
  not supported and will not be back-ported.

## Deprecation process

When a rule, option, or message ID is to be removed:

1. **Minor release N**: deprecation notice in CHANGELOG; runtime
   warning emitted on first use; documented in the rule's `docs.url`
   page.
2. **Minor release N+2 or major release**: removal.

A deprecation lasts at least 6 months between deprecation notice and
removal, even if N+2 falls earlier.

## Pre-1.0 caveat

While the plugin is at `0.x`, the contract above is the **intent**
but breaking changes can also happen in minor releases when
warranted. Any such change is called out explicitly in the CHANGELOG
under a `### Breaking` heading. Consumers pinning to `^0.1.0` may
want to switch to `~0.1.0` (patch only) until v1.0.0.

The `1.0.0` release will lock the contract above strictly.
