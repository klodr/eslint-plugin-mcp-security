# Security Policy

## Scope

This policy covers `eslint-plugin-security-mcp` itself: the published
npm package, the source in this repository, the GitHub Actions workflows,
and the release artifacts.

**Out of scope**: vulnerabilities in your own MCP server code that this
plugin failed to detect. Static analysis is best-effort — see the
`Limitations` section of the README. False negatives (an injection vector
the plugin missed) are bug reports, not security vulnerabilities, and
can be filed as public issues.

## What this plugin provides

- **Stateless static analysis**: each rule is a pure function over the
  ESLint AST. No file system access, no network access, no side effects
  beyond the ESLint reporter API.
- **Zero runtime dependencies**: the package's `dependencies` field is
  empty. The only `peerDependency` is `eslint >= 9.0.0`. Supply-chain
  surface is therefore limited to ESLint itself + Node's built-ins.
- **Supply-chain integrity**: every release artifact is signed with
  Sigstore (`*.sigstore`) and ships an SLSA in-toto attestation
  (`*.intoto.jsonl`). npm publishes carry
  [provenance](https://docs.npmjs.com/generating-provenance-statements).
  All GitHub Actions in `.github/workflows/` are pinned by full commit SHA.
- **Least-privilege CI**: the release workflow is split into a read-only
  build job and a publish job (release-only) that holds `NPM_TOKEN`.
- **Dogfooding**: the plugin lints its own `src/` (with `test/`
  excluded since they intentionally contain encoded fixtures). A
  regression that allows an injection pattern through would also fail
  the plugin's own CI.

## Verifying releases

Every published release of `eslint-plugin-security-mcp` is
cryptographically signed. There is **no private signing key** to manage:
signing is keyless via [Sigstore](https://www.sigstore.dev/) using
GitHub's OIDC identity through the
[`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)
workflow. The trust chain is: GitHub OIDC -> Fulcio (short-lived cert) ->
Rekor (transparency log).

Three independent ways to verify:

### 1. npm package — npm CLI

```bash
npm view eslint-plugin-security-mcp@<version> --json | jq .dist.attestations
npm install --ignore-scripts eslint-plugin-security-mcp@<version>
# or, for the strict provenance check across the dependency tree:
npm audit signatures
```

### 2. GitHub Release artifacts — `gh attestation`

```bash
gh release download v<version> --repo klodr/eslint-plugin-security-mcp \
  --pattern 'index.js*'
gh attestation verify index.js --repo klodr/eslint-plugin-security-mcp
```

### 3. Sigstore bundle — `cosign`

```bash
cosign verify-blob-attestation \
  --bundle index.js.sigstore \
  --certificate-identity-regexp '^https://github\.com/klodr/eslint-plugin-security-mcp/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  index.js
```

The companion `index.js.intoto.jsonl` shipped in the same release is the
DSSE envelope on its own, exposed for tools (like OpenSSF Scorecard's
`Signed-Releases` check) that scan release assets by file extension.

Any verification failure means the artifact was not built by the official
release pipeline — do not install it.

## Software Bill of Materials (SBOM)

Every GitHub Release ships two SBOMs generated from the **runtime**
dependency tree (`devDependencies` pruned before `syft` walks the tree):

- `sbom.spdx.json` — SPDX 2.3 JSON
- `sbom.cdx.json` — CycloneDX 1.6 JSON

Each SBOM carries its own Sigstore attestation binding it to the
`src/index.js` of the same release run.

## Reporting a Vulnerability

If you discover a security vulnerability in `eslint-plugin-security-mcp`,
please report it **privately** so we can address it before any disclosure.

### Preferred channel: Private vulnerability reporting

Use GitHub's
[Private vulnerability reporting](https://github.com/klodr/eslint-plugin-security-mcp/security/advisories/new)
feature. Maintainers will receive your report directly.

### Alternative

If for any reason you cannot use GitHub's private reporting, open an
issue with **only** the message "private security report — please contact
me" and a maintainer will reach out.

**Do not** open a public issue with vulnerability details before a fix
is released.

## What to include

- A clear description of the issue
- Steps to reproduce (proof of concept if possible)
- Affected versions
- Suggested mitigation if you have one

## Response targets

- **Acknowledgement**: within 72 hours
- **Initial assessment**: within 7 days
- **Fix or mitigation**: depends on severity, typically within 30 days
  for high/critical issues

## What is NOT a vulnerability

- **A false negative** (an injection vector the plugin missed). Report
  as a public issue with a reproducible test case — these are
  improvements to detection, not security holes in the plugin itself.
- **A false positive** (the plugin flagging a legitimate string).
  Report as a public issue. Use `// eslint-disable-next-line` to unblock
  in the meantime.
- **A vulnerability in a downstream MCP server** that this plugin
  failed to catch. Report it to that project — this plugin's role is
  defense-in-depth, not a guarantee.

Thanks for helping keep `eslint-plugin-security-mcp` and its users safe.
