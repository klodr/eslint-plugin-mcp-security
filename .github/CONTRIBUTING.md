# Contributing to eslint-plugin-security-mcp

Thanks for considering a contribution.

## Developer Certificate of Origin (DCO)

By contributing, you agree to license your contribution under the
[Apache License 2.0](./LICENSE) and certify the
[Developer Certificate of Origin](https://developercertificate.org/).

Sign your commits with:

```bash
git commit -s
```

This appends a `Signed-off-by: Your Name <email>` line to the commit
message. Pull requests with unsigned commits will be asked to amend.

## Local development

```bash
npm install
npm run lint
npm test
```

## Adding a new rule

1. Create `src/rules/<rule-name>.js` with the standard ESLint rule shape
   (`meta` + `create`).
2. Wire it up in `src/index.js` under the exported `rules` map.
3. Add tests in `test/<rule-name>.test.mjs` using `RuleTester` from ESLint.
4. Document the rule in `README.md` under the **Rules** section.

## Testing the rule end-to-end

The `test/` directory uses [Vitest](https://vitest.dev) with ESLint's
built-in `RuleTester`. Run:

```bash
npm test
```

## Pull request checklist

- [ ] Commits are signed off (DCO).
- [ ] `npm run lint` passes.
- [ ] `npm test` passes.
- [ ] New behavior has tests covering both `valid` and `invalid` cases.
- [ ] Documentation updated if rule semantics changed.
