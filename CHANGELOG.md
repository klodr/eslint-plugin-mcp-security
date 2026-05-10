# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0](https://github.com/klodr/eslint-plugin-security-mcp/compare/v0.1.0...v0.2.0) (2026-05-10)


### Added

* initial commit ([504eb2f](https://github.com/klodr/eslint-plugin-security-mcp/commit/504eb2fb371e3dd794e8f94ef6a22e4e721f09b8))


### Changed

* add auto-merge caller for release-please PRs ([#12](https://github.com/klodr/eslint-plugin-security-mcp/issues/12)) ([985934b](https://github.com/klodr/eslint-plugin-security-mcp/commit/985934b108feedf0971fdd09379c0b58c3ef1eea))
* add release-please workflow for automated releases ([#5](https://github.com/klodr/eslint-plugin-security-mcp/issues/5)) ([6681126](https://github.com/klodr/eslint-plugin-security-mcp/commit/66811268fa8ab8e1cecd9736e0bef6f1e5fdedb8))
* apply klodr hardening baseline (workflows, rulesets, configs) ([#1](https://github.com/klodr/eslint-plugin-security-mcp/issues/1)) ([b3a55ed](https://github.com/klodr/eslint-plugin-security-mcp/commit/b3a55edbc08d44da14d9d0f6630482b93476d632))
* bump github/codeql-action from 4.35.3 to 4.35.4 ([#2](https://github.com/klodr/eslint-plugin-security-mcp/issues/2)) ([1f93dce](https://github.com/klodr/eslint-plugin-security-mcp/commit/1f93dce3b44e253085ae4d184a050ff724cf50b0))
* **dependabot:** use chore(deps) prefix for Conventional Commits ([#6](https://github.com/klodr/eslint-plugin-security-mcp/issues/6)) ([3b6bfc4](https://github.com/klodr/eslint-plugin-security-mcp/commit/3b6bfc4face5eb7b4009e2ccc018e55d3db6bf66))
* **deps-dev:** bump eslint and lint-staged majors ([#3](https://github.com/klodr/eslint-plugin-security-mcp/issues/3)) ([1fe6352](https://github.com/klodr/eslint-plugin-security-mcp/commit/1fe635245fcaa4f3a24fc45f8bb11a8317f9bf03))
* **deps:** bump actions/github-script SHA ([#8](https://github.com/klodr/eslint-plugin-security-mcp/issues/8)) ([01bc443](https://github.com/klodr/eslint-plugin-security-mcp/commit/01bc443c96e104e21695c076f4fce4cd6daef562))
* drop node 20, bump engines, add codecov via composites ([#4](https://github.com/klodr/eslint-plugin-security-mcp/issues/4)) ([28fd5a9](https://github.com/klodr/eslint-plugin-security-mcp/commit/28fd5a93a2b5c781889caea5d3848376ba28be4f))
* extract rule helpers + doc fix ESLint 10.3.0+ ([#10](https://github.com/klodr/eslint-plugin-security-mcp/issues/10)) ([6ead0f3](https://github.com/klodr/eslint-plugin-security-mcp/commit/6ead0f31a03a26346154a604ceabb2a908b7db2e))
* rename package to eslint-plugin-security-mcp ([#7](https://github.com/klodr/eslint-plugin-security-mcp/issues/7)) ([f125467](https://github.com/klodr/eslint-plugin-security-mcp/commit/f125467631b519a6eff322b4dd3e3fb77254353f))

## [Unreleased]

### Added

- Initial `no-encoded-prompt-injection` rule detecting base64-encoded
  text and invisible Unicode characters in string literals and template
  segments.
- Recommended flat-config preset under `plugin.configs.recommended`.

## [0.1.0] - 2026-05-10

Initial release.
