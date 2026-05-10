# 🆘 Support

`eslint-plugin-mcp-security` is an open-source ESLint plugin maintained
by **@klodr** in spare time. Use the channels below — opening an issue
with the right template gives the fastest path to a triage decision.

## 🐛 Bug reports

Open an issue using the **Bug report** template. Include:

- Plugin version (`npm ls eslint-plugin-mcp-security`).
- ESLint version + flat-config snippet showing the plugin block.
- Node.js version (`node --version`).
- Minimal failing source (or the offending string literal) and the rule
  output you observed vs. what you expected.
- For false positives: the exact base64 / Unicode payload and why you
  consider it benign.

## ✨ Feature requests

Open an issue using the **Feature request** template. State the threat
or false-positive class first, then the proposed rule / option.
Proposals are evaluated against [`docs/ROADMAP.md`](../docs/ROADMAP.md)
— items already scheduled or explicitly out-of-scope are listed there.

## 🔒 Security issues

**Do not open a public issue.** Follow the coordinated-disclosure
procedure in [`SECURITY.md`](SECURITY.md). Acknowledgement target:
72 h. Critical-CVE patch target: 7 days.

A "security issue" here means a flaw in the plugin itself
(false-negative on a documented vector, prototype pollution in the
detector, ReDoS) — not the absence of a rule for a new attack class
(use Feature request for that).

## ❓ Questions

Search [closed issues](https://github.com/klodr/eslint-plugin-mcp-security/issues?q=is%3Aissue+is%3Aclosed)
first — most operational questions (per-line opt-out, file-level
disable, integration with other linters) are already answered. If
nothing matches, open a new issue with the **Bug report** template and
label it `question`.

## ⏱️ Response expectations

| Severity | Target |
|---|---|
| Security issue acknowledgement | 72 h (per `SECURITY.md`) |
| Critical CVE patch released | 7 days |
| False-negative on documented vector | 48 h |
| Other issue / PR | 7 days |

Best-effort SLOs from a solo maintainer doing open-source on the side.
Sponsoring (see [`FUNDING.yml`](FUNDING.yml)) helps keep the lights on.
