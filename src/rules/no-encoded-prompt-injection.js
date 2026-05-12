/**
 * Copyright 2026 klodr
 * SPDX-License-Identifier: Apache-2.0
 */

"use strict";

const {
  INVISIBLE_UNICODE,
  tryDecodeBase64AsText,
  extractBase64Candidates,
  findInjectionKeyword,
  previewOf,
  codepointHex,
} = require("./no-encoded-prompt-injection.helpers.js");

/** @type {import('eslint').Rule.RuleModule} */
const rule = {
  meta: {
    type: "problem",
    docs: {
      description:
        "Disallow base64-encoded text and invisible Unicode characters that may carry hidden LLM instructions",
      recommended: true,
      url: "https://github.com/klodr/eslint-plugin-security-mcp#no-encoded-prompt-injection",
    },
    messages: {
      base64Text:
        "Base64-encoded text detected (decoded: {{preview}}). If intentional, add an eslint-disable-next-line comment.",
      base64Injection:
        "HIGH RISK: base64 string decodes to suspected prompt injection (matched /{{keyword}}/, decoded: {{preview}}).",
      invisibleUnicode:
        "Invisible Unicode character at position {{position}} (U+{{codepoint}}). May be used for hidden prompt injection.",
    },
    schema: [],
  },

  create(context) {
    function checkValue(node, value) {
      if (typeof value !== "string" || value.length === 0) return;

      // 1. Invisible Unicode
      const invisibleMatch = value.match(INVISIBLE_UNICODE);
      if (invisibleMatch) {
        context.report({
          node,
          messageId: "invisibleUnicode",
          data: {
            position: String(invisibleMatch.index),
            codepoint: codepointHex(invisibleMatch[0]),
          },
        });
      }

      // 2. Base64 → text. Scan every base64-shaped substring inside
      // `value`: the iterator yields the whole literal when it is itself
      // base64-shaped, AND each embedded base64-shaped token when the
      // payload is hidden inside surrounding prose (e.g.
      // `"Use this tool: <payload> please."`).
      //
      // Collect every decoded candidate first, then prefer the HIGH
      // severity path: if any candidate decodes to a known injection
      // keyword, report ALL such injections and suppress the lower
      // `base64Text` findings on the same literal — a benign-looking
      // first token must not mask a malicious second one. Otherwise
      // fall back to a single `base64Text` finding (the first decodable
      // candidate) so a literal full of innocuous base64 doesn't fire
      // a flood of duplicate notices.
      const findings = [];
      for (const candidate of extractBase64Candidates(value)) {
        const decoded = tryDecodeBase64AsText(candidate);
        if (!decoded) continue;
        findings.push({ decoded, keyword: findInjectionKeyword(decoded) });
      }
      const injections = findings.filter((f) => f.keyword);
      if (injections.length > 0) {
        for (const f of injections) {
          context.report({
            node,
            messageId: "base64Injection",
            data: { keyword: f.keyword, preview: previewOf(f.decoded) },
          });
        }
      } else if (findings.length > 0) {
        const f = findings[0];
        context.report({
          node,
          messageId: "base64Text",
          data: { preview: previewOf(f.decoded) },
        });
      }
    }

    return {
      Literal(node) {
        checkValue(node, node.value);
      },
      TemplateElement(node) {
        checkValue(node, node.value.cooked);
      },
    };
  },
};

module.exports = rule;
