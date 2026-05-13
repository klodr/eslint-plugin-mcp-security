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
      // `value`: the iterator yields the whole literal when it is
      // itself base64-shaped, every embedded base64-shaped token
      // (`"Use this tool: <payload> please."`), AND every end-aligned
      // 4-char suffix of those tokens (to recover payloads an attacker
      // has prepended with junk).
      //
      // Collect every distinct decoded candidate first, then emit a
      // SINGLE finding per literal — prefer the HIGH severity path:
      // if any candidate decodes to a known injection keyword, report
      // the first one as `base64Injection`. Otherwise emit a single
      // `base64Text` on the first decodable candidate. The single-
      // report policy keeps a literal full of innocuous base64 from
      // firing a flood of duplicate notices while still surfacing the
      // strongest signal present.
      const findings = [];
      const seen = new Set();
      for (const candidate of extractBase64Candidates(value)) {
        const decoded = tryDecodeBase64AsText(candidate);
        if (!decoded || seen.has(decoded)) continue;
        seen.add(decoded);
        findings.push({ decoded, keyword: findInjectionKeyword(decoded) });
      }
      const injection = findings.find((f) => f.keyword);
      if (injection) {
        context.report({
          node,
          messageId: "base64Injection",
          data: { keyword: injection.keyword, preview: previewOf(injection.decoded) },
        });
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
