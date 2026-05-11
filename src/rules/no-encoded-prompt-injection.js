/**
 * Copyright 2026 klodr
 * SPDX-License-Identifier: Apache-2.0
 */

"use strict";

const {
  INVISIBLE_UNICODE,
  tryDecodeBase64AsText,
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

      // 2. Base64 → text
      const decoded = tryDecodeBase64AsText(value);
      if (decoded) {
        const keyword = findInjectionKeyword(decoded);
        if (keyword) {
          context.report({
            node,
            messageId: "base64Injection",
            data: { keyword, preview: previewOf(decoded) },
          });
        } else {
          context.report({
            node,
            messageId: "base64Text",
            data: { preview: previewOf(decoded) },
          });
        }
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
