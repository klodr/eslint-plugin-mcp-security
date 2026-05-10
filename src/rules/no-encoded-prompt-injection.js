/**
 * Copyright 2026 klodr
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

/**
 * Phrases that, if found in a base64-decoded string, escalate severity
 * because they match well-known prompt-injection patterns.
 */
const INJECTION_KEYWORDS = [
  /ignore (previous|prior|above|all)/i,
  /disregard (previous|the|all|above)/i,
  /forget (everything|previous|all)/i,
  /you are (now|actually)/i,
  /new instructions?/i,
  /system (prompt|message|role)/i,
  /\bact as\b/i,
  /pretend (to be|you)/i,
  /jailbreak/i,
  /developer mode/i,
  /reveal (your|the) (prompt|instructions|system)/i,
  /print (your|the) (prompt|instructions|system)/i,
  /<\|.*?\|>/,
  /\[INST\]|\[\/INST\]/,
  /<\/?(system|user|assistant|tool)>/i,
];

/**
 * Invisible Unicode characters that LLMs read but humans don't see:
 * - U+200B–U+200D : zero-width space, non-joiner, joiner
 * - U+FEFF       : zero-width no-break space (BOM)
 * - U+E0000–U+E007F : Tags block (used in known prompt-injection PoCs)
 */
const INVISIBLE_UNICODE = /[\u200B-\u200D\uFEFF]|[\u{E0000}-\u{E007F}]/u;

/** Candidate base64 strings: standard alphabet OR base64url, with optional padding. */
const BASE64_CANDIDATE = /^[A-Za-z0-9+/_-]{24,}={0,2}$/;

/** SRI hash prefix to ignore entirely. */
const SRI_PREFIX = /^sha(256|384|512)-/;

/**
 * Heuristic: does this byte buffer look like printable text?
 * - ≥90% of bytes are printable ASCII (incl. tab/LF/CR)
 * - ≥95% of bytes are ASCII (rules out random binary that happens to have some printable bytes)
 */
function looksLikeText(buf) {
  if (buf.length < 8) return false;
  let printable = 0;
  let ascii = 0;
  for (const b of buf) {
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126)) printable++;
    if (b < 128) ascii++;
  }
  return printable / buf.length >= 0.9 && ascii / buf.length >= 0.95;
}

/**
 * Try to decode `s` as base64 (standard or url-safe variant).
 * Returns the decoded UTF-8 string if AND ONLY IF:
 * - it survives a round-trip re-encoding (eliminates non-base64 high-density strings)
 * - it decodes to something that looks like printable text
 * Otherwise returns null.
 */
function tryDecodeBase64AsText(s) {
  if (!BASE64_CANDIDATE.test(s)) return null;
  if (SRI_PREFIX.test(s)) return null;

  // Normalize base64url to standard base64
  const normalized = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);

  let buf;
  try {
    buf = Buffer.from(padded, 'base64');
  } catch {
    return null;
  }

  // Round-trip check: Buffer.from is lenient and will swallow invalid chars,
  // so we re-encode and compare to ensure the input was actually valid base64.
  const reencoded = buf.toString('base64');
  if (reencoded.replace(/=+$/, '') !== padded.replace(/=+$/, '')) return null;

  if (!looksLikeText(buf)) return null;

  return buf.toString('utf8');
}

function findInjectionKeyword(text) {
  for (const re of INJECTION_KEYWORDS) {
    if (re.test(text)) return re.source;
  }
  return null;
}

function previewOf(text, max = 60) {
  const truncated = text.length > max ? text.slice(0, max) + '…' : text;
  return JSON.stringify(truncated);
}

function codepointHex(ch) {
  return ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
}

/** @type {import('eslint').Rule.RuleModule} */
const rule = {
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow base64-encoded text and invisible Unicode characters that may carry hidden LLM instructions',
      recommended: true,
      url: 'https://github.com/klodr/eslint-plugin-security-mcp#no-encoded-prompt-injection',
    },
    messages: {
      base64Text:
        'Base64-encoded text detected (decoded: {{preview}}). If intentional, add an eslint-disable-next-line comment.',
      base64Injection:
        'HIGH RISK: base64 string decodes to suspected prompt injection (matched /{{keyword}}/, decoded: {{preview}}).',
      invisibleUnicode:
        'Invisible Unicode character at position {{position}} (U+{{codepoint}}). May be used for hidden prompt injection.',
    },
    schema: [],
  },

  create(context) {
    function checkValue(node, value) {
      if (typeof value !== 'string' || value.length === 0) return;

      // 1. Invisible Unicode
      const invisibleMatch = value.match(INVISIBLE_UNICODE);
      if (invisibleMatch) {
        context.report({
          node,
          messageId: 'invisibleUnicode',
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
            messageId: 'base64Injection',
            data: { keyword, preview: previewOf(decoded) },
          });
        } else {
          context.report({
            node,
            messageId: 'base64Text',
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
// Internal helpers exposed for property-based tests; not part of the
// public API (no `_` prefix would still be visible to ESLint, which
// ignores unknown rule keys, so this is safe to attach on the rule).
module.exports.tryDecodeBase64AsText = tryDecodeBase64AsText;
module.exports.looksLikeText = looksLikeText;
module.exports.findInjectionKeyword = findInjectionKeyword;
