/**
 * Copyright 2026 klodr
 * SPDX-License-Identifier: Apache-2.0
 */

"use strict";

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

/**
 * Anchored regex used by `tryDecodeBase64AsText` to validate a candidate
 * string. {12,} on the alphabet portion catches base64 representations of
 * payloads with ≥9 decoded bytes — enough for single-word injection
 * keywords like "jailbreak" (9 bytes → 12 base64 chars) and short phrases
 * like "ignore all" (10 bytes → 14 alpha + 2 padding). Below this length
 * the false-positive risk on short identifiers in source code outweighs
 * the marginal detection gain.
 */
const BASE64_CANDIDATE = /^[A-Za-z0-9+/_-]{12,}={0,2}$/;

/**
 * Non-anchored variant used to extract candidate substrings from a larger
 * literal. Lets the rule detect base64 payloads embedded in surrounding
 * prose (e.g. `"Use this tool: aWdub3JlIGFsbA== please."`) — the anchored
 * regex above would miss such payloads because the literal as a whole is
 * not base64-shaped.
 */
const BASE64_CANDIDATE_EMBEDDED = /[A-Za-z0-9+/_-]{12,}={0,2}/g;

/**
 * Strict SRI shape patterns. A legitimate SRI digest has an EXACT byte
 * count for each algorithm, which fixes the base64 length to one of:
 *   sha256: 32 bytes → 43 base64 alpha + 1 `=` padding   (44 chars body)
 *   sha384: 48 bytes → 64 base64 alpha + 0 padding       (64 chars body)
 *   sha512: 64 bytes → 86 base64 alpha + 2 `=` padding   (88 chars body)
 * SRI uses the standard base64 alphabet (NOT base64url), so `-` and `_`
 * are not allowed inside the digest body.
 *
 * The previous loose check (`/^sha(256|384|512)-/`) would exempt ANY
 * string with one of those prefixes — letting an attacker bypass detection
 * by writing `sha256-<arbitrary-injection-payload>`. The strict shape
 * check rejects every length except a legitimate digest's, killing the
 * trivial bypass. A determined attacker could still craft an attack
 * payload at the exact legitimate shape (e.g. a 32-byte ASCII payload
 * after `sha256-`); that residual surface relies on `looksLikeText` /
 * `findInjectionKeyword` for the rule's remaining acceptance paths.
 */
const SRI_PATTERNS = [
  /^sha256-[A-Za-z0-9+/]{43}=$/,
  /^sha384-[A-Za-z0-9+/]{64}$/,
  /^sha512-[A-Za-z0-9+/]{86}==$/,
];

function isLegitSRI(s) {
  for (const re of SRI_PATTERNS) {
    if (re.test(s)) return true;
  }
  return false;
}

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
 * - the candidate shape matches (≥12 base64 alpha chars + optional padding)
 * - it is NOT a legitimate-shape SRI digest (those are exempt to avoid
 *   re-flagging every npm package-lock SRI hash)
 * - it survives a round-trip re-encoding (eliminates non-base64
 *   high-density strings that `Buffer.from` would lenient-decode)
 * - either the decoded text matches a known injection keyword (high-signal,
 *   accept short payloads like 10-byte "ignore all") OR the bytes look
 *   like printable text (low-signal fallback for arbitrary base64 prose).
 * Otherwise returns null.
 */
function tryDecodeBase64AsText(s) {
  if (!BASE64_CANDIDATE.test(s)) return null;
  if (isLegitSRI(s)) return null;

  // Normalize base64url to standard base64
  const normalized = s.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);

  let buf;
  /* v8 ignore next 4 -- Buffer.from('base64') is permissive and never throws on
     ASCII input; the catch is a defensive fail-closed guard for hypothetical
     runtime API changes. Not exercised by tests. */
  try {
    buf = Buffer.from(padded, "base64");
  } catch {
    return null;
  }

  // Round-trip check: Buffer.from is lenient and will swallow invalid chars,
  // so we re-encode and compare to ensure the input was actually valid base64.
  const reencoded = buf.toString("base64");
  if (reencoded.replace(/=+$/, "") !== padded.replace(/=+$/, "")) return null;

  const text = buf.toString("utf8");

  // Two acceptance paths:
  //   1. The decoded text matches a known prompt-injection keyword — return
  //      it so the rule can emit a HIGH-severity `base64Injection` finding,
  //      even when the buffer is too small for `looksLikeText`'s heuristic
  //      to be statistically reliable.
  //   2. Otherwise the bytes must look like printable text (≥90% printable
  //      ASCII, ≥8 bytes total). This emits a MEDIUM `base64Text` finding
  //      while keeping the false-positive rate low on identifiers that
  //      happen to fit the base64 shape.
  if (findInjectionKeyword(text)) return text;
  if (!looksLikeText(buf)) return null;
  return text;
}

/**
 * Iterate over base64-shaped subtokens of `s` for the rule's decode loop.
 *
 * The non-anchored regex matches the LONGEST contiguous run of base64
 * alphabet characters at each position. That, alone, leaves a bypass:
 * an attacker can prepend plain letters directly before a payload
 * (e.g. `"prefixaWdub3JlIGFsbA=="`) so the merged regex match decodes
 * to misaligned garbage and the inner payload is never evaluated.
 *
 * To close that, for every regex match we ALSO yield every alphabet
 * suffix whose length is at least the anchored detector's `{12,}`
 * threshold, excluding lengths whose mod-4 residue is 1 (no valid
 * base64 alphabet sequence has that shape regardless of padding).
 * This catches both padded payloads (mod 4 = 0 with trailing `=` /
 * `==`) and unpadded payloads (mod 4 ∈ {0, 2, 3}, used by base64url
 * by convention). Each suffix is independently re-validated by
 * `tryDecodeBase64AsText`'s anchored regex + round-trip guard, so
 * over-yielding a misaligned shape is rejected cheaply.
 *
 * The trailing-padding length is computed ONCE per token using
 * arithmetic on `endsWith()` instead of `/=+$/` inside the loop —
 * the CodeQL polynomial-regex check flagged the latter as O(L²) per
 * candidate when L is library-controllable. With the lookup hoisted
 * out, the per-token cost stays `O(L)` regex work plus `O(L)` yields,
 * each consumed in `O(L)` by the downstream validator.
 */
function* extractBase64Candidates(s) {
  for (const m of s.matchAll(BASE64_CANDIDATE_EMBEDDED)) {
    const token = m[0];
    yield token;
    let padLen = 0;
    if (token.endsWith("==")) padLen = 2;
    else if (token.endsWith("=")) padLen = 1;
    const alphaLen = token.length - padLen;
    for (let suffixAlphaLen = alphaLen - 1; suffixAlphaLen >= 12; suffixAlphaLen--) {
      if (suffixAlphaLen % 4 === 1) continue;
      yield token.slice(alphaLen - suffixAlphaLen);
    }
  }
}

function findInjectionKeyword(text) {
  for (const re of INJECTION_KEYWORDS) {
    if (re.test(text)) return re.source;
  }
  return null;
}

function previewOf(text, max = 60) {
  const truncated = text.length > max ? text.slice(0, max) + "…" : text;
  return JSON.stringify(truncated);
}

function codepointHex(ch) {
  return ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
}

module.exports = {
  INVISIBLE_UNICODE,
  tryDecodeBase64AsText,
  extractBase64Candidates,
  looksLikeText,
  findInjectionKeyword,
  previewOf,
  codepointHex,
};
