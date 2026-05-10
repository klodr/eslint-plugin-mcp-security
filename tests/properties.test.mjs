/**
 * Copyright 2026 klodr
 * SPDX-License-Identifier: Apache-2.0
 */

import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  codepointHex,
  findInjectionKeyword,
  looksLikeText,
  previewOf,
  tryDecodeBase64AsText,
} from '../src/rules/no-encoded-prompt-injection.helpers.js';

describe('helper invariants (property-based)', () => {
  it('tryDecodeBase64AsText returns null or a UTF-8 string for any input', () => {
    fc.assert(
      fc.property(fc.string(), (s) => {
        const result = tryDecodeBase64AsText(s);
        expect(result === null || typeof result === 'string').toBe(true);
      }),
      { numRuns: 200 },
    );
  });

  it('round-trips: any printable text re-encoded as base64 decodes back', () => {
    fc.assert(
      // BASE64_CANDIDATE requires >=24 chars in the encoded form, so the
      // source text must be >=18 chars (each 3 bytes → 4 base64 chars).
      fc.property(
        fc.string({
          minLength: 18,
          unit: fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789 '),
        }),
        (text) => {
          const b64 = Buffer.from(text, 'utf8').toString('base64');
          expect(tryDecodeBase64AsText(b64)).toBe(text);
        },
      ),
      { numRuns: 200 },
    );
  });

  it('looksLikeText is total: returns boolean for any Buffer', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 256 }), (bytes) => {
        const result = looksLikeText(Buffer.from(bytes));
        expect(typeof result).toBe('boolean');
      }),
      { numRuns: 200 },
    );
  });

  it('findInjectionKeyword returns null or a regex source string', () => {
    fc.assert(
      fc.property(fc.string(), (s) => {
        const result = findInjectionKeyword(s);
        expect(result === null || typeof result === 'string').toBe(true);
      }),
      { numRuns: 200 },
    );
  });

  it('previewOf returns a JSON-stringified string capped at max chars + ellipsis', () => {
    fc.assert(
      fc.property(fc.string(), fc.integer({ min: 1, max: 200 }), (text, max) => {
        const result = previewOf(text, max);
        expect(typeof result).toBe('string');
        expect(result.startsWith('"')).toBe(true);
        expect(result.endsWith('"')).toBe(true);
        const parsed = JSON.parse(result);
        expect(parsed.length).toBeLessThanOrEqual(max + 1);
        if (text.length > max) expect(parsed.endsWith('…')).toBe(true);
        else expect(parsed).toBe(text);
      }),
      { numRuns: 100 },
    );
    expect(previewOf('short')).toBe('"short"');
    expect(previewOf('x'.repeat(100), 10)).toBe('"xxxxxxxxxx…"');
  });

  it('codepointHex returns a 4+-digit uppercase hex for any codepoint', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 0x10ffff }), (cp) => {
        const ch = String.fromCodePoint(cp);
        const result = codepointHex(ch);
        expect(result).toMatch(/^[0-9A-F]{4,6}$/);
        expect(Number.parseInt(result, 16)).toBe(cp);
      }),
      { numRuns: 100 },
    );
    expect(codepointHex('A')).toBe('0041');
    expect(codepointHex('​')).toBe('200B');
  });
});
