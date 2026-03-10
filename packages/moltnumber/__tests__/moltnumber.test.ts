import {
  generateMoltNumber,
  verifyMoltNumber,
  validateMoltNumber,
  normalizeMoltNumber,
  parseMoltNumber,
  deriveSubscriber,
  CROCKFORD_ALPHABET,
} from '../src/format';

import { generateKeyPair } from '@moltprotocol/core';

import {
  generateDomainClaimToken,
  buildWellKnownUrl,
  parseWellKnownFile,
  validateDomainClaim,
} from '../src/domain-binding';

// ── Self-Certifying MoltNumber Format ────────────────────

describe('MoltNumber Format', () => {
  it('generates valid numbers without + prefix', () => {
    const kp = generateKeyPair();
    const num = generateMoltNumber('MOLT', kp.publicKey);
    expect(num).toMatch(/^MOLT-/);
    expect(num).not.toContain('+');
    expect(validateMoltNumber(num)).toBe(true);
  });

  it('is URL-safe (encodeURIComponent is identity)', () => {
    for (let i = 0; i < 10; i++) {
      const kp = generateKeyPair();
      const num = generateMoltNumber('AION', kp.publicKey);
      expect(encodeURIComponent(num)).toBe(num);
    }
  });

  it('uses Crockford Base32 for subscriber (no I, L, O)', () => {
    for (let i = 0; i < 20; i++) {
      const kp = generateKeyPair();
      const num = generateMoltNumber('MOLT', kp.publicKey);
      const parts = parseMoltNumber(num)!;
      expect(parts.subscriber).not.toMatch(/[ILO]/);
    }
  });

  it('stores uppercase only', () => {
    const kp = generateKeyPair();
    const num = generateMoltNumber('CLAW', kp.publicKey);
    expect(num).toBe(num.toUpperCase());
  });

  it('format is NATION-AAAA-BBBB-CCCC-DDDD (4 groups of 4)', () => {
    const kp = generateKeyPair();
    const num = generateMoltNumber('MOLT', kp.publicKey);
    expect(num).toMatch(/^[A-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
  });

  it('subscriber is 16 characters (80 bits)', () => {
    const kp = generateKeyPair();
    const num = generateMoltNumber('MOLT', kp.publicKey);
    const parts = parseMoltNumber(num)!;
    expect(parts.subscriber).toHaveLength(16);
  });

  it('generates unique numbers for unique keys', () => {
    const nums = new Set<string>();
    for (let i = 0; i < 100; i++) {
      const kp = generateKeyPair();
      nums.add(generateMoltNumber('MOLT', kp.publicKey));
    }
    expect(nums.size).toBe(100);
  });

  it('same key always produces same number (deterministic)', () => {
    const kp = generateKeyPair();
    const num1 = generateMoltNumber('MOLT', kp.publicKey);
    const num2 = generateMoltNumber('MOLT', kp.publicKey);
    expect(num1).toBe(num2);
  });

  it('different nations with same key produce different subscribers', () => {
    const kp = generateKeyPair();
    const num1 = generateMoltNumber('MOLT', kp.publicKey);
    const num2 = generateMoltNumber('AION', kp.publicKey);
    expect(num1).not.toBe(num2);
    // Nation is included in hash, so subscribers are DIFFERENT
    const parts1 = parseMoltNumber(num1)!;
    const parts2 = parseMoltNumber(num2)!;
    expect(parts1.subscriber).not.toBe(parts2.subscriber);
  });

  it('parseMoltNumber returns correct parts', () => {
    const kp = generateKeyPair();
    const num = generateMoltNumber('AION', kp.publicKey);
    const parts = parseMoltNumber(num);
    expect(parts).not.toBeNull();
    expect(parts!.nation).toBe('AION');
    expect(parts!.subscriber).toHaveLength(16);
    expect(parts!.formatted).toBe(num);
  });

  it('normalizeMoltNumber trims and uppercases', () => {
    expect(normalizeMoltNumber('  molt-aaaa-bbbb-cccc-dddd  ')).toBe('MOLT-AAAA-BBBB-CCCC-DDDD');
  });

  it('rejects + prefixed numbers', () => {
    const kp = generateKeyPair();
    const num = generateMoltNumber('MOLT', kp.publicKey);
    expect(validateMoltNumber('+' + num)).toBe(false);
  });

  it('rejects invalid formats', () => {
    // Old format with check digit (13 subscriber chars + 1 check)
    expect(validateMoltNumber('MOLT-1234-5678-9012-3')).toBe(false);
    expect(validateMoltNumber('+MOLT-1234-5678-9012-3456')).toBe(false);
    expect(validateMoltNumber('MOL-1234-5678-9012-3456')).toBe(false);
  });

  it('throws for invalid nation code', () => {
    const kp = generateKeyPair();
    expect(() => generateMoltNumber('MOL', kp.publicKey)).toThrow();
    expect(() => generateMoltNumber('molt', kp.publicKey)).toThrow();
    expect(() => generateMoltNumber('12AB', kp.publicKey)).toThrow();
  });

  it('throws when public key is missing', () => {
    expect(() => generateMoltNumber('MOLT', '')).toThrow();
  });
});

// ── Self-Certifying Verification ────────────────────────

describe('Self-Certifying Verification', () => {
  it('verifyMoltNumber confirms matching key', () => {
    const kp = generateKeyPair();
    const num = generateMoltNumber('MOLT', kp.publicKey);
    expect(verifyMoltNumber(num, kp.publicKey)).toBe(true);
  });

  it('verifyMoltNumber rejects wrong key', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const num = generateMoltNumber('MOLT', kp1.publicKey);
    expect(verifyMoltNumber(num, kp2.publicKey)).toBe(false);
  });

  it('verifyMoltNumber rejects tampered number', () => {
    const kp = generateKeyPair();
    const num = generateMoltNumber('MOLT', kp.publicKey);
    // Flip one character in the subscriber
    const chars = num.split('');
    const idx = 5; // first subscriber char
    const cur = CROCKFORD_ALPHABET.indexOf(chars[idx]);
    chars[idx] = CROCKFORD_ALPHABET[(cur + 1) % CROCKFORD_ALPHABET.length];
    expect(verifyMoltNumber(chars.join(''), kp.publicKey)).toBe(false);
  });

  it('deriveSubscriber is deterministic', () => {
    const kp = generateKeyPair();
    expect(deriveSubscriber('MOLT', kp.publicKey)).toBe(deriveSubscriber('MOLT', kp.publicKey));
  });

  it('deriveSubscriber produces only Crockford Base32 chars', () => {
    for (let i = 0; i < 20; i++) {
      const kp = generateKeyPair();
      const sub = deriveSubscriber('MOLT', kp.publicKey);
      for (const ch of sub) {
        expect(CROCKFORD_ALPHABET).toContain(ch);
      }
    }
  });

  it('deriveSubscriber includes nation in hash (different nation = different subscriber)', () => {
    const kp = generateKeyPair();
    const sub1 = deriveSubscriber('MOLT', kp.publicKey);
    const sub2 = deriveSubscriber('AION', kp.publicKey);
    expect(sub1).not.toBe(sub2);
  });
});

// ── Domain Binding ──────────────────────────────────────

describe('Domain Binding', () => {
  it('generates 64-char hex token', () => {
    const token = generateDomainClaimToken();
    expect(token).toHaveLength(64);
    expect(token).toMatch(/^[0-9a-f]{64}$/);
  });

  it('builds well-known URL from bare domain', () => {
    expect(buildWellKnownUrl('example.com')).toBe('https://example.com/.well-known/moltnumber.txt');
  });

  it('strips protocol and trailing slash', () => {
    expect(buildWellKnownUrl('https://example.com/')).toBe('https://example.com/.well-known/moltnumber.txt');
    expect(buildWellKnownUrl('http://example.com///')).toBe('https://example.com/.well-known/moltnumber.txt');
  });

  it('parses well-known file contents', () => {
    const body = 'moltnumber: MOLT-1234-5678-9012-A\ntoken: abc123';
    const parsed = parseWellKnownFile(body);
    expect(parsed.moltnumber).toBe('MOLT-1234-5678-9012-A');
    expect(parsed.token).toBe('abc123');
  });

  it('handles blank lines and whitespace', () => {
    const body = '\n  moltnumber:  AION-AAAA-BBBB-CCCC-0  \n\n  token:  mytoken  \n';
    const parsed = parseWellKnownFile(body);
    expect(parsed.moltnumber).toBe('AION-AAAA-BBBB-CCCC-0');
    expect(parsed.token).toBe('mytoken');
  });

  it('returns null for missing fields', () => {
    expect(parseWellKnownFile('nothing here')).toEqual({ moltnumber: null, token: null });
    expect(parseWellKnownFile('moltnumber: X')).toEqual({ moltnumber: 'X', token: null });
  });

  it('validates matching claim', () => {
    const mn = 'MOLT-1234-5678-9012-A';
    const token = 'abc123';
    const body = `moltnumber: ${mn}\ntoken: ${token}`;
    const result = validateDomainClaim(body, mn, token);
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it('rejects MoltNumber mismatch', () => {
    const body = 'moltnumber: MOLT-AAAA-BBBB-CCCC-0\ntoken: tok';
    const result = validateDomainClaim(body, 'MOLT-XXXX-YYYY-ZZZZ-0', 'tok');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('MoltNumber mismatch');
  });

  it('rejects token mismatch', () => {
    const mn = 'MOLT-1234-5678-9012-A';
    const body = `moltnumber: ${mn}\ntoken: wrong`;
    const result = validateDomainClaim(body, mn, 'correct');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Token mismatch');
  });

  it('rejects missing moltnumber field', () => {
    const result = validateDomainClaim('token: abc', 'MOLT-1234-5678-9012-A', 'abc');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Missing moltnumber');
  });

  it('rejects missing token field', () => {
    const result = validateDomainClaim('moltnumber: MOLT-1234-5678-9012-A', 'MOLT-1234-5678-9012-A', 'abc');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Missing token');
  });
});

// ── Appendix B — Spec Test Vectors ───────────────────────

describe('SPEC Appendix B — Test Vectors', () => {
  // Vector 1: MOLT nation, key A
  const KEY_A = 'MCowBQYDK2VwAyEA36lOovr35LhKwcQr9YSXHdMJP6hQkgIk1KjHaMm2XaU';
  // Vector 3: MOLT nation, key B
  const KEY_B = 'MCowBQYDK2VwAyEA5sL5FhLKBYNfSOg0mZ0TCp1etmM0xqUqYOKmz-zVZBo';

  it('Vector 1 — MOLT nation, key A', () => {
    expect(deriveSubscriber('MOLT', KEY_A)).toBe('YQZZ23NDQ5KW17VA');
    expect(generateMoltNumber('MOLT', KEY_A)).toBe('MOLT-YQZZ-23ND-Q5KW-17VA');
    expect(verifyMoltNumber('MOLT-YQZZ-23ND-Q5KW-17VA', KEY_A)).toBe(true);
  });

  it('Vector 2 — same key A, different nation (cross-nation binding)', () => {
    expect(deriveSubscriber('SOLR', KEY_A)).toBe('47QDGKWVNPWQ2YW0');
    expect(generateMoltNumber('SOLR', KEY_A)).toBe('SOLR-47QD-GKWV-NPWQ-2YW0');
    expect(verifyMoltNumber('SOLR-47QD-GKWV-NPWQ-2YW0', KEY_A)).toBe(true);
  });

  it('Vector 3 — different key B, MOLT nation', () => {
    expect(deriveSubscriber('MOLT', KEY_B)).toBe('ZKK9SH34ZXRH6CN3');
    expect(generateMoltNumber('MOLT', KEY_B)).toBe('MOLT-ZKK9-SH34-ZXRH-6CN3');
    expect(verifyMoltNumber('MOLT-ZKK9-SH34-ZXRH-6CN3', KEY_B)).toBe(true);
  });

  it('cross-nation binding: same key → different numbers', () => {
    const moltNumber = generateMoltNumber('MOLT', KEY_A);
    const solrNumber = generateMoltNumber('SOLR', KEY_A);
    expect(moltNumber).not.toBe(solrNumber);
  });

  it('cross-key verification fails', () => {
    // Key A's number verified against key B → false
    expect(verifyMoltNumber('MOLT-YQZZ-23ND-Q5KW-17VA', KEY_B)).toBe(false);
    // Key B's number verified against key A → false
    expect(verifyMoltNumber('MOLT-ZKK9-SH34-ZXRH-6CN3', KEY_A)).toBe(false);
  });
});
