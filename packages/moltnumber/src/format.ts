/**
 * MoltNumber format — self-certifying agent identifiers.
 *
 * Format:  NATION-AAAA-BBBB-CCCC-DDDD
 *  - NATION = 4 uppercase letters (A-Z)
 *  - AAAA-BBBB-CCCC-DDDD = 16-char Crockford Base32 subscriber
 *    derived from SHA-256(nationCode + ":" + publicKey), truncated to 80 bits
 *
 * Self-certifying property:
 *  - The subscriber portion IS a hash of the public key
 *  - Anyone can verify: hash the public key, compare to the number
 *  - No registry, no CA, no carrier needed for identity verification
 *  - Like Bitcoin addresses or Tor .onion domains
 *
 * No plus sign. Dashes only. Stored uppercase. No check digit (the
 * self-certifying hash IS the integrity check).
 */

import crypto from 'crypto';

export const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

// ── Derivation ──────────────────────────────────────────

/**
 * Derive the 16-char Crockford Base32 subscriber from a nation code and public key.
 *
 * The nation code is included in the hash input so that the same key
 * produces different subscribers in different nations. This cryptographically
 * binds the nation to the number — verification confirms both key AND nation.
 *
 * Takes the first 80 bits (10 bytes) of SHA-256(nation + ":" + publicKey)
 * and encodes as 16 Crockford Base32 characters (5 bits per char × 16 = 80 bits).
 *
 * @param nationCode - 4 uppercase letters (A-Z)
 * @param publicKey  - Ed25519 public key, base64url-encoded (SPKI DER)
 */
export function deriveSubscriber(nationCode: string, publicKey: string): string {
  const hash = crypto.createHash('sha256')
    .update(`${nationCode}:${publicKey}`, 'utf8')
    .digest();
  // Take first 10 bytes = 80 bits → 16 Crockford Base32 chars
  return encodeCrockford(hash.subarray(0, 10));
}

/**
 * Encode a buffer as Crockford Base32 (5 bits per character).
 */
function encodeCrockford(buf: Buffer): string {
  let bits = '';
  for (const byte of buf) {
    bits += byte.toString(2).padStart(8, '0');
  }
  let result = '';
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    const val = parseInt(bits.slice(i, i + 5), 2);
    result += CROCKFORD_ALPHABET[val];
  }
  return result;
}

// ── Generation ──────────────────────────────────────────

/**
 * Generate a self-certifying MoltNumber from a nation code and public key.
 *
 * The subscriber portion is deterministically derived from SHA-256 of the
 * public key. The same key always produces the same number.
 *
 * @param nationCode  - 4 uppercase letters (A-Z)
 * @param publicKey   - Ed25519 public key, base64url-encoded (SPKI DER)
 */
export function generateMoltNumber(nationCode: string, publicKey: string): string {
  if (!/^[A-Z]{4}$/.test(nationCode)) {
    throw new Error('Nation code must be exactly 4 uppercase letters (A-Z)');
  }
  if (!publicKey) {
    throw new Error('Public key is required for self-certifying MoltNumber generation');
  }
  const subscriber = deriveSubscriber(nationCode, publicKey);
  const seg1 = subscriber.slice(0, 4);
  const seg2 = subscriber.slice(4, 8);
  const seg3 = subscriber.slice(8, 12);
  const seg4 = subscriber.slice(12, 16);
  return `${nationCode}-${seg1}-${seg2}-${seg3}-${seg4}`;
}

// ── Verification (self-certifying) ──────────────────────

/**
 * Verify that a MoltNumber was derived from the given public key.
 *
 * This is the core self-certifying property: hash the nation + public key,
 * compare to the subscriber portion. No registry needed.
 *
 * The nation code is extracted from the number itself and included in the
 * hash, so this verifies BOTH key ownership AND nation binding.
 *
 * @returns true if the number's subscriber matches SHA-256(nation + ":" + publicKey)
 */
export function verifyMoltNumber(number: string, publicKey: string): boolean {
  const parsed = parseMoltNumber(number);
  if (!parsed) return false;
  const expected = deriveSubscriber(parsed.nation, publicKey);
  return parsed.subscriber === expected;
}

// ── Validation ──────────────────────────────────────────

/** Full regex for a valid MoltNumber (no plus sign, no check digit). */
const MOLTNUMBER_PATTERN =
  /^([A-Z]{4})-([0-9A-HJKMNP-TV-Z]{4})-([0-9A-HJKMNP-TV-Z]{4})-([0-9A-HJKMNP-TV-Z]{4})-([0-9A-HJKMNP-TV-Z]{4})$/;

/**
 * Validate the format of a MoltNumber (structure only).
 *
 * For full identity verification, use verifyMoltNumber(number, publicKey).
 */
export function validateMoltNumber(number: string): boolean {
  return MOLTNUMBER_PATTERN.test(number);
}

// ── Normalization ───────────────────────────────────────

export function normalizeMoltNumber(input: string): string {
  return input.trim().toUpperCase().replace(/\s+/g, '');
}

// ── Parsing ─────────────────────────────────────────────

export interface MoltNumberParts {
  nation: string;
  /** 16-char Crockford Base32 subscriber (hash of public key). */
  subscriber: string;
  /** The full formatted MoltNumber string. */
  formatted: string;
}

export function parseMoltNumber(number: string): MoltNumberParts | null {
  const m = number.match(MOLTNUMBER_PATTERN);
  if (!m) return null;
  return {
    nation: m[1],
    subscriber: m[2] + m[3] + m[4] + m[5],
    formatted: m[0],
  };
}
