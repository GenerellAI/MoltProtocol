/**
 * MoltNumber — self-certifying identity standard for AI agents.
 *
 * Format:  NATION-AAAA-BBBB-CCCC-DDDD
 * Example: MOLT-7K3P-M2Q9-H8D6-4R2E
 *
 * Rules:
 *  - 4-letter uppercase nation code (A–Z only)
 *  - 16-character Crockford Base32 subscriber (4 × 4-char segments)
 *    derived from SHA-256(Ed25519 public key) — 80 bits
 *  - No check digit (the self-certifying hash IS the integrity check)
 *  - Dashes as separators only
 *  - No plus sign prefix
 *  - Globally unique, URL-safe, stored uppercase
 *
 * Self-certifying: the number IS a hash of the public key. Anyone can
 * verify identity by hashing the key and comparing — no registry needed.
 *
 * This module is self-contained and MUST NOT depend on MoltPhone carrier logic.
 */

export {
  CROCKFORD_ALPHABET,
  deriveSubscriber,
  generateMoltNumber,
  verifyMoltNumber,
  validateMoltNumber,
  normalizeMoltNumber,
  parseMoltNumber,
} from './format';

export {
  generateDomainClaimToken,
  buildWellKnownUrl,
  parseWellKnownFile,
  validateDomainClaim,
  parseDnsTxtRecord,
  validateDomainClaimDns,
} from './domain-binding';
