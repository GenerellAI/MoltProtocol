/**
 * MoltProtocol — Carrier Identity (STIR/SHAKEN-inspired).
 *
 * Defines the standard for carrier-signed deliveries. Based on:
 *
 * - **STIR (RFC 8224)** — Authenticated Identity Management in SIP.
 *   The originating carrier signs calls; the terminating carrier verifies.
 *   We adapt this: the relaying carrier signs deliveries; the receiving
 *   MoltUA verifies.
 *
 * - **SHAKEN** — Signature-based Handling of Asserted information using
 *   toKENs. The token format and trust model for STIR. We use a simpler
 *   Ed25519-based approach instead of X.509 certificates.
 *
 * - **PASSporT (RFC 8225)** — Personal Assertion Token. STIR's JWT-like
 *   token containing origin, destination, and attestation. Our
 *   `CarrierIdentityToken` is a simplified PASSporT.
 *
 * Trust model: Each carrier has an Ed25519 keypair. The public key is
 * distributed in the MoltSIM. Deliveries include an `X-Molt-Identity`
 * header containing the carrier's signature over the delivery metadata.
 * MoltUA implementations verify this to reject unauthorized direct calls.
 *
 * Like Cloudflare Tunnel's Authenticated Origin Pulls — knowing the
 * endpoint URL is useless if you can't produce a valid carrier signature.
 *
 * This module defines the OPEN STANDARD. Any MoltProtocol carrier MUST
 * implement this format. Carrier-specific key management lives in the
 * carrier codebase.
 */

import crypto from 'crypto';

// ── Attestation levels (from STIR/SHAKEN) ────────────────

/**
 * Attestation levels, inspired by STIR/SHAKEN attestation:
 *
 * - `A` (Full): Carrier has fully verified the caller's identity.
 *   The caller is a registered agent on this carrier with a valid Ed25519
 *   keypair. Equivalent to SHAKEN "Full Attestation."
 *
 * - `B` (Partial): Carrier knows the caller but hasn't verified
 *   the specific request signature (e.g., public-policy agent,
 *   no Ed25519 required). Equivalent to SHAKEN "Partial Attestation."
 *
 * - `C` (Gateway): Carrier is relaying from an external source
 *   (cross-carrier, external A2A). Cannot vouch for caller identity.
 *   Equivalent to SHAKEN "Gateway Attestation."
 */
export type AttestationLevel = 'A' | 'B' | 'C';

// ── Carrier Identity Token ───────────────────────────────

/**
 * The carrier identity assertion — a simplified PASSporT (RFC 8225).
 *
 * Carried in the `X-Molt-Identity` header as a base64url-encoded signature
 * over the canonical delivery string.
 */
export interface CarrierIdentityParams {
  /** Carrier domain (e.g., "moltphone.ai"). */
  carrierDomain: string;
  /** Caller MoltNumber, or "anonymous" if unknown. */
  origNumber: string;
  /** Target MoltNumber. */
  destNumber: string;
  /** Attestation level. */
  attestation: AttestationLevel;
  /** Unix timestamp (seconds). */
  timestamp: string;
  /** SHA-256 hex hash of the request body. */
  bodyHash: string;
}

/**
 * Build the canonical string for carrier identity signing.
 *
 * Format (fields joined by newlines):
 *   CARRIER_DOMAIN
 *   ATTESTATION
 *   ORIG_MOLTNUMBER
 *   DEST_MOLTNUMBER
 *   TIMESTAMP
 *   BODY_SHA256_HEX
 *
 * This is analogous to PASSporT's payload but signed directly with
 * Ed25519 instead of being wrapped in a JWT.
 */
export function buildCarrierIdentityString(params: CarrierIdentityParams): string {
  return [
    params.carrierDomain,
    params.attestation,
    params.origNumber,
    params.destNumber,
    params.timestamp,
    params.bodyHash,
  ].join('\n');
}

// ── Signing ──────────────────────────────────────────────

export interface CarrierSignResult {
  /** Base64url-encoded Ed25519 signature. */
  signature: string;
  /** Unix timestamp used in the canonical string. */
  timestamp: string;
  /** Attestation level included in the signed data. */
  attestation: AttestationLevel;
}

/**
 * Sign a delivery with the carrier's Ed25519 private key.
 *
 * The resulting signature goes in the `X-Molt-Identity` header.
 * Additional headers carry the metadata needed for verification:
 *   - `X-Molt-Identity`: base64url signature
 *   - `X-Molt-Identity-Carrier`: carrier domain
 *   - `X-Molt-Identity-Attest`: attestation level (A/B/C)
 *   - `X-Molt-Identity-Timestamp`: unix timestamp
 */
export function signCarrierDelivery(
  params: {
    carrierDomain: string;
    origNumber: string;
    destNumber: string;
    attestation: AttestationLevel;
    body: string;
    /** Base64url-encoded PKCS#8 DER carrier private key. */
    carrierPrivateKey: string;
  },
): CarrierSignResult {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const bodyHash = crypto.createHash('sha256').update(params.body, 'utf8').digest('hex');

  const canonical = buildCarrierIdentityString({
    carrierDomain: params.carrierDomain,
    attestation: params.attestation,
    origNumber: params.origNumber,
    destNumber: params.destNumber,
    timestamp,
    bodyHash,
  });

  const pkDer = Buffer.from(params.carrierPrivateKey, 'base64url');
  const privateKeyObj = crypto.createPrivateKey({ key: pkDer, format: 'der', type: 'pkcs8' });
  const sig = crypto.sign(null, Buffer.from(canonical, 'utf8'), privateKeyObj);

  return {
    signature: sig.toString('base64url'),
    timestamp,
    attestation: params.attestation,
  };
}

// ── Verification ─────────────────────────────────────────

export interface VerifyCarrierIdentityParams {
  /** Base64url signature from `X-Molt-Identity`. */
  signature: string;
  /** Carrier domain from `X-Molt-Identity-Carrier`. */
  carrierDomain: string;
  /** Attestation from `X-Molt-Identity-Attest`. */
  attestation: AttestationLevel;
  /** Timestamp from `X-Molt-Identity-Timestamp`. */
  timestamp: string;
  /** Caller MoltNumber (from request metadata or "anonymous"). */
  origNumber: string;
  /** Target MoltNumber (this agent). */
  destNumber: string;
  /** Raw request body. */
  body: string;
  /** Base64url-encoded SPKI DER carrier public key (from MoltSIM). */
  carrierPublicKey: string;
  /** Allowed clock skew in seconds. Defaults to 300 (5 min). */
  windowSeconds?: number;
}

export interface VerifyCarrierIdentityResult {
  valid: boolean;
  attestation?: AttestationLevel;
  reason?: string;
}

/**
 * Verify a carrier identity signature.
 *
 * MoltUA implementations call this on every incoming request to confirm
 * the delivery was authorized by a trusted carrier.
 *
 * Verification steps (aligned with RFC 8224 §6):
 * 1. Check timestamp is within window (replay protection)
 * 2. Reconstruct canonical string from headers + body hash
 * 3. Verify Ed25519 signature against carrier public key
 */
export function verifyCarrierIdentity(params: VerifyCarrierIdentityParams): VerifyCarrierIdentityResult {
  const window = params.windowSeconds ?? 300;
  const now = Math.floor(Date.now() / 1000);
  const ts = parseInt(params.timestamp, 10);

  if (isNaN(ts) || Math.abs(now - ts) > window) {
    return { valid: false, reason: 'Carrier identity timestamp out of window' };
  }

  const bodyHash = crypto.createHash('sha256').update(params.body, 'utf8').digest('hex');
  const canonical = buildCarrierIdentityString({
    carrierDomain: params.carrierDomain,
    attestation: params.attestation,
    origNumber: params.origNumber,
    destNumber: params.destNumber,
    timestamp: params.timestamp,
    bodyHash,
  });

  try {
    const pkDer = Buffer.from(params.carrierPublicKey, 'base64url');
    const publicKeyObj = crypto.createPublicKey({ key: pkDer, format: 'der', type: 'spki' });
    const sigBuf = Buffer.from(params.signature, 'base64url');
    const ok = crypto.verify(null, Buffer.from(canonical, 'utf8'), publicKeyObj, sigBuf);
    if (!ok) return { valid: false, reason: 'Carrier identity signature mismatch' };
  } catch {
    return { valid: false, reason: 'Invalid carrier identity signature or key' };
  }

  return { valid: true, attestation: params.attestation };
}

// ── Header constants ─────────────────────────────────────

/** Header names for carrier identity (X-Molt-Identity family). */
export const CARRIER_IDENTITY_HEADERS = {
  /** Base64url Ed25519 signature. */
  SIGNATURE: 'X-Molt-Identity',
  /** Carrier domain (e.g., "moltphone.ai"). */
  CARRIER: 'X-Molt-Identity-Carrier',
  /** Attestation level: A, B, or C. */
  ATTESTATION: 'X-Molt-Identity-Attest',
  /** Unix timestamp (seconds). */
  TIMESTAMP: 'X-Molt-Identity-Timestamp',
} as const;
