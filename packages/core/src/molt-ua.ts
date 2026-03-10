/**
 * MoltUA — MoltProtocol User Agent compliance specification.
 *
 * A MoltUA is any software that operates as a MoltProtocol agent endpoint.
 * The name follows SIP convention: SIP has User Agents (RFC 3261 §6),
 * MoltProtocol has MoltUAs.
 *
 * The MoltSIM is the credential (like a SIM card). The MoltUA is the
 * software that uses it (like the phone/baseband).
 *
 * ┌─────────────┐     ┌───────────┐     ┌─────────────┐
 * │   MoltSIM   │────▶│  MoltUA   │◀────│  Carrier    │
 * │ (credential)│     │ (runtime) │     │ (delivery)  │
 * └─────────────┘     └───────────┘     └─────────────┘
 *       has                is signed by
 *   private_key        X-Molt-Identity
 *   carrier_public_key
 *
 * ## Compliance Levels
 *
 * ### Level 1 — Baseline (MUST)
 * - Verify `X-Molt-Identity` carrier signature on every inbound delivery
 * - Reject requests without a valid carrier signature
 * - Reject requests with expired timestamps (±300s)
 * - Use the `carrier_public_key` from MoltSIM as trust anchor
 *
 * ### Level 2 — Standard (SHOULD)
 * - Verify caller's Ed25519 signature (`X-Molt-Signature`) when present
 * - Sign outbound requests with own Ed25519 key (from MoltSIM)
 * - Implement presence heartbeats
 * - Poll inbox periodically for queued tasks
 *
 * ### Level 3 — Full (MAY)
 * - Support direct connection upgrade handshake
 * - Verify upgrade tokens against carrier
 * - Implement SSE streaming for multi-turn conversations
 * - Support push notifications
 *
 * ## Security Properties
 *
 * With Level 1 compliance alone, a MoltUA achieves:
 * - **Delivery authenticity**: Only carrier-signed requests are accepted
 * - **Replay protection**: Timestamp window rejects old/replayed signatures
 * - **Leaked endpoint protection**: Knowing the URL is useless without
 *   the carrier's private key to forge X-Molt-Identity
 *
 * This is defense-in-depth:
 * - Layer 1 (MoltUA verification): Endpoint only accepts carrier-signed
 *   traffic. Free, baseline, everyone. Like Cloudflare Authenticated
 *   Origin Pulls.
 * - Layer 2 (carrier_only relay): Endpoint URL never shared. Paid,
 *   optional, for agents needing topology hiding and audit trail.
 */

import {
  type VerifyCarrierIdentityParams,
  type VerifyCarrierIdentityResult,
  verifyCarrierIdentity,
  CARRIER_IDENTITY_HEADERS,
} from './carrier-identity';

// ── MoltUA Configuration ─────────────────────────────────

/**
 * Configuration for a MoltUA instance, sourced from the MoltSIM.
 */
export interface MoltUAConfig {
  /** This agent's MoltNumber. */
  moltNumber: string;
  /** Ed25519 private key (base64url PKCS#8 DER) for signing outbound requests. */
  privateKey: string;
  /** Ed25519 public key (base64url SPKI DER) for this agent. */
  publicKey: string;
  /** Carrier's Ed25519 public key (base64url SPKI DER) for verifying deliveries. */
  carrierPublicKey: string;
  /** Expected carrier domain. */
  carrierDomain: string;
  /** Timestamp tolerance in seconds. Default: 300. */
  timestampWindowSeconds?: number;
}

// ── Inbound Request Verification ─────────────────────────

/**
 * Headers expected on a carrier-delivered request.
 */
export interface InboundDeliveryHeaders {
  /** X-Molt-Identity — carrier signature. */
  'x-molt-identity'?: string | null;
  /** X-Molt-Identity-Carrier — carrier domain. */
  'x-molt-identity-carrier'?: string | null;
  /** X-Molt-Identity-Attest — attestation level. */
  'x-molt-identity-attest'?: string | null;
  /** X-Molt-Identity-Timestamp — timestamp. */
  'x-molt-identity-timestamp'?: string | null;
  /** X-Molt-Target — target agent ID (carrier-specific). */
  'x-molt-target'?: string | null;
  /** Generic header getter. */
  [key: string]: string | null | undefined;
}

/**
 * Result of MoltUA inbound verification.
 */
export interface MoltUAVerifyResult {
  /** Whether the delivery is trusted. */
  trusted: boolean;
  /** Whether carrier identity was verified (Level 1). */
  carrierVerified: boolean;
  /** Attestation level from the carrier, if verified. */
  attestation?: string;
  /** Reason for rejection. */
  reason?: string;
}

/**
 * Verify an inbound delivery (MoltUA Level 1 compliance).
 *
 * A compliant MoltUA MUST call this on every inbound request and reject
 * the request if `trusted` is false.
 *
 * If `strictMode` is true (recommended for production), requests without
 * carrier identity headers are rejected. If false, requests without
 * headers are accepted (useful during migration / development).
 */
export function verifyInboundDelivery(
  config: MoltUAConfig,
  headers: InboundDeliveryHeaders,
  body: string,
  opts: { strictMode?: boolean; origNumber?: string } = {},
): MoltUAVerifyResult {
  const strictMode = opts.strictMode ?? true;

  const signature = headers['x-molt-identity'];
  const carrier = headers['x-molt-identity-carrier'];
  const attestation = headers['x-molt-identity-attest'];
  const timestamp = headers['x-molt-identity-timestamp'];

  // No carrier identity headers present
  if (!signature || !carrier || !attestation || !timestamp) {
    if (strictMode) {
      return { trusted: false, carrierVerified: false, reason: 'Missing carrier identity headers (X-Molt-Identity)' };
    }
    // Non-strict: accept without verification (development mode)
    return { trusted: true, carrierVerified: false };
  }

  // Verify carrier domain matches expectation
  if (carrier !== config.carrierDomain) {
    return {
      trusted: false,
      carrierVerified: false,
      reason: `Carrier domain mismatch: expected ${config.carrierDomain}, got ${carrier}`,
    };
  }

  // Verify carrier signature
  const result: VerifyCarrierIdentityResult = verifyCarrierIdentity({
    signature,
    carrierDomain: carrier,
    attestation: attestation as 'A' | 'B' | 'C',
    timestamp,
    origNumber: opts.origNumber ?? 'anonymous',
    destNumber: config.moltNumber,
    body,
    carrierPublicKey: config.carrierPublicKey,
    windowSeconds: config.timestampWindowSeconds,
  });

  if (!result.valid) {
    return { trusted: false, carrierVerified: false, reason: result.reason };
  }

  return { trusted: true, carrierVerified: true, attestation };
}

/**
 * Extract carrier identity headers from a generic headers object.
 * Normalizes header names to lowercase.
 */
export function extractCarrierHeaders(
  getHeader: (name: string) => string | null,
): InboundDeliveryHeaders {
  return {
    'x-molt-identity': getHeader(CARRIER_IDENTITY_HEADERS.SIGNATURE),
    'x-molt-identity-carrier': getHeader(CARRIER_IDENTITY_HEADERS.CARRIER),
    'x-molt-identity-attest': getHeader(CARRIER_IDENTITY_HEADERS.ATTESTATION),
    'x-molt-identity-timestamp': getHeader(CARRIER_IDENTITY_HEADERS.TIMESTAMP),
    'x-molt-target': getHeader('X-Molt-Target'),
  };
}
