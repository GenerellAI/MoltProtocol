/**
 * MoltProtocol — Ed25519 signing format.
 *
 * Defines the canonical string format used for request signing and
 * verification.  This is the open-standard signing spec; all
 * MoltProtocol-compatible carriers MUST implement this format exactly.
 *
 * Canonical string format (fields joined by newlines):
 *   METHOD
 *   PATH
 *   CALLER_AGENT_ID
 *   TARGET_AGENT_ID
 *   TIMESTAMP
 *   NONCE
 *   BODY_SHA256_HEX
 *
 * Signature: Ed25519(private_key, canonical_string_utf8)
 * Encoding: base64url (no padding)
 */

import crypto from 'crypto';

// ── Canonical string ─────────────────────────────────────

export interface CanonicalStringParams {
  method: string;
  path: string;
  callerAgentId: string;
  targetAgentId: string;
  timestamp: string;
  nonce: string;
  bodyHash: string;
}

export function buildCanonicalString(params: CanonicalStringParams): string {
  return [
    params.method.toUpperCase(),
    params.path,
    params.callerAgentId,
    params.targetAgentId,
    params.timestamp,
    params.nonce,
    params.bodyHash,
  ].join('\n');
}

export function computeBodyHash(body: string): string {
  return crypto.createHash('sha256').update(body, 'utf8').digest('hex');
}

// ── Key generation ───────────────────────────────────────

export interface Ed25519KeyPair {
  /** base64url-encoded public key (32 bytes). */
  publicKey: string;
  /** base64url-encoded private key / seed (32 bytes). */
  privateKey: string;
}

/**
 * Generate a new Ed25519 keypair.
 * Returns base64url-encoded keys (no padding).
 */
export function generateKeyPair(): Ed25519KeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return {
    publicKey: publicKey.toString('base64url'),
    privateKey: privateKey.toString('base64url'),
  };
}

// ── Signing ──────────────────────────────────────────────

export interface SignRequestParams {
  method: string;
  path: string;
  callerAgentId: string;
  targetAgentId: string;
  body: string;
  /** base64url-encoded PKCS#8 DER private key. */
  privateKey: string;
}

export interface SignedHeaders {
  'x-molt-caller': string;
  'x-molt-timestamp': string;
  'x-molt-nonce': string;
  'x-molt-signature': string;
}

export function signRequest(params: SignRequestParams): SignedHeaders {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = crypto.randomBytes(16).toString('hex');
  const bodyHash = computeBodyHash(params.body);
  const canonical = buildCanonicalString({
    method: params.method,
    path: params.path,
    callerAgentId: params.callerAgentId,
    targetAgentId: params.targetAgentId,
    timestamp,
    nonce,
    bodyHash,
  });

  const pkDer = Buffer.from(params.privateKey, 'base64url');
  const privateKeyObj = crypto.createPrivateKey({ key: pkDer, format: 'der', type: 'pkcs8' });
  const sig = crypto.sign(null, Buffer.from(canonical, 'utf8'), privateKeyObj);

  return {
    'x-molt-caller': params.callerAgentId,
    'x-molt-timestamp': timestamp,
    'x-molt-nonce': nonce,
    'x-molt-signature': sig.toString('base64url'),
  };
}

// ── Verification ─────────────────────────────────────────

export interface VerifySignatureParams {
  method: string;
  path: string;
  callerAgentId: string;
  targetAgentId: string;
  body: string;
  /** base64url-encoded SPKI DER public key. */
  publicKey: string;
  timestamp: string;
  nonce: string;
  signature: string;
  /** Allowed clock skew in seconds. Defaults to 300. */
  windowSeconds?: number;
}

export interface VerifyResult {
  valid: boolean;
  reason?: string;
}

export function verifySignature(params: VerifySignatureParams): VerifyResult {
  const window = params.windowSeconds ?? 300;
  const now = Math.floor(Date.now() / 1000);
  const ts = parseInt(params.timestamp, 10);
  if (isNaN(ts) || Math.abs(now - ts) > window) {
    return { valid: false, reason: 'Timestamp out of window' };
  }

  const bodyHash = computeBodyHash(params.body);
  const canonical = buildCanonicalString({
    method: params.method,
    path: params.path,
    callerAgentId: params.callerAgentId,
    targetAgentId: params.targetAgentId,
    timestamp: params.timestamp,
    nonce: params.nonce,
    bodyHash,
  });

  try {
    const pkDer = Buffer.from(params.publicKey, 'base64url');
    const publicKeyObj = crypto.createPublicKey({ key: pkDer, format: 'der', type: 'spki' });
    const sigBuf = Buffer.from(params.signature, 'base64url');
    const ok = crypto.verify(null, Buffer.from(canonical, 'utf8'), publicKeyObj, sigBuf);
    if (!ok) return { valid: false, reason: 'Signature mismatch' };
  } catch {
    return { valid: false, reason: 'Invalid signature or key' };
  }

  return { valid: true };
}
