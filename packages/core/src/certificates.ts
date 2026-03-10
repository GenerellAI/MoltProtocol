/**
 * MoltProtocol — Registration Certificates.
 *
 * Two-level certificate chain for offline trust verification:
 *
 *   Root (moltprotocol.org)  ──signs──▶  Carrier (moltphone.ai)
 *   Carrier (moltphone.ai)  ──signs──▶  Agent (MOLT-XXXX-...)
 *
 * Like TLS: Root CA → Intermediate CA → End Entity.
 *
 * 1. **Carrier Certificate** — The root authority (moltprotocol.org) signs
 *    a statement that a given carrier public key is authorized to operate
 *    under a given domain. Anyone with the root public key can verify that
 *    a carrier is legitimate without contacting the root.
 *
 * 2. **Registration Certificate** — A carrier signs a statement that a
 *    given agent (MoltNumber + public key) was registered. Anyone with the
 *    carrier's public key can verify offline that an agent was registered
 *    by that carrier.
 *
 * Both certificates are Ed25519 signatures over canonical strings.
 * No X.509, no ASN.1, no JWTs — just raw Ed25519 over deterministic text.
 *
 * This module defines the OPEN STANDARD. Any MoltProtocol implementation
 * MUST use this exact format for interoperable certificate verification.
 */

import crypto from 'crypto';

// ══════════════════════════════════════════════════════════
// ── Carrier Certificate (Root → Carrier) ─────────────────
// ══════════════════════════════════════════════════════════

/**
 * A carrier certificate proves that a root authority authorized a carrier
 * to operate under a given domain with a given public key.
 *
 * Analogous to an intermediate CA certificate in TLS.
 */
export interface CarrierCertificate {
  /** Certificate format version. */
  version: '1';
  /** The carrier domain being certified (e.g., "moltphone.ai"). */
  carrierDomain: string;
  /** The carrier's Ed25519 public key (base64url SPKI DER). */
  carrierPublicKey: string;
  /** Unix timestamp (seconds) when the certificate was issued. */
  issuedAt: number;
  /** Unix timestamp (seconds) when the certificate expires. */
  expiresAt: number;
  /** The root authority domain that issued this certificate. */
  issuer: string;
  /** Ed25519 signature by the root authority (base64url). */
  signature: string;
}

/**
 * Canonical string for carrier certificate signing.
 *
 * Format (fields joined by newlines):
 *   CERT_TYPE
 *   VERSION
 *   CARRIER_DOMAIN
 *   CARRIER_PUBLIC_KEY
 *   ISSUED_AT
 *   EXPIRES_AT
 *   ISSUER
 */
export function buildCarrierCertCanonical(params: {
  carrierDomain: string;
  carrierPublicKey: string;
  issuedAt: number;
  expiresAt: number;
  issuer: string;
}): string {
  return [
    'CARRIER_CERT',
    '1',
    params.carrierDomain,
    params.carrierPublicKey,
    params.issuedAt.toString(),
    params.expiresAt.toString(),
    params.issuer,
  ].join('\n');
}

/**
 * Sign a carrier certificate with the root authority's private key.
 *
 * Called by moltprotocol.org to authorize a carrier.
 */
export function signCarrierCertificate(params: {
  carrierDomain: string;
  carrierPublicKey: string;
  issuedAt: number;
  expiresAt: number;
  issuer: string;
  /** Root authority's Ed25519 private key (base64url PKCS#8 DER). */
  rootPrivateKey: string;
}): CarrierCertificate {
  const canonical = buildCarrierCertCanonical(params);
  const pkDer = Buffer.from(params.rootPrivateKey, 'base64url');
  const privateKeyObj = crypto.createPrivateKey({ key: pkDer, format: 'der', type: 'pkcs8' });
  const sig = crypto.sign(null, Buffer.from(canonical, 'utf8'), privateKeyObj);

  return {
    version: '1',
    carrierDomain: params.carrierDomain,
    carrierPublicKey: params.carrierPublicKey,
    issuedAt: params.issuedAt,
    expiresAt: params.expiresAt,
    issuer: params.issuer,
    signature: sig.toString('base64url'),
  };
}

export interface VerifyCertResult {
  valid: boolean;
  reason?: string;
}

/**
 * Verify a carrier certificate against the root authority's public key.
 *
 * Checks:
 * 1. Signature is valid (root signed this exact data).
 * 2. Certificate is not expired.
 * 3. Issuer matches the expected root authority.
 */
export function verifyCarrierCertificate(
  cert: CarrierCertificate,
  rootPublicKey: string,
  opts?: {
    /** Override "now" for testing (unix seconds). */
    now?: number;
    /** Expected issuer domain (e.g., "moltprotocol.org"). */
    expectedIssuer?: string;
  },
): VerifyCertResult {
  const now = opts?.now ?? Math.floor(Date.now() / 1000);

  if (opts?.expectedIssuer && cert.issuer !== opts.expectedIssuer) {
    return { valid: false, reason: `Unexpected issuer: ${cert.issuer}` };
  }

  if (now < cert.issuedAt) {
    return { valid: false, reason: 'Certificate not yet valid (issuedAt in the future)' };
  }

  if (now > cert.expiresAt) {
    return { valid: false, reason: 'Carrier certificate expired' };
  }

  const canonical = buildCarrierCertCanonical({
    carrierDomain: cert.carrierDomain,
    carrierPublicKey: cert.carrierPublicKey,
    issuedAt: cert.issuedAt,
    expiresAt: cert.expiresAt,
    issuer: cert.issuer,
  });

  try {
    const pkDer = Buffer.from(rootPublicKey, 'base64url');
    const publicKeyObj = crypto.createPublicKey({ key: pkDer, format: 'der', type: 'spki' });
    const sigBuf = Buffer.from(cert.signature, 'base64url');
    const ok = crypto.verify(null, Buffer.from(canonical, 'utf8'), publicKeyObj, sigBuf);
    if (!ok) return { valid: false, reason: 'Carrier certificate signature mismatch' };
  } catch {
    return { valid: false, reason: 'Invalid carrier certificate signature or key' };
  }

  return { valid: true };
}


// ══════════════════════════════════════════════════════════
// ── Registration Certificate (Carrier → Agent) ──────────
// ══════════════════════════════════════════════════════════

/**
 * A registration certificate proves that a carrier registered an agent.
 *
 * Analogous to an end-entity certificate in TLS.
 */
export interface RegistrationCertificate {
  /** Certificate format version. */
  version: '1';
  /** The agent's MoltNumber. */
  moltNumber: string;
  /** The agent's Ed25519 public key (base64url SPKI DER). */
  agentPublicKey: string;
  /** The nation code. */
  nationCode: string;
  /** The carrier domain that issued this certificate. */
  carrierDomain: string;
  /** Unix timestamp (seconds) when registration occurred. */
  issuedAt: number;
  /** Ed25519 signature by the carrier (base64url). */
  signature: string;
}

/**
 * Canonical string for registration certificate signing.
 *
 * Format (fields joined by newlines):
 *   CERT_TYPE
 *   VERSION
 *   MOLT_NUMBER
 *   AGENT_PUBLIC_KEY
 *   NATION_CODE
 *   CARRIER_DOMAIN
 *   ISSUED_AT
 */
export function buildRegistrationCertCanonical(params: {
  moltNumber: string;
  agentPublicKey: string;
  nationCode: string;
  carrierDomain: string;
  issuedAt: number;
}): string {
  return [
    'REGISTRATION_CERT',
    '1',
    params.moltNumber,
    params.agentPublicKey,
    params.nationCode,
    params.carrierDomain,
    params.issuedAt.toString(),
  ].join('\n');
}

/**
 * Sign a registration certificate with the carrier's private key.
 *
 * Called by the carrier when an agent is registered or re-provisioned.
 */
export function signRegistrationCertificate(params: {
  moltNumber: string;
  agentPublicKey: string;
  nationCode: string;
  carrierDomain: string;
  issuedAt: number;
  /** Carrier's Ed25519 private key (base64url PKCS#8 DER). */
  carrierPrivateKey: string;
}): RegistrationCertificate {
  const canonical = buildRegistrationCertCanonical(params);
  const pkDer = Buffer.from(params.carrierPrivateKey, 'base64url');
  const privateKeyObj = crypto.createPrivateKey({ key: pkDer, format: 'der', type: 'pkcs8' });
  const sig = crypto.sign(null, Buffer.from(canonical, 'utf8'), privateKeyObj);

  return {
    version: '1',
    moltNumber: params.moltNumber,
    agentPublicKey: params.agentPublicKey,
    nationCode: params.nationCode,
    carrierDomain: params.carrierDomain,
    issuedAt: params.issuedAt,
    signature: sig.toString('base64url'),
  };
}

/**
 * Verify a registration certificate against the carrier's public key.
 *
 * Checks:
 * 1. Signature is valid (carrier signed this exact data).
 * 2. Carrier domain matches expectations.
 *
 * For full chain verification, also verify the carrier certificate
 * with verifyCarrierCertificate() to confirm the carrier itself is
 * authorized by the root authority.
 */
export function verifyRegistrationCertificate(
  cert: RegistrationCertificate,
  carrierPublicKey: string,
  opts?: {
    /** Expected carrier domain. */
    expectedCarrierDomain?: string;
  },
): VerifyCertResult {
  if (opts?.expectedCarrierDomain && cert.carrierDomain !== opts.expectedCarrierDomain) {
    return { valid: false, reason: `Unexpected carrier: ${cert.carrierDomain}` };
  }

  const canonical = buildRegistrationCertCanonical({
    moltNumber: cert.moltNumber,
    agentPublicKey: cert.agentPublicKey,
    nationCode: cert.nationCode,
    carrierDomain: cert.carrierDomain,
    issuedAt: cert.issuedAt,
  });

  try {
    const pkDer = Buffer.from(carrierPublicKey, 'base64url');
    const publicKeyObj = crypto.createPublicKey({ key: pkDer, format: 'der', type: 'spki' });
    const sigBuf = Buffer.from(cert.signature, 'base64url');
    const ok = crypto.verify(null, Buffer.from(canonical, 'utf8'), publicKeyObj, sigBuf);
    if (!ok) return { valid: false, reason: 'Registration certificate signature mismatch' };
  } catch {
    return { valid: false, reason: 'Invalid registration certificate signature or key' };
  }

  return { valid: true };
}


// ══════════════════════════════════════════════════════════
// ── Delegation Certificate (Nation → Carrier) ────────────
// ══════════════════════════════════════════════════════════

/**
 * A delegation certificate proves that a nation (org or carrier type)
 * authorized a specific carrier to manage agents under its nation code.
 *
 * This is the cryptographic foundation for multi-carrier org nations.
 * The nation owner holds an Ed25519 keypair; the delegation cert is
 * signed by the nation's private key to authorize a carrier (identified
 * by public key + domain) to register agents in the nation.
 *
 * Trust chain with delegation:
 *   Root → Carrier cert → Delegation cert → Registration cert → Agent
 *
 * Analogous to an intermediate CA cross-certification in PKI, or a
 * domain-validated SSL certificate where the domain owner (nation)
 * authorizes a CA (carrier) to issue certs (registrations) for it.
 */
export interface DelegationCertificate {
  /** Certificate format version. */
  version: '1';
  /** Nation code being delegated. */
  nationCode: string;
  /** Nation owner's Ed25519 public key (base64url SPKI DER). */
  nationPublicKey: string;
  /** Carrier domain being authorized. */
  carrierDomain: string;
  /** Carrier's Ed25519 public key (base64url SPKI DER). */
  carrierPublicKey: string;
  /** Unix timestamp (seconds) when the delegation was issued. */
  issuedAt: number;
  /** Unix timestamp (seconds) when the delegation expires. Omitted = no expiry. */
  expiresAt?: number;
  /** Ed25519 signature by the nation owner (base64url). */
  signature: string;
}

/**
 * Canonical string for delegation certificate signing.
 *
 * Format (fields joined by newlines):
 *   CERT_TYPE
 *   VERSION
 *   NATION_CODE
 *   NATION_PUBLIC_KEY
 *   CARRIER_DOMAIN
 *   CARRIER_PUBLIC_KEY
 *   ISSUED_AT
 *   EXPIRES_AT (empty string if no expiry)
 */
export function buildDelegationCertCanonical(params: {
  nationCode: string;
  nationPublicKey: string;
  carrierDomain: string;
  carrierPublicKey: string;
  issuedAt: number;
  expiresAt?: number;
}): string {
  return [
    'DELEGATION_CERT',
    '1',
    params.nationCode,
    params.nationPublicKey,
    params.carrierDomain,
    params.carrierPublicKey,
    params.issuedAt.toString(),
    params.expiresAt?.toString() ?? '',
  ].join('\n');
}

/**
 * Sign a delegation certificate with the nation owner's private key.
 *
 * Called by a nation owner (org or carrier type) to authorize a carrier
 * to manage agents under their nation code.
 */
export function signDelegationCertificate(params: {
  nationCode: string;
  nationPublicKey: string;
  carrierDomain: string;
  carrierPublicKey: string;
  issuedAt: number;
  expiresAt?: number;
  /** Nation owner's Ed25519 private key (base64url PKCS#8 DER). */
  nationPrivateKey: string;
}): DelegationCertificate {
  const canonical = buildDelegationCertCanonical(params);
  const pkDer = Buffer.from(params.nationPrivateKey, 'base64url');
  const privateKeyObj = crypto.createPrivateKey({ key: pkDer, format: 'der', type: 'pkcs8' });
  const sig = crypto.sign(null, Buffer.from(canonical, 'utf8'), privateKeyObj);

  return {
    version: '1',
    nationCode: params.nationCode,
    nationPublicKey: params.nationPublicKey,
    carrierDomain: params.carrierDomain,
    carrierPublicKey: params.carrierPublicKey,
    issuedAt: params.issuedAt,
    expiresAt: params.expiresAt,
    signature: sig.toString('base64url'),
  };
}

/**
 * Verify a delegation certificate against the nation owner's public key.
 *
 * Checks:
 * 1. Signature is valid (nation owner signed this exact data).
 * 2. Certificate is not expired (if expiresAt is set).
 * 3. Nation code matches expectations (if provided).
 */
export function verifyDelegationCertificate(
  cert: DelegationCertificate,
  nationPublicKey: string,
  opts?: {
    /** Override "now" for testing (unix seconds). */
    now?: number;
    /** Expected nation code. */
    expectedNationCode?: string;
    /** Expected carrier domain. */
    expectedCarrierDomain?: string;
  },
): VerifyCertResult {
  const now = opts?.now ?? Math.floor(Date.now() / 1000);

  if (opts?.expectedNationCode && cert.nationCode !== opts.expectedNationCode) {
    return { valid: false, reason: `Unexpected nation code: ${cert.nationCode}` };
  }

  if (opts?.expectedCarrierDomain && cert.carrierDomain !== opts.expectedCarrierDomain) {
    return { valid: false, reason: `Unexpected carrier domain: ${cert.carrierDomain}` };
  }

  if (now < cert.issuedAt) {
    return { valid: false, reason: 'Delegation certificate not yet valid (issuedAt in the future)' };
  }

  if (cert.expiresAt && now > cert.expiresAt) {
    return { valid: false, reason: 'Delegation certificate expired' };
  }

  // Verify that the public key in the cert matches the provided key
  if (cert.nationPublicKey !== nationPublicKey) {
    return { valid: false, reason: 'Nation public key mismatch' };
  }

  const canonical = buildDelegationCertCanonical({
    nationCode: cert.nationCode,
    nationPublicKey: cert.nationPublicKey,
    carrierDomain: cert.carrierDomain,
    carrierPublicKey: cert.carrierPublicKey,
    issuedAt: cert.issuedAt,
    expiresAt: cert.expiresAt,
  });

  try {
    const pkDer = Buffer.from(nationPublicKey, 'base64url');
    const publicKeyObj = crypto.createPublicKey({ key: pkDer, format: 'der', type: 'spki' });
    const sigBuf = Buffer.from(cert.signature, 'base64url');
    const ok = crypto.verify(null, Buffer.from(canonical, 'utf8'), publicKeyObj, sigBuf);
    if (!ok) return { valid: false, reason: 'Delegation certificate signature mismatch' };
  } catch {
    return { valid: false, reason: 'Invalid delegation certificate signature or key' };
  }

  return { valid: true };
}


// ══════════════════════════════════════════════════════════
// ── Full Chain Verification ──────────────────────────────
// ══════════════════════════════════════════════════════════

export interface ChainVerifyResult {
  valid: boolean;
  /** Which layer failed, if any. */
  failedAt?: 'carrier_cert' | 'registration_cert' | 'self_certifying';
  reason?: string;
}

/**
 * Verify the full trust chain: root → carrier → agent.
 *
 * 1. Verify the carrier certificate (root signed it).
 * 2. Verify the registration certificate (carrier signed it).
 * 3. Verify the MoltNumber is self-certifying (hash of agent public key).
 *
 * If all three pass, the agent is fully verified: the number matches the
 * key, the carrier registered it, and the root authorized the carrier.
 *
 * @param rootPublicKey  - The root authority's public key (base64url SPKI DER).
 *                         Hardcoded or fetched from moltprotocol.org/.well-known/molt-root.json
 * @param carrierCert    - Carrier certificate issued by the root.
 * @param registrationCert - Registration certificate issued by the carrier.
 * @param verifyMoltNumberFn - Function that checks number ↔ key self-certifying binding.
 */
export function verifyFullChain(params: {
  rootPublicKey: string;
  carrierCert: CarrierCertificate;
  registrationCert: RegistrationCertificate;
  /** A function that verifies MoltNumber ↔ publicKey binding (self-certifying check). */
  verifyMoltNumber: (moltNumber: string, publicKey: string) => boolean;
  opts?: {
    now?: number;
    expectedRootIssuer?: string;
  };
}): ChainVerifyResult {
  // Step 1: Verify carrier certificate (root → carrier)
  const carrierResult = verifyCarrierCertificate(
    params.carrierCert,
    params.rootPublicKey,
    {
      now: params.opts?.now,
      expectedIssuer: params.opts?.expectedRootIssuer,
    },
  );
  if (!carrierResult.valid) {
    return { valid: false, failedAt: 'carrier_cert', reason: carrierResult.reason };
  }

  // Step 2: Verify registration certificate (carrier → agent)
  // The carrier public key from the (now-verified) carrier cert is the trust anchor
  const regResult = verifyRegistrationCertificate(
    params.registrationCert,
    params.carrierCert.carrierPublicKey,
    { expectedCarrierDomain: params.carrierCert.carrierDomain },
  );
  if (!regResult.valid) {
    return { valid: false, failedAt: 'registration_cert', reason: regResult.reason };
  }

  // Step 3: Verify self-certifying binding (number ↔ key)
  if (!params.verifyMoltNumber(params.registrationCert.moltNumber, params.registrationCert.agentPublicKey)) {
    return { valid: false, failedAt: 'self_certifying', reason: 'MoltNumber does not match agent public key' };
  }

  return { valid: true };
}
