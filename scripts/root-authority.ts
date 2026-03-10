#!/usr/bin/env npx tsx
/**
 * MoltProtocol Root Authority — Key & Certificate Management
 *
 * This script manages the root authority keypair and signs carrier certificates.
 * The root authority (moltprotocol.org) is the trust anchor for the entire
 * MoltProtocol certificate chain.
 *
 * Usage:
 *   npx tsx scripts/root-authority.ts generate-root-key
 *   npx tsx scripts/root-authority.ts sign-carrier --domain <carrier> --carrier-public-key <key> [--validity-days 365]
 *   npx tsx scripts/root-authority.ts verify-carrier --cert <json-file-or-string>
 *   npx tsx scripts/root-authority.ts show-root-public-key
 *
 * The root private key is loaded from:
 *   1. --root-private-key flag
 *   2. ROOT_PRIVATE_KEY environment variable
 *   3. .root-keypair.json (dev only)
 *
 * SECURITY: The root private key is the most sensitive secret in the entire
 * MoltProtocol ecosystem. In production, it should be stored in a hardware
 * security module or an encrypted secrets manager — never in plaintext on disk.
 */

import crypto from 'crypto';
import fs from 'fs';
import {
  signCarrierCertificate,
  verifyCarrierCertificate,
  type CarrierCertificate,
} from '@moltprotocol/core';
import { generateKeyPair } from '@moltprotocol/core';

// ── Helpers ──────────────────────────────────────────────

function die(msg: string): never {
  console.error(`Error: ${msg}`);
  process.exit(1);
}

function getFlag(args: string[], name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  return args[idx + 1];
}

function loadRootPrivateKey(args: string[]): string {
  // 1. CLI flag
  const fromFlag = getFlag(args, '--root-private-key');
  if (fromFlag) return fromFlag;

  // 2. Environment variable
  if (process.env.ROOT_PRIVATE_KEY) return process.env.ROOT_PRIVATE_KEY;

  // 3. Dev file
  try {
    const saved = JSON.parse(fs.readFileSync('.root-keypair.json', 'utf-8'));
    return saved.privateKey;
  } catch {
    // fall through
  }

  die(
    'Root private key not found. Provide via:\n' +
    '  --root-private-key <key>\n' +
    '  ROOT_PRIVATE_KEY env var\n' +
    '  .root-keypair.json file'
  );
}

function loadRootPublicKey(args: string[]): string {
  // 1. CLI flag
  const fromFlag = getFlag(args, '--root-public-key');
  if (fromFlag) return fromFlag;

  // 2. Environment variable
  if (process.env.ROOT_PUBLIC_KEY) return process.env.ROOT_PUBLIC_KEY;

  // 3. Dev file
  try {
    const saved = JSON.parse(fs.readFileSync('.root-keypair.json', 'utf-8'));
    return saved.publicKey;
  } catch {
    // fall through
  }

  die(
    'Root public key not found. Provide via:\n' +
    '  --root-public-key <key>\n' +
    '  ROOT_PUBLIC_KEY env var\n' +
    '  .root-keypair.json file'
  );
}

// ── Commands ─────────────────────────────────────────────

function cmdGenerateRootKey() {
  const kp = generateKeyPair();

  console.log('=== MoltProtocol Root Authority Keypair ===\n');
  console.log('IMPORTANT: Store the private key securely. It controls the entire trust chain.\n');
  console.log(`ROOT_PUBLIC_KEY=${kp.publicKey}`);
  console.log(`ROOT_PRIVATE_KEY=${kp.privateKey}`);
  console.log('\n--- JSON format (for .root-keypair.json dev file) ---');
  console.log(JSON.stringify({ publicKey: kp.publicKey, privateKey: kp.privateKey }, null, 2));

  // Also output the molt-root.json content
  console.log('\n--- molt-root.json (for moltprotocol.org/.well-known/) ---');
  console.log(JSON.stringify({
    version: '1',
    issuer: 'moltprotocol.org',
    public_key: kp.publicKey,
    key_algorithm: 'Ed25519',
    key_encoding: 'base64url SPKI DER',
  }, null, 2));
}

function cmdShowRootPublicKey(args: string[]) {
  const pubKey = loadRootPublicKey(args);
  console.log(pubKey);
}

function cmdSignCarrier(args: string[]) {
  const domain = getFlag(args, '--domain');
  if (!domain) die('--domain is required (e.g., --domain moltphone.ai)');

  const carrierPublicKey = getFlag(args, '--carrier-public-key');
  if (!carrierPublicKey) die('--carrier-public-key is required (base64url SPKI DER)');

  const validityDays = parseInt(getFlag(args, '--validity-days') || '365', 10);
  const issuer = getFlag(args, '--issuer') || 'moltprotocol.org';

  const rootPrivateKey = loadRootPrivateKey(args);
  const now = Math.floor(Date.now() / 1000);

  const cert = signCarrierCertificate({
    carrierDomain: domain,
    carrierPublicKey: carrierPublicKey,
    issuedAt: now,
    expiresAt: now + validityDays * 24 * 60 * 60,
    issuer,
    rootPrivateKey,
  });

  // Output the cert in the JSON format used by CARRIER_CERTIFICATE env var
  const certJSON = {
    version: cert.version,
    carrier_domain: cert.carrierDomain,
    carrier_public_key: cert.carrierPublicKey,
    issued_at: cert.issuedAt,
    expires_at: cert.expiresAt,
    issuer: cert.issuer,
    signature: cert.signature,
  };

  console.log('=== Signed Carrier Certificate ===\n');
  console.log(`Carrier: ${domain}`);
  console.log(`Issued:  ${new Date(cert.issuedAt * 1000).toISOString()}`);
  console.log(`Expires: ${new Date(cert.expiresAt * 1000).toISOString()}`);
  console.log(`Issuer:  ${issuer}`);
  console.log(`\n--- Set this as CARRIER_CERTIFICATE env var ---`);
  console.log(`CARRIER_CERTIFICATE='${JSON.stringify(certJSON)}'`);
  console.log('\n--- JSON (pretty) ---');
  console.log(JSON.stringify(certJSON, null, 2));
}

function cmdVerifyCarrier(args: string[]) {
  const certArg = getFlag(args, '--cert');
  if (!certArg) die('--cert is required (JSON string or path to .json file)');

  let certJSON: Record<string, unknown>;
  try {
    // Try as file first
    if (fs.existsSync(certArg)) {
      certJSON = JSON.parse(fs.readFileSync(certArg, 'utf-8'));
    } else {
      certJSON = JSON.parse(certArg);
    }
  } catch {
    die('Could not parse certificate. Provide valid JSON or a path to a .json file.');
  }

  // Convert from JSON format (snake_case) to internal format (camelCase)
  const cert: CarrierCertificate = {
    version: '1',
    carrierDomain: (certJSON.carrier_domain as string) || '',
    carrierPublicKey: (certJSON.carrier_public_key as string) || '',
    issuedAt: (certJSON.issued_at as number) || 0,
    expiresAt: (certJSON.expires_at as number) || 0,
    issuer: (certJSON.issuer as string) || '',
    signature: (certJSON.signature as string) || '',
  };

  const rootPublicKey = loadRootPublicKey(args);
  const result = verifyCarrierCertificate(cert, rootPublicKey);

  if (result.valid) {
    console.log('✓ Carrier certificate is VALID');
    console.log(`  Carrier: ${cert.carrierDomain}`);
    console.log(`  Issued:  ${new Date(cert.issuedAt * 1000).toISOString()}`);
    console.log(`  Expires: ${new Date(cert.expiresAt * 1000).toISOString()}`);
    console.log(`  Issuer:  ${cert.issuer}`);
  } else {
    console.log(`✗ Carrier certificate is INVALID: ${result.reason}`);
    process.exit(1);
  }
}

// ── Main ─────────────────────────────────────────────────

const args = process.argv.slice(2);
const command = args[0];

switch (command) {
  case 'generate-root-key':
    cmdGenerateRootKey();
    break;
  case 'show-root-public-key':
    cmdShowRootPublicKey(args);
    break;
  case 'sign-carrier':
    cmdSignCarrier(args);
    break;
  case 'verify-carrier':
    cmdVerifyCarrier(args);
    break;
  default:
    console.log(`MoltProtocol Root Authority Tool

Commands:
  generate-root-key                Generate a new root Ed25519 keypair
  show-root-public-key             Display the root public key
  sign-carrier                     Sign a carrier certificate
  verify-carrier                   Verify a carrier certificate

Sign carrier options:
  --domain <domain>                Carrier domain (required)
  --carrier-public-key <key>       Carrier's Ed25519 public key, base64url SPKI DER (required)
  --validity-days <n>              Certificate validity in days (default: 365)
  --issuer <domain>                Root issuer domain (default: moltprotocol.org)
  --root-private-key <key>         Root private key (or set ROOT_PRIVATE_KEY env)

Verify carrier options:
  --cert <json-or-path>            Certificate JSON string or path to .json file
  --root-public-key <key>          Root public key (or set ROOT_PUBLIC_KEY env)

Examples:
  # Generate the root keypair (do this once, store securely)
  npx tsx scripts/root-authority.ts generate-root-key

  # Sign a carrier certificate for moltphone.ai
  npx tsx scripts/root-authority.ts sign-carrier \\
    --domain moltphone.ai \\
    --carrier-public-key MCowBQYDK2VwAyEA...

  # Verify a carrier certificate
  npx tsx scripts/root-authority.ts verify-carrier \\
    --cert carrier-cert.json
`);
    break;
}
