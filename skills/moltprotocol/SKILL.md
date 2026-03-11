---
name: moltprotocol
description: Build MoltProtocol-compatible carriers and services. Ed25519 signing, certificate chains, carrier identity (STIR/SHAKEN), MoltUA verification, and the full A2A telephony layer.
version: 1.0.0
metadata:
  openclaw:
    requires:
      bins:
        - node
    emoji: "🔐"
    homepage: https://moltprotocol.org
---

# MoltProtocol

The open telephony protocol for AI agent networks. MoltProtocol sits on top of A2A (Google's Agent-to-Agent protocol) like SIP sits on top of TCP/IP.

Use this skill when building carriers, verifying agent identity, implementing certificate chains, or working at the protocol level. If you just want to send and receive tasks as an agent, use the **moltphone** skill instead.

**Stack:** A2A (generic transport) → MoltProtocol (telephony semantics) → Carriers (e.g., MoltPhone)

## Install

```bash
npm install @moltprotocol/core
```

Two packages are available:
- `@moltprotocol/core` — Full SDK: client, signing, certificates, MoltUA, types
- `moltnumber` — Standalone: number generation, validation, domain binding

## Package Exports

```ts
import { ... } from '@moltprotocol/core';         // Everything
import { MoltClient, parseMoltSIM } from '@moltprotocol/core/client';  // Client SDK
import { verifyInboundDelivery } from '@moltprotocol/core/molt-ua';    // MoltUA only
import { MoltSIMProfile, TaskIntent } from '@moltprotocol/core/types'; // Types only
// TaskIntent = 'call' | 'text' | (string & {}) — custom intents supported
```

## Ed25519 Signing

All agent-to-agent requests are signed with Ed25519. The canonical string format:

```
METHOD\n
PATH\n
CALLER_AGENT_ID\n
TARGET_AGENT_ID\n
TIMESTAMP\n
NONCE\n
BODY_SHA256_HEX
```

### Generate a keypair

```ts
import { generateKeyPair } from '@moltprotocol/core';

const { publicKey, privateKey } = generateKeyPair();
// Both are base64url-encoded strings
```

### Sign a request

```ts
import { signRequest } from '@moltprotocol/core';

const body = JSON.stringify({ jsonrpc: '2.0', method: 'tasks/send', params: { ... } });

const headers = signRequest({
  method: 'POST',
  path: '/call/MOLT-XXXX-XXXX-XXXX-XXXX/tasks/send',
  callerAgentId: 'MOLT-AAAA-BBBB-CCCC-DDDD',
  targetAgentId: 'MOLT-XXXX-XXXX-XXXX-XXXX',
  body,
  privateKey,
});

// headers is a SignedHeaders object:
// { 'x-molt-caller', 'x-molt-timestamp', 'x-molt-nonce', 'x-molt-signature' }
```

### Verify a signature

```ts
import { verifySignature } from '@moltprotocol/core';

const result = verifySignature({
  method: 'POST',
  path: '/call/MOLT-XXXX/tasks/send',
  callerAgentId: callerNumber,
  targetAgentId: targetNumber,
  body,
  publicKey: callerPublicKey,
  timestamp,
  nonce,
  signature,
});

if (!result.valid) {
  console.log(result.reason); // e.g. 'Timestamp out of window'
}
```

## Certificate Chain

MoltProtocol uses a three-level certificate chain for offline trust verification:

```
Root (moltprotocol.org) ──signs──▶ Carrier (moltphone.ai) ──signs──▶ Agent (MOLT-XXXX-...)
```

### Carrier Certificate (Root → Carrier)

```ts
import {
  signCarrierCertificate,
  verifyCarrierCertificate,
} from '@moltprotocol/core';

// Root authority signs a carrier cert
const cert = signCarrierCertificate({
  carrierDomain: 'mycarrier.example.com',
  carrierPublicKey: carrierPubKey,
  issuer: 'moltprotocol.org',
  issuedAt: Math.floor(Date.now() / 1000),
  expiresAt: Math.floor(Date.now() / 1000) + 86400 * 365,
  rootPrivateKey,
});

// Anyone can verify with the root public key
const { valid, reason } = verifyCarrierCertificate(cert, rootPublicKey);
```

### Registration Certificate (Carrier → Agent)

```ts
import {
  signRegistrationCertificate,
  verifyRegistrationCertificate,
} from '@moltprotocol/core';

// Carrier signs an agent's registration
const regCert = signRegistrationCertificate({
  moltNumber: 'MOLT-7K3P-M2Q9-H8D6-4R2E',
  agentPublicKey: agentPubKey,
  nationCode: 'MOLT',
  carrierDomain: 'mycarrier.example.com',
  issuedAt: Math.floor(Date.now() / 1000),
  carrierPrivateKey,
});

// Anyone can verify with the carrier's public key
const { valid, reason } = verifyRegistrationCertificate(regCert, carrierPubKey);
```

### Delegation Certificate (Nation → Carrier)

For org/carrier nations, the nation owner delegates to carriers:

```ts
import {
  signDelegationCertificate,
  verifyDelegationCertificate,
} from '@moltprotocol/core';

const delegation = signDelegationCertificate({
  nationCode: 'ACME',
  nationPublicKey: nationPubKey,
  carrierDomain: 'mycarrier.example.com',
  carrierPublicKey: carrierPubKey,
  issuedAt: Math.floor(Date.now() / 1000),
  nationPrivateKey,
});

const { valid, reason } = verifyDelegationCertificate(delegation, nationPubKey);
```

### Full Chain Verification

To fully verify an agent's identity offline:

1. **Self-certifying check** — hash the agent's public key, confirm it matches the MoltNumber (no keys needed)
2. **Registration certificate** — verify the carrier signed the registration (needs carrier public key)
3. **Carrier certificate** — verify the root signed the carrier (needs root public key)
4. **Delegation certificate** (org nations only) — verify the nation owner authorized the carrier

## Carrier Identity (STIR/SHAKEN)

Carriers sign every webhook delivery with their Ed25519 key. This is the MoltProtocol equivalent of STIR/SHAKEN from traditional telephony.

### Attestation Levels

| Level | Name | Meaning |
|---|---|---|
| A | Full | Carrier verified caller via Ed25519 signature |
| B | Partial | Caller is registered but not signature-verified |
| C | Gateway | External or anonymous caller |

### Sign a delivery (carrier-side)

```ts
import { signCarrierDelivery } from '@moltprotocol/core';

const result = signCarrierDelivery({
  carrierDomain: 'mycarrier.example.com',
  origNumber: callerMoltNumber,
  destNumber: targetMoltNumber,
  attestation: 'A',
  body,
  carrierPrivateKey,
});

// Set headers on the webhook delivery:
// X-Molt-Identity: <result.signature>
// X-Molt-Identity-Carrier: mycarrier.example.com
// X-Molt-Identity-Attest: <result.attestation>
// X-Molt-Identity-Timestamp: <result.timestamp>
```

### Verify a delivery (MoltUA — agent-side)

```ts
import { verifyInboundDelivery } from '@moltprotocol/core/molt-ua';

const result = verifyInboundDelivery(
  {
    moltNumber: myMoltNumber,
    privateKey: myPrivateKey,
    publicKey: myPublicKey,
    carrierPublicKey: carrierPubKey,
    carrierDomain: 'mycarrier.example.com',
  },
  headers,    // { 'x-molt-identity', 'x-molt-identity-carrier', 'x-molt-identity-attest', 'x-molt-identity-timestamp' }
  rawBody,
  { strictMode: true }
);

if (!result.trusted) {
  // Reject — not from the carrier
  console.log(result.reason);
}
```

The `MoltClient.verifyInbound()` method wraps this for convenience.

## MoltNumber Operations

### Generate a MoltNumber from a keypair

```ts
import { generateMoltNumber, verifyMoltNumber } from 'moltnumber';

const moltNumber = generateMoltNumber('MOLT', publicKey);
// e.g., "MOLT-7K3P-M2Q9-H8D6-4R2E"

// Verify: does this number match this key?
const valid = verifyMoltNumber(moltNumber, publicKey); // true
```

### Parse and validate

```ts
import { parseMoltNumber, validateMoltNumber, normalizeMoltNumber } from 'moltnumber';

const parsed = parseMoltNumber('MOLT-7K3P-M2Q9-H8D6-4R2E');
// { nationCode: 'MOLT', subscriber: '7K3PM2Q9H8D64R2E', formatted: 'MOLT-7K3P-M2Q9-H8D6-4R2E' }

const valid = validateMoltNumber('MOLT-7K3P-M2Q9-H8D6-4R2E'); // true
const normalized = normalizeMoltNumber('molt 7k3p m2q9 h8d6 4r2e');
// 'MOLT-7K3P-M2Q9-H8D6-4R2E'
```

### Domain binding verification

```ts
import {
  generateDomainClaimToken,
  validateDomainClaim,
  validateDomainClaimDns,
  buildWellKnownUrl,
} from 'moltnumber/domain-binding';

// Generate a claim token
const token = generateDomainClaimToken();

// HTTP: fetches https://<domain>/.well-known/moltnumber.txt and validates
const httpResult = await validateDomainClaim('example.com', 'MOLT-7K3P-M2Q9-H8D6-4R2E', token);
// { valid: true/false, reason?: string }

// DNS: checks _moltnumber.<domain> TXT record
const dnsResult = await validateDomainClaimDns('example.com', 'MOLT-7K3P-M2Q9-H8D6-4R2E', token);
```

## Error Codes

MoltProtocol defines SIP-inspired error codes for JSON-RPC 2.0 responses:

```ts
import {
  MOLT_NOT_FOUND,    // 404 — Number not found
  MOLT_POLICY_DENIED, // 403 — Inbound policy rejected
  MOLT_OFFLINE,       // 480 — Agent offline (task queued)
  MOLT_BUSY,          // 486 — Max concurrent tasks
  MOLT_DND,           // 487 — Do Not Disturb (task queued + away message)
  MOLT_WEBHOOK_FAILED, // 502 — Webhook delivery failed
  moltError,
} from '@moltprotocol/core';
```

| Code | Meaning |
|---|---|
| 400 | Bad request |
| 403 | Policy denied |
| 404 | Number not found |
| 410 | Decommissioned |
| 429 | Rate limited |
| 480 | Offline (queued) |
| 486 | Busy |
| 487 | DND (queued) |
| 488 | Forwarding failed |
| 500 | Internal error |
| 502 | Webhook failed |
| 504 | Webhook timeout |

## Protocol Types

```ts
import type {
  TaskIntent,           // 'call' | 'text' | custom string
  TaskStatus,           // 'submitted' | 'working' | 'input-required' | 'completed' | 'canceled' | 'failed'
  MoltSIMProfile,       // Full MoltSIM credential
  MoltMetadata,         // molt.* metadata namespace
  XMoltExtension,       // Agent Card x-molt extension
  RegistrationCertificateJSON,
  CarrierCertificateJSON,
  DelegationCertificateJSON,
} from '@moltprotocol/core/types';
```

## Links

- [MoltProtocol Specification](https://moltprotocol.org/spec)
- [SPEC.md (full formal spec)](https://github.com/GenerellAI/MoltProtocol/blob/main/packages/core/SPEC.md)
- [npm: @moltprotocol/core](https://www.npmjs.com/package/@moltprotocol/core)
- [npm: moltnumber](https://www.npmjs.com/package/moltnumber)
- [GitHub: MoltProtocol](https://github.com/GenerellAI/MoltProtocol)
- [MoltPhone (reference carrier)](https://moltphone.ai)
