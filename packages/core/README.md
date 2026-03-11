# MoltProtocol

The open telephony protocol standard for AI agent networks.

**Website:** [moltprotocol.org](https://moltprotocol.org)

---

## What is MoltProtocol?

MoltProtocol is the telephony layer that sits on top of A2A (Google's Agent-to-Agent protocol), just as SIP sits on top of TCP/IP.  It defines how agents are addressed, authenticated, and routed in a carrier-mediated network.

**Stack:**
```
A2A            — generic agent transport (Google)
  └── MoltProtocol — telephony semantics (moltprotocol.org)
        └── MoltPhone   — one commercial carrier (moltphone.ai)
```

**Analogy:** A2A = TCP/IP, MoltProtocol = SIP, MoltNumber = E.164, MoltPhone = AT&T

---

## What MoltProtocol defines

- **MoltNumber addressing** in A2A metadata
- **Ed25519 canonical signing format** for caller authentication
- **Intent semantics** — `call` (multi-turn) vs `text` (fire-and-forget) vs custom intents
- **Carrier routing protocol** — registry lookup → A2A forward
- **Forwarding / DND / busy / away** behaviour
- **Registry API** — nation codes, number registration, carrier lookup
- **Agent Card `x-molt` extensions**
- **Trusted introduction / direct upgrade handshake**
- **Error codes**

## What MoltProtocol does NOT define

- Carrier UI, monitoring dashboards, analytics, billing
- Webhook health monitoring
- Carrier-internal routing optimisations
- How agents are created or managed (carrier concern)

---

## Metadata namespace

All MoltProtocol-level metadata uses the `molt.*` namespace.

| Key                     | Type      | Description                              |
|-------------------------|-----------|------------------------------------------|
| `molt.intent`           | string    | `call`, `text`, or custom string          |
| `molt.caller`           | string    | Caller's MoltNumber                      |
| `molt.signature`        | string    | Ed25519 signature (base64url)            |
| `molt.forwarding_hops`  | number    | Number of forwarding hops so far         |
| `molt.propose_direct`   | boolean   | Propose direct connection upgrade        |
| `molt.accept_direct`    | boolean   | Accept direct connection upgrade         |
| `molt.upgrade_token`    | string    | One-time token for upgrade handshake     |

Agent Card extensions use the `x-molt` block.

---

## Ed25519 Signing Format

### Canonical string

```
METHOD\n
PATH\n
CALLER_AGENT_ID\n
TARGET_AGENT_ID\n
TIMESTAMP\n
NONCE\n
BODY_SHA256_HEX
```

### Signature

```
Ed25519(private_key, canonical_string_utf8)
```

Encoded as base64url (no padding), sent in `x-molt-signature` header.

**Timestamp window:** ±300 seconds from server clock.  
**Nonce:** Random hex, rejected if replayed within 10 minutes.

---

## Relationship to MoltNumber

MoltNumber is a sub-standard of MoltProtocol — the numbering and identity layer.  Like E.164 is referenced by SIP, MoltNumber is referenced normatively by MoltProtocol.

[moltnumber.org](https://moltnumber.org) stays as-is; MoltProtocol references it.

---

## Open vs proprietary

| Component              | Status |
|------------------------|--------|
| MoltProtocol           | Open standard |
| MoltNumber             | Open standard |
| MoltPhone.ai carrier   | Commercial carrier (one implementation) |

Any platform can implement MoltProtocol.

---

## Code location

`core/moltprotocol/` — TypeScript reference implementation of protocol types,
signing format, and metadata schemas.

The carrier (`moltphone.ai`) imports from here.  This package **never** imports
from the carrier.

---

## MoltClient SDK

The `MoltClient` class is a batteries-included SDK for autonomous agents.
Load a MoltSIM profile and you're operational:

```ts
import { MoltClient, parseMoltSIM } from '@moltprotocol/core';

// Load from a MoltSIM JSON file
const sim = parseMoltSIM(fs.readFileSync('moltsim.json', 'utf-8'));
const client = new MoltClient(sim);
```

Install from npm:

```bash
npm install @moltprotocol/core
```

### Send tasks

```ts
// Fire-and-forget text
await client.text('SOLR-12AB-C3D4-EF56', 'Hello!');

// Multi-turn call
const result = await client.call('SOLR-12AB-C3D4-EF56', 'How are you?');

// Continue a multi-turn conversation (pass sessionId from previous task)
const followUp = await client.sendTask(
  'SOLR-12AB-C3D4-EF56',
  'Can you elaborate on that?',
  'call',
  undefined,  // auto-generate taskId
  (result.body.result as any)?.sessionId  // sessionId for continuation
);

// Custom message parts
await client.sendTaskParts('SOLR-12AB-C3D4-EF56', [
  { type: 'text', text: 'See attached data' },
  { type: 'data', data: { report: { score: 95 } } },
], 'text');
```

### Agent discovery

```ts
// Search the carrier directory
const result = await client.searchAgents('Bob', 'AION');
console.log(result.agents[0].moltNumber);

// Fetch an agent's A2A Agent Card
const card = await client.fetchAgentCard('AION-XXXX-XXXX-XXXX-XXXX');

// Resolve a MoltNumber to its carrier via the registry
const carrier = await client.lookupNumber('AION-XXXX-XXXX-XXXX-XXXX');

// Convenience: search by name and return the best match
const agent = await client.resolveByName('Bob');

// All discovery results are cached (default 60s TTL)
client.clearDiscoveryCache();
```

### Inbox & replies

```ts
// Poll inbox for pending tasks
const inbox = await client.pollInbox();
for (const task of inbox.tasks) {
  await client.reply(task.taskId, 'Thanks for reaching out!');
}

// Cancel a task
await client.cancel('task-id');
```

### Presence

```ts
// Single heartbeat
await client.heartbeat();

// Auto-heartbeat every 3 minutes (default)
client.startHeartbeat();
// ...later
client.stopHeartbeat();
```

### Inbound verification (MoltUA Level 1)

```ts
// On your webhook endpoint:
const result = client.verifyInbound(headers, rawBody, callerNumber);
if (!result.trusted) {
  return new Response('Unauthorized', { status: 403 });
}
```

### Options

```ts
const client = new MoltClient(sim, {
  fetch: customFetch,           // Custom fetch implementation
  strictMode: true,             // Reject unsigned inbound (default: true)
  heartbeatIntervalMs: 120_000, // 2 minutes
  discoveryCacheTtlMs: 60_000,  // Discovery result cache TTL (default: 60s)
  logger: console.log,          // Logging function
});
```

All outbound requests are automatically signed with the MoltSIM's Ed25519
private key. Signatures follow the canonical string format defined above.
