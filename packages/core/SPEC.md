# MoltProtocol Specification

**Version:** 1.0.0-draft  
**Status:** Draft  
**Date:** 2026-03-03  
**Authors:** MoltPhone Contributors

---

## Abstract

MoltProtocol is a telephony signaling protocol for AI agents. It defines
how agents authenticate, route tasks, verify carrier deliveries, and
establish trust — layered on top of Google's Agent-to-Agent (A2A)
protocol as the wire format.

The relationship to A2A is analogous to SIP on TCP/IP: A2A provides
message transport and task lifecycle; MoltProtocol adds identity
verification, carrier routing, inbound policies, call forwarding,
presence, and a STIR/SHAKEN-inspired carrier attestation framework.

This document specifies the protocol in full: Ed25519 authentication,
canonical signing formats, carrier identity headers, the two-level
certificate chain, MoltUA client compliance levels, Agent Card
extensions, and MoltSIM credential profiles.

---

## Table of Contents

1.  [Conventions](#1-conventions)
2.  [Introduction](#2-introduction)
3.  [Terminology](#3-terminology)
4.  [Protocol Overview](#4-protocol-overview)
5.  [Task Model](#5-task-model)
6.  [Agent Authentication](#6-agent-authentication)
7.  [Carrier Routing](#7-carrier-routing)
8.  [Carrier Identity](#8-carrier-identity)
9.  [Certificate Chain](#9-certificate-chain)
10. [MoltUA Compliance](#10-moltua-compliance)
11. [Agent Card](#11-agent-card)
12. [MoltSIM Profile](#12-moltsim-profile)
13. [Direct Connections](#13-direct-connections)
14. [Presence](#14-presence)
15. [Error Codes](#15-error-codes)
16. [Security Considerations](#16-security-considerations)
17. [IANA Considerations](#17-iana-considerations)
18. [References](#18-references)
19. [Appendix A — Canonical String Examples](#appendix-a--canonical-string-examples)
20. [Appendix B — Design Rationale](#appendix-b--design-rationale)

---

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [RFC 2119].

---

## 2. Introduction

Existing agent communication standards (A2A, MCP, ACP) define message
formats and task lifecycles but do not address telephony concerns:

- **Who is calling?** How does the target verify the caller's identity?
- **Who may call?** How does an agent restrict inbound traffic?
- **Who delivered this?** How does an endpoint verify that a request
  came from a legitimate carrier, not a spoofed direct call?
- **Where is the agent?** How does activity-based presence work?
- **What if the agent is busy?** How are tasks queued, forwarded, or
  rejected?

MoltProtocol answers these questions. It is designed for a world where
AI agents have phone numbers ([MoltNumbers][MoltNumber Spec]), make and
receive calls (tasks), and operate through carriers — but where the
underlying wire format is A2A, not SIP.

### 2.1 Layering

```
┌─────────────────────────────────────────────┐
│              Application Layer              │
│   (Agent business logic, LLM, tools)        │
├─────────────────────────────────────────────┤
│              MoltProtocol Layer             │
│   (Identity, routing, policy, presence)     │
├─────────────────────────────────────────────┤
│              A2A Transport Layer            │
│   (JSON-RPC 2.0, task lifecycle, SSE)       │
├─────────────────────────────────────────────┤
│              HTTPS                          │
└─────────────────────────────────────────────┘
```

| Layer         | Analogy        | Defines                            |
| ------------- | -------------- | ---------------------------------- |
| Application   | Phone app      | What the agent does                |
| MoltProtocol  | SIP            | Who, where, how (signaling)        |
| A2A           | TCP/IP         | Message format and delivery        |
| HTTPS         | Physical layer | Encrypted transport                |

### 2.2 Scope

MoltProtocol defines:

- Ed25519 canonical signing format for agent authentication
- Carrier identity headers (STIR/SHAKEN-inspired attestation)
- Two-level certificate chain (Root → Carrier → Agent)
- MoltUA client compliance levels
- Agent Card `x-molt` extensions
- MoltSIM credential profiles
- Task routing semantics (policy, forwarding, DND, busy)
- Presence heartbeats
- Direct connection upgrade handshake
- Error codes (SIP-inspired)

MoltProtocol does NOT define:

- MoltNumber format or derivation (see [MoltNumber Spec])
- A2A message format or task lifecycle (see [A2A Protocol])
- Application-level agent behavior
- Billing or metering

### 2.3 Goals

1. **Carrier-mediated by default.** All traffic flows through the
   carrier. Endpoints are never exposed publicly.
2. **Cryptographic identity.** Ed25519 signatures prove caller identity
   without shared secrets.
3. **Defense in depth.** Carrier identity verification makes leaked
   endpoint URLs unexploitable.
4. **Interoperable.** Any standard A2A client can call a MoltProtocol
   agent via its Agent Card. Any MoltProtocol agent can call external
   A2A agents by URL.
5. **Telephony-flavored.** Concepts map to familiar telephony: calls,
   texts, voicemail (inbox), busy signals, call forwarding, DND.

---

## 3. Terminology

**Carrier**
: An implementation that mediates agent-to-agent communication.
  Analogous to a telephone carrier. Example: MoltPhone.

**Caller**
: The agent initiating a task.

**Target** (or **Callee**)
: The agent receiving a task.

**Task**
: A unit of agent-to-agent communication, corresponding to an A2A task.
  Tasks have an intent (call or text) and a lifecycle (Section 5).

**Intent**
: The communication mode: `call` (multi-turn, streaming) or `text`
  (fire-and-forget, single message).

**MoltNumber**
: A self-certifying agent identifier as defined in the [MoltNumber
  Spec]. Format: `NATION-AAAA-BBBB-CCCC-DDDD`.

**MoltSIM**
: A machine-readable credential profile containing everything an
  autonomous client needs to operate as an agent (Section 12).

**MoltUA**
: A MoltProtocol User Agent — any software that operates as a
  MoltProtocol agent endpoint. Named after SIP User Agents (RFC 3261
  §6). See Section 10.

**Agent Card**
: An A2A discovery document extended with MoltProtocol-specific fields
  in the `x-molt` namespace (Section 11).

**Inbound Policy**
: An agent's access control rule for incoming tasks (Section 7.2).

**Attestation Level**
: The carrier's confidence in the caller's identity, modeled on
  STIR/SHAKEN (Section 8.3).

**Dial Route**
: A carrier endpoint for sending tasks to an agent, hosted on a
  dedicated subdomain. Format: `https://call.{carrier}/{moltnumber}/...`

---

## 4. Protocol Overview

### 4.1 Carrier as Mediating Proxy

The carrier receives standard A2A requests on its call routes, applies
MoltProtocol telephony logic (authentication, policy, forwarding, DND),
and forwards as standard A2A to the target agent's webhook endpoint.

```
┌────────┐     A2A + Molt headers     ┌──────────┐     A2A + Identity headers     ┌────────┐
│ Caller │ ──────────────────────────▶ │ Carrier  │ ────────────────────────────▶  │ Target │
│ Agent  │                             │ (proxy)  │                                │ Agent  │
└────────┘                             └──────────┘                                └────────┘
              X-Molt-Caller                            X-Molt-Identity
              X-Molt-Signature                         X-Molt-Identity-Attest
              X-Molt-Timestamp                         X-Molt-Identity-Timestamp
              X-Molt-Nonce
```

The caller authenticates to the carrier using Ed25519 signatures
(Section 6). The carrier authenticates to the target using carrier
identity headers (Section 8). The target's `endpointUrl` is NEVER
exposed in any public surface.

### 4.2 Dial Routes

All carrier endpoints for agent communication live on a dedicated
subdomain, separate from the carrier's web UI:

```
https://call.{carrier}/{moltnumber}/...
```

| Route                                  | Method | Description                    |
| -------------------------------------- | ------ | ------------------------------ |
| `/{number}/agent.json`                 | GET    | Agent Card (A2A discovery)     |
| `/{number}/tasks/send`                 | POST   | Send a task                    |
| `/{number}/tasks/sendSubscribe`        | POST   | Send + subscribe (SSE stream)  |
| `/{number}/tasks`                      | GET    | Poll inbox (authenticated)     |
| `/{number}/tasks/{id}/reply`           | POST   | Reply to a queued task         |
| `/{number}/tasks/{id}/cancel`          | POST   | Cancel / hang up               |
| `/{number}/presence/heartbeat`         | POST   | Presence heartbeat             |

The `{number}` parameter is a raw MoltNumber (URL-safe, no encoding
needed per [MoltNumber Spec] Section 4.4).

### 4.3 A2A Wire Format

All task-related requests use the A2A JSON-RPC 2.0 format:

```json
{
  "jsonrpc": "2.0",
  "method": "tasks/send",
  "params": {
    "id": "task-uuid",
    "message": {
      "role": "user",
      "parts": [{ "type": "text", "text": "Hello" }]
    },
    "metadata": {
      "molt.intent": "call",
      "molt.caller": "SOLR-12AB-C3D4-EF56"
    }
  }
}
```

MoltProtocol uses the `metadata` object with the `molt.` prefix
namespace for protocol-specific fields (Section 5.4).

---

## 5. Task Model

### 5.1 Intent

Every task has an **intent** that determines its communication semantics:

| Intent | A2A Behavior                | Telephony Analogy |
| ------ | --------------------------- | ----------------- |
| `call` | Multi-turn conversation     | Phone call        |
| `text` | Single message, no reply    | SMS               |

The intent is declared in task metadata as `molt.intent` and is
**required**. Omitting it returns a `400 Bad Request` error.

A `call` intent task cycles between `working` and `input-required`
states until one party sends `completed` or `canceled`. A `text` intent
task transitions directly to `completed` after delivery.

### 5.2 Task States

MoltProtocol maps A2A task states to telephony semantics:

| A2A Status       | MoltProtocol Meaning              | Telephony Analogy |
| ---------------- | --------------------------------- | ----------------- |
| `submitted`      | Ringing / queued in inbox         | Ringing           |
| `working`        | Connected, agent is responding    | Active call       |
| `input-required` | Agent's turn (multi-turn)         | Hold / your turn  |
| `completed`      | Hung up normally                  | Call ended         |
| `canceled`       | Caller hung up                    | Caller hang-up    |
| `failed`         | Error (see Section 15)            | Call failed       |

### 5.3 Messages

Each task contains an ordered sequence of messages. Each message has a
`role` (`user` for caller, `agent` for target) and an array of typed
parts:

| Part Type | Fields                          | Description           |
| --------- | ------------------------------- | --------------------- |
| `text`    | `type`, `text`                  | Plain text content    |
| `data`    | `type`, `data`                  | Structured JSON data  |
| `file`    | `type`, `mimeType`, `uri`       | File reference        |

### 5.4 Metadata Namespace

MoltProtocol reserves the `molt.` prefix in A2A task metadata for
protocol-specific fields:

| Key                      | Type   | Description                              |
| ------------------------ | ------ | ---------------------------------------- |
| `molt.intent`            | string | `call` or `text` (Section 5.1)           |
| `molt.caller`            | string | Caller MoltNumber                        |
| `molt.propose_direct`    | bool   | Propose direct connection upgrade        |
| `molt.accept_direct`     | bool   | Accept direct connection upgrade         |
| `molt.upgrade_token`     | string | One-time token for direct upgrade        |

Implementations MUST NOT use the `molt.` prefix for application-level
metadata. Implementations MUST ignore unrecognized `molt.*` keys.

---

## 6. Agent Authentication

### 6.1 Ed25519 Keypair

Each agent has an Ed25519 keypair generated at registration. The public
key is stored by the carrier and published in the Agent Card. The
private key is returned in the MoltSIM (shown once).

Key encoding:

| Key     | Format        | Encoding   |
| ------- | ------------- | ---------- |
| Public  | SPKI DER      | base64url  |
| Private | PKCS#8 DER    | base64url  |

The SPKI DER encoding includes the algorithm identifier (OID), which
makes the format algorithm-agnostic — the same signing protocol works
with Ed25519, ML-DSA, or any future scheme whose keys can be encoded
as SPKI/PKCS#8.

### 6.2 Canonical Signing Format

To authenticate a request, the caller constructs a canonical string and
signs it with Ed25519. The canonical string is deterministic —
identical inputs always produce the same string.

```abnf
canonical-string = method LF path LF caller LF target LF
                   timestamp LF nonce LF body-hash

method       = "GET" / "POST" / "PUT" / "PATCH" / "DELETE"
path         = <URI path component, no query string>
caller       = moltnumber                ; caller's MoltNumber
target       = moltnumber                ; target's MoltNumber
timestamp    = 1*DIGIT                   ; Unix seconds (UTC)
nonce        = 1*( ALPHA / DIGIT / "-" ) ; random, unique
body-hash    = 64HEXDIG                  ; SHA-256 of request body (hex, lowercase)

LF           = %x0A                      ; newline
```

**Construction procedure:**

```
1.  method     ←  HTTP method (uppercase)
2.  path       ←  URL pathname (e.g., "/MOLT-XXXX-.../tasks/send")
3.  caller     ←  Caller's MoltNumber
4.  target     ←  Target's MoltNumber
5.  timestamp  ←  Current time as Unix seconds (UTC)
6.  nonce      ←  Cryptographically random string
7.  body-hash  ←  SHA-256(request body UTF-8), lowercase hex
                   For empty bodies: SHA-256("") =
                   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
8.  canonical  ←  Join fields 1–7 with newline (LF, U+000A)
9.  signature  ←  Ed25519.sign(private_key, canonical)
10. Encode signature as base64url (no padding)
```

### 6.3 Request Headers

The caller sends four headers with each authenticated request:

| Header             | Value                              | Required |
| ------------------ | ---------------------------------- | -------- |
| `X-Molt-Caller`   | Caller's MoltNumber                | Yes      |
| `X-Molt-Timestamp` | Unix timestamp (seconds, UTC)     | Yes      |
| `X-Molt-Nonce`    | Random nonce string                | Yes      |
| `X-Molt-Signature` | Ed25519 signature (base64url)     | Yes      |

All four headers MUST be present for authenticated requests. For
`public` inbound policy agents, the carrier MAY accept requests without
authentication headers (Section 7.2).

### 6.4 Verification Procedure

The carrier verifies signatures as follows:

```
1. Extract X-Molt-Caller, X-Molt-Timestamp, X-Molt-Nonce,
   X-Molt-Signature from request headers.
2. Look up the caller agent by MoltNumber. Retrieve the stored
   public key.
3. Verify timestamp window: |now - timestamp| ≤ 300 seconds.
   If outside window → reject (replay / clock skew).
4. Check nonce: look up nonce in the replay store
   (keyed by caller:nonce). If present → reject (replay).
5. Reconstruct the canonical string from the request.
6. Verify: Ed25519.verify(public_key, canonical, signature).
   If invalid → reject (forgery / tampering).
7. Record the nonce with a TTL of 600 seconds (10 minutes).
8. Request is authenticated.
```

### 6.5 Constants

| Constant                  | Value  | Description                          |
| ------------------------- | ------ | ------------------------------------ |
| `TIMESTAMP_WINDOW_SECONDS`| 300    | Maximum clock skew tolerance (±5min) |
| `NONCE_TTL_SECONDS`       | 600    | Nonce replay window (10min)          |

The nonce TTL MUST be at least `2 × TIMESTAMP_WINDOW_SECONDS` to ensure
that any valid timestamp within the window has its nonce protected.

---

## 7. Carrier Routing

When the carrier receives a task for a target agent, it applies the
following routing logic in order. Each step either continues to the
next or terminates with an error response.

### 7.1 Block Check

The carrier checks two levels of blocks before any other logic:

1. **Carrier-wide blocks.** Administrative blocks by agent ID, phone
   number pattern, nation code, or IP address. Enforced before any
   per-agent logic.
2. **Per-agent blocks.** The target agent's owner may block specific
   callers. Checked after carrier-wide blocks.

If blocked, the carrier MUST return error code 403 (Section 15).

### 7.2 Inbound Policy Enforcement

Each agent declares an inbound policy that controls who may send tasks:

| Policy             | Requirement                                          |
| ------------------ | ---------------------------------------------------- |
| `public`           | No authentication required. Anyone may send tasks.   |
| `registered_only`  | Caller MUST provide `X-Molt-Caller` with a valid MoltNumber. Ed25519 signature verified if present. |
| `allowlist`        | Caller MUST be authenticated AND present in the agent's `allowlistAgentIds` array. |

For `registered_only` and `allowlist` policies, the carrier MUST verify
the caller's Ed25519 signature (Section 6.4) before proceeding.

### 7.3 Call Forwarding

When forwarding is enabled, the carrier redirects inbound tasks to
another agent based on a condition:

| Condition      | Triggers when                              |
| -------------- | ------------------------------------------ |
| `always`       | Every inbound task                         |
| `when_offline` | Target's `lastSeenAt` > 5 minutes ago      |
| `when_busy`    | Target has hit `maxConcurrentCalls`         |
| `when_dnd`     | Target has `dndEnabled = true`              |

**Forwarding rules:**

1. The carrier MUST follow forwarding chains up to a maximum of
   **3 hops** (`MAX_FORWARDING_HOPS`).
2. The carrier MUST detect loops (an agent appearing twice in the
   forwarding chain) and terminate with error code 488 (Section 15).
3. The carrier MUST record the forwarding path in the task's
   `forwardingHops` array for audit purposes.
4. Policy enforcement (Section 7.2) is applied at the **original**
   target, not the forwarded target.

### 7.4 Do Not Disturb (DND)

If the final target has `dndEnabled = true`:

1. The task is created with status `submitted` (queued in inbox).
2. The carrier returns error code 487 with the agent's `awayMessage`
   (if set) and the `task_id`.
3. A push notification MAY be sent to the agent if configured.

### 7.5 Busy (Concurrent Task Limit)

If the final target has reached `maxConcurrentCalls` active tasks
(status `working`):

1. Stale tasks (status `working` with no activity for 30 minutes)
   are auto-expired to `completed` before counting.
2. If still at capacity, the task is created with status `submitted`.
3. The carrier returns error code 486 with the agent's `awayMessage`
   and the `task_id`.

### 7.6 Online Delivery

If the final target is online (Section 14) and has an `endpointUrl`:

1. The carrier validates the webhook URL against SSRF protections.
2. The carrier signs the delivery with carrier identity headers
   (Section 8).
3. The carrier forwards the A2A request to the webhook with a ring
   timeout (default: 30 seconds).
4. If the webhook returns 2xx within the timeout, the task transitions
   to `working` (for `call` intent) or `completed` (for `text` intent).
5. If the webhook fails or times out, the task is queued as `submitted`
   with retry scheduling.

### 7.7 Offline Queuing

If the final target is offline or has no `endpointUrl`:

1. The task is created with status `submitted` (queued in inbox).
2. The carrier returns error code 480 with the agent's `awayMessage`
   and the `task_id`.
3. The agent retrieves queued tasks via inbox polling (Section 7.8).

### 7.8 Inbox

There is no separate voicemail concept. When an inbound task cannot be
delivered in real-time, it remains in `submitted` status. Pending tasks
**are** the inbox.

**Poll inbox:**

```
GET /{number}/tasks
```

Authenticated via Ed25519 (Section 6). Returns all pending tasks
(status `submitted`), ordered oldest-first. Also updates the agent's
`lastSeenAt` (acts as a presence heartbeat).

**Reply to task:**

```
POST /{number}/tasks/{id}/reply

{
  "message": {
    "role": "agent",
    "parts": [{ "type": "text", "text": "Thanks for reaching out!" }]
  }
}
```

**Cancel task:**

```
POST /{number}/tasks/{id}/cancel
```

### 7.9 Routing Flow Summary

```
Inbound task
    │
    ▼
┌─────────────────┐     ┌─────────────────┐
│ Carrier-wide    │────▶│ Per-agent        │
│ block check     │ ok  │ block check      │
└────────┬────────┘     └────────┬────────┘
         │ blocked               │ blocked
         ▼                       ▼
      403 error               403 error
                                 │ ok
                                 ▼
                        ┌─────────────────┐
                        │ Inbound policy  │
                        │ enforcement     │
                        └────────┬────────┘
                                 │ ok
                                 ▼
                        ┌─────────────────┐
                        │ Call forwarding │──── up to 3 hops
                        │ resolution      │
                        └────────┬────────┘
                                 │
                                 ▼
                     ┌───── Final agent ─────┐
                     │                       │
                ┌────┴────┐            ┌─────┴─────┐
                │  DND?   │            │  Busy?    │
                │ → 487   │            │ → 486     │
                └─────────┘            └───────────┘
                                             │ no
                                             ▼
                                    ┌─────────────────┐
                                    │ Online +        │
                                    │ endpoint?       │
                                    └────────┬────────┘
                                        yes  │  no
                                        ▼    ▼
                                  webhook  queue
                                  delivery (480)
```

---

## 8. Carrier Identity

MoltProtocol implements carrier-signed delivery authentication inspired
by the STIR/SHAKEN framework ([RFC 8224] / [RFC 8225]). The carrier
signs every webhook delivery with its Ed25519 key. Compliant MoltUA
implementations (Section 10) verify this signature to reject
unauthorized direct calls.

### 8.1 Analogy to STIR/SHAKEN

| STIR/SHAKEN (SIP)            | MoltProtocol                          |
| ---------------------------- | ------------------------------------- |
| Authentication Service       | Carrier private key signs deliveries  |
| SIP Identity header          | `X-Molt-Identity` header              |
| PASSporT token (RFC 8225)    | Carrier Identity canonical string     |
| Certificate / trust anchor   | Carrier public key in MoltSIM         |
| Verification Service         | MoltUA `verifyInboundDelivery()`      |

### 8.2 Canonical Signing Format

The carrier constructs a canonical string for each delivery:

```abnf
carrier-identity = carrier-domain LF attestation LF
                   orig-number LF dest-number LF
                   timestamp LF body-hash

carrier-domain  = 1*( ALPHA / DIGIT / "." / "-" )
attestation     = "A" / "B" / "C"
orig-number     = moltnumber / "anonymous"
dest-number     = moltnumber
timestamp       = 1*DIGIT              ; Unix seconds (UTC)
body-hash       = 64HEXDIG            ; SHA-256 of body (hex, lowercase)

LF              = %x0A
```

**Construction procedure:**

```
1. carrier-domain  ←  Carrier's domain (e.g., "moltphone.ai")
2. attestation     ←  Attestation level (Section 8.3)
3. orig-number     ←  Caller's MoltNumber, or "anonymous"
4. dest-number     ←  Target's MoltNumber
5. timestamp       ←  Current time as Unix seconds (UTC)
6. body-hash       ←  SHA-256(request body UTF-8), lowercase hex
7. canonical       ←  Join fields 1–6 with newline (LF)
8. signature       ←  Ed25519.sign(carrier_private_key, canonical)
9. Encode signature as base64url (no padding)
```

### 8.3 Attestation Levels

The carrier asserts its confidence in the caller's identity, following
the STIR/SHAKEN attestation model:

| Level | Name    | Meaning                                              |
| ----- | ------- | ---------------------------------------------------- |
| A     | Full    | Carrier verified caller via Ed25519 signature        |
| B     | Partial | Caller is registered (valid MoltNumber) but not signature-verified |
| C     | Gateway | External or anonymous caller                         |

The carrier MUST set attestation to `A` only when the caller's Ed25519
signature has been cryptographically verified. `B` indicates the caller
provided a valid MoltNumber but did not sign the request (e.g., public
policy). `C` indicates an unknown or external caller.

### 8.4 Delivery Headers

Every webhook delivery from the carrier to a target agent MUST include
these headers:

| Header                       | Value                                |
| ---------------------------- | ------------------------------------ |
| `X-Molt-Identity`           | Ed25519 signature (base64url)        |
| `X-Molt-Identity-Carrier`   | Carrier domain (e.g., `moltphone.ai`) |
| `X-Molt-Identity-Attest`    | Attestation level (`A`, `B`, `C`)    |
| `X-Molt-Identity-Timestamp` | Unix seconds (UTC)                   |

### 8.5 Verification

A MoltUA verifies an inbound delivery as follows:

```
1. Extract X-Molt-Identity, X-Molt-Identity-Carrier,
   X-Molt-Identity-Attest, X-Molt-Identity-Timestamp from headers.
2. Verify the carrier domain matches the expected carrier
   (from MoltSIM carrier_domain field).
3. Verify timestamp window: |now - timestamp| ≤ 300 seconds.
4. Reconstruct the canonical string from the delivery.
5. Verify: Ed25519.verify(carrier_public_key, canonical, signature).
   The carrier_public_key is sourced from the MoltSIM.
6. If all checks pass → delivery is trusted.
```

### 8.6 Carrier Keypair Management

- **Production:** Carrier private and public keys are loaded from
  environment variables (`CARRIER_PRIVATE_KEY`, `CARRIER_PUBLIC_KEY`).
  These MUST be stable — rotating them invalidates all existing
  MoltSIMs.
- **Development:** An ephemeral keypair MAY be auto-generated per
  process and persisted to disk for session continuity.
- **Distribution:** The carrier's public key is included in every
  MoltSIM as `carrier_public_key`.

---

## 9. Certificate Chain

MoltProtocol implements a multi-level certificate chain for offline
trust verification, analogous to TLS certificate chains:

```
Root Authority    ──signs──▶   Carrier          ──signs──▶   Agent
(moltprotocol.org)             (moltphone.ai)               (MOLT-XXXX-...)
                                    ▲
Nation (org/carrier)  ──delegates───┘  (optional, for org/carrier nations)
```

All certificates are Ed25519 signatures over deterministic canonical
strings. No X.509, no ASN.1, no JWTs — raw Ed25519 over plain text.

### 9.1 Carrier Certificate (Root → Carrier)

The root authority signs a statement that a carrier's public key is
authorized to operate under a given domain. Anyone with the root
public key can verify offline that a carrier is legitimate.

**Canonical signing format:**

```abnf
carrier-cert-canonical = "CARRIER_CERT" LF "1" LF
                         carrier-domain LF carrier-public-key LF
                         issued-at LF expires-at LF issuer

carrier-domain     = 1*( ALPHA / DIGIT / "." / "-" )
carrier-public-key = base64url        ; SPKI DER
issued-at          = 1*DIGIT          ; Unix seconds
expires-at         = 1*DIGIT          ; Unix seconds
issuer             = 1*( ALPHA / DIGIT / "." / "-" )

LF                 = %x0A
```

**Certificate structure (JSON):**

```json
{
  "version": "1",
  "carrier_domain": "moltphone.ai",
  "carrier_public_key": "<base64url SPKI DER>",
  "issued_at": 1719936000,
  "expires_at": 1751472000,
  "issuer": "moltprotocol.org",
  "signature": "<base64url Ed25519>"
}
```

**Verification:**

1. Verify `issuer` matches the expected root authority.
2. Verify the certificate is within validity period
   (`issued_at ≤ now ≤ expires_at`).
3. Reconstruct canonical string from certificate fields.
4. Verify Ed25519 signature using the root authority's public key.

### 9.2 Registration Certificate (Carrier → Agent)

When an agent is registered (or re-provisioned), the carrier signs a
statement binding the agent's MoltNumber, public key, and nation code
to the carrier. Anyone with the carrier's public key can verify offline
that the agent was registered.

**Canonical signing format:**

```abnf
reg-cert-canonical = "REGISTRATION_CERT" LF "1" LF
                     phone-number LF agent-public-key LF
                     nation-code LF carrier-domain LF issued-at

phone-number       = moltnumber
agent-public-key   = base64url        ; SPKI DER
nation-code        = 4ALPHA
carrier-domain     = 1*( ALPHA / DIGIT / "." / "-" )
issued-at          = 1*DIGIT          ; Unix seconds

LF                 = %x0A
```

**Certificate structure (JSON):**

```json
{
  "version": "1",
  "molt_number": "SOLR-12AB-C3D4-EF56",
  "agent_public_key": "<base64url SPKI DER>",
  "nation_code": "SOLR",
  "carrier_domain": "moltphone.ai",
  "issued_at": 1719936000,
  "signature": "<base64url Ed25519>"
}
```

**Verification:**

1. Optionally verify `carrier_domain` matches expectations.
2. Reconstruct canonical string from certificate fields.
3. Verify Ed25519 signature using the carrier's public key.

### 9.3 Delegation Certificate (Nation → Carrier)

For `org` and `carrier` type nations (see [MoltNumber Spec] Section 9),
the nation owner MAY sign a delegation certificate authorizing a carrier
to register agents under their nation code. This enables multi-carrier
organizational namespaces.

**Canonical signing format:**

```abnf
delegation-cert-canonical = "DELEGATION_CERT" LF "1" LF
                            nation-code LF nation-public-key LF
                            carrier-domain LF carrier-public-key LF
                            issued-at LF expires-at

nation-code        = 4ALPHA
nation-public-key  = base64url        ; SPKI DER
carrier-domain     = 1*( ALPHA / DIGIT / "." / "-" )
carrier-public-key = base64url        ; SPKI DER
issued-at          = 1*DIGIT          ; Unix seconds
expires-at         = 1*DIGIT / ""     ; Unix seconds, or empty for no expiry

LF                 = %x0A
```

**Certificate structure (JSON):**

```json
{
  "version": "1",
  "nation_code": "ACME",
  "nation_public_key": "<base64url SPKI DER>",
  "carrier_domain": "moltphone.ai",
  "carrier_public_key": "<base64url SPKI DER>",
  "issued_at": 1719936000,
  "expires_at": null,
  "signature": "<base64url Ed25519>"
}
```

**Verification:**

1. Verify the nation public key in the certificate matches the expected
   nation owner's key.
2. Verify the certificate is within validity period (if `expires_at` is
   set: `issued_at ≤ now ≤ expires_at`).
3. Reconstruct canonical string from certificate fields.
4. Verify Ed25519 signature using the nation owner's public key.

Delegation certificates are OPTIONAL. They are only relevant for `org`
and `carrier` type nations where the nation owner delegates authority.
For `open` nations, no delegation is needed.

### 9.4 Full Chain Verification

To fully verify an agent's identity offline, a verifier performs the
following checks in order:

```
1. Self-certifying check — hash the agent's public key, confirm it
   matches the MoltNumber. (Needs no keys — per MoltNumber Spec §6.)

2. Registration certificate — verify the carrier signed the agent's
   registration. (Needs carrier public key.)

3. Carrier certificate — verify the root signed the carrier's
   authorization. (Needs root public key.)

4. Delegation certificate (org/carrier nations only) — verify the
   nation owner authorized this carrier. (Needs nation public key.)
```

If all checks pass: the number matches the key, the carrier registered
it, the root authorized the carrier, and (for org nations) the
organization authorized the carrier.

### 9.5 Certificate Distribution

| Surface                    | Registration Cert | Carrier Cert            | Delegation Cert          |
| -------------------------- | ----------------- | ----------------------- | ------------------------ |
| Agent Card (`x-molt`)     | ✓                 | via carrier well-known  | ✓ (org/carrier nations)  |
| MoltSIM profile            | ✓                 | ✓                       | —                        |
| Agent creation response    | ✓                 | —                       | —                        |

The root authority's public key is distributed out-of-band (hardcoded
in implementations or fetched from the root's well-known endpoint).

---

## 10. MoltUA Compliance

MoltUA is the client compliance layer of MoltProtocol, named after the
SIP User Agent ([RFC 3261] §6). It defines what a conforming client
implementation MUST, SHOULD, and MAY implement when receiving
carrier-delivered tasks.

### 10.1 Compliance Levels

| Level | Name     | Requirements                                        |
| ----- | -------- | --------------------------------------------------- |
| 1     | Baseline | MUST verify carrier identity signature on inbound deliveries. MUST reject unsigned or invalid signatures. |
| 2     | Standard | Level 1 + SHOULD verify caller Ed25519 signatures. SHOULD sign outbound requests. SHOULD implement presence heartbeats and inbox polling. |
| 3     | Full     | Level 2 + MAY support direct connection upgrades (Section 13), SSE streaming, and push notifications. |

### 10.2 Level 1 — Baseline

A Level 1 compliant MoltUA MUST:

1. Verify the `X-Molt-Identity` carrier signature on every inbound
   request using the verification procedure in Section 8.5.
2. Reject requests without valid carrier identity headers (in strict
   mode) or without a valid signature.
3. Reject requests with timestamps outside the ±300 second window.
4. Use the `carrier_public_key` from the MoltSIM as trust anchor.

With Level 1 compliance alone, leaked endpoint URLs become
unexploitable — an attacker cannot forge the carrier's signature.

### 10.3 Level 2 — Standard

A Level 2 compliant MoltUA SHOULD additionally:

1. Verify caller Ed25519 signatures (`X-Molt-Signature`) when present.
2. Validate attestation levels from the carrier identity headers.
3. Sign all outbound requests with the agent's Ed25519 private key.
4. Send periodic presence heartbeats (Section 14).
5. Poll the inbox for queued tasks.

### 10.4 Level 3 — Full

A Level 3 compliant MoltUA MAY additionally:

1. Support direct connection upgrade handshakes (Section 13).
2. Verify upgrade tokens against the carrier.
3. Implement SSE streaming for multi-turn conversations
   (`tasks/sendSubscribe`).
4. Support push notification handling.

### 10.5 Defense in Depth

| Layer | What                              | Cost | Solves                        |
| ----- | --------------------------------- | ---- | ----------------------------- |
| 1     | MoltUA carrier signature check    | Free | Leaked endpoints unexploitable|
| 2     | `carrier_only` relay mode         | Paid | Topology hiding + audit trail |

---

## 11. Agent Card

Each agent has an auto-generated [A2A Agent Card][A2A Protocol] served
at `GET /{number}/agent.json` on the carrier's call subdomain.

### 11.1 Standard A2A Fields

| Field          | Source                                     |
| -------------- | ------------------------------------------ |
| `name`         | Agent `displayName`                        |
| `description`  | Agent `description`                        |
| `url`          | `https://call.{carrier}/{number}/tasks/send` |
| `provider`     | Carrier organization and URL               |
| `version`      | Protocol version                           |
| `capabilities` | Streaming, push notifications, state history |
| `skills`       | Agent's declared skills                    |
| `authentication` | Scheme and required flag                 |

The `url` field MUST always point to the **carrier's** call route,
never the agent's real webhook endpoint.

### 11.2 `x-molt` Extension

MoltProtocol extends the Agent Card with an `x-molt` object containing
protocol-specific fields:

```json
{
  "x-molt": {
    "molt_number": "SOLR-12AB-C3D4-EF56",
    "nation": "SOLR",
    "public_key": "<Ed25519 public key, base64url SPKI DER>",
    "inbound_policy": "public",
    "timestamp_window_seconds": 300,
    "direct_connection_policy": "direct_on_consent",
    "registration_certificate": {
      "version": "1",
      "molt_number": "SOLR-12AB-C3D4-EF56",
      "agent_public_key": "<base64url>",
      "nation_code": "SOLR",
      "carrier_domain": "moltphone.ai",
      "issued_at": 1719936000,
      "signature": "<base64url>"
    }
  }
}
```

| Field                        | Type   | Required | Description                    |
| ---------------------------- | ------ | -------- | ------------------------------ |
| `molt_number`               | string | Yes      | Agent's MoltNumber             |
| `nation`                     | string | Yes      | Nation code                    |
| `public_key`                 | string | Yes      | Ed25519 public key (base64url) |
| `inbound_policy`             | string | Yes      | `public`, `registered_only`, `allowlist` |
| `timestamp_window_seconds`   | number | Yes      | Accepted clock skew (seconds)  |
| `direct_connection_policy`   | string | No       | Privacy tier (Section 13)      |
| `registration_certificate`   | object | No       | Carrier-signed registration    |

### 11.3 Access Control

The Agent Card itself is access-controlled by the agent's inbound
policy:

- **`public`:** Anyone may fetch the Agent Card.
- **`registered_only` / `allowlist`:** The GET request MUST include
  valid Ed25519 authentication headers (Section 6.3). The carrier
  verifies the caller's identity before returning the card.

### 11.4 Complete Example

```json
{
  "schema": "https://moltprotocol.org/a2a/agent-card/v1",
  "name": "Solar Inspector",
  "description": "An autonomous solar panel inspector",
  "url": "https://call.moltphone.ai/SOLR-12AB-C3D4-EF56/tasks/send",
  "provider": {
    "organization": "MoltPhone",
    "url": "https://moltphone.ai"
  },
  "version": "1.0",
  "capabilities": {
    "streaming": false,
    "pushNotifications": false,
    "stateTransitionHistory": true
  },
  "defaultInputModes": ["text"],
  "defaultOutputModes": ["text"],
  "skills": [
    { "id": "call", "name": "Call" },
    { "id": "text", "name": "Text" }
  ],
  "authentication": {
    "schemes": ["Ed25519"],
    "required": false
  },
  "status": "online",
  "x-molt": {
    "molt_number": "SOLR-12AB-C3D4-EF56",
    "nation": "SOLR",
    "public_key": "MCowBQYDK2VwAyEA...",
    "inbound_policy": "public",
    "timestamp_window_seconds": 300,
    "direct_connection_policy": "direct_on_consent",
    "registration_certificate": {
      "version": "1",
      "molt_number": "SOLR-12AB-C3D4-EF56",
      "agent_public_key": "MCowBQYDK2VwAyEA...",
      "nation_code": "SOLR",
      "carrier_domain": "moltphone.ai",
      "issued_at": 1719936000,
      "signature": "..."
    }
  }
}
```

---

## 12. MoltSIM Profile

A MoltSIM is a machine-readable credential that contains everything an
autonomous client needs to operate as an agent. It is analogous to a
physical SIM card: the MoltSIM is the credential, the MoltUA is the
phone.

### 12.1 Profile Structure

```json
{
  "version": "1",
  "carrier": "moltphone.ai",
  "agent_id": "<cuid>",
  "molt_number": "SOLR-12AB-C3D4-EF56",
  "private_key": "<Ed25519 private key, base64url PKCS#8 DER>",
  "carrier_public_key": "<Ed25519 public key, base64url SPKI DER>",
  "carrier_call_base": "https://call.moltphone.ai",
  "inbox_url": "https://call.moltphone.ai/SOLR-12AB-C3D4-EF56/tasks",
  "presence_url": "https://call.moltphone.ai/SOLR-12AB-C3D4-EF56/presence/heartbeat",
  "signature_algorithm": "Ed25519",
  "canonical_string": "METHOD\\nPATH\\nCALLER\\nTARGET\\nTIMESTAMP\\nNONCE\\nBODY_SHA256_HEX",
  "timestamp_window_seconds": 300,
  "registration_certificate": { "..." },
  "carrier_certificate": { "..." }
}
```

### 12.2 Field Definitions

| Field                        | Type   | Description                              |
| ---------------------------- | ------ | ---------------------------------------- |
| `version`                    | string | Profile format version (`"1"`)           |
| `carrier`                    | string | Carrier domain                           |
| `agent_id`                   | string | Carrier-internal agent identifier        |
| `molt_number`               | string | Agent's MoltNumber                       |
| `private_key`                | string | Ed25519 private key (base64url PKCS#8)   |
| `carrier_public_key`         | string | Carrier's public key for delivery verification |
| `carrier_call_base`          | string | Base URL for this agent's call routes    |
| `inbox_url`                  | string | Full URL for inbox polling               |
| `presence_url`               | string | Full URL for presence heartbeats         |
| `signature_algorithm`        | string | Signing algorithm identifier             |
| `canonical_string`           | string | Template for canonical string construction |
| `timestamp_window_seconds`   | number | Accepted clock skew                      |
| `registration_certificate`   | object | Carrier-signed registration (Section 9.2) |
| `carrier_certificate`        | object | Root-signed carrier cert (Section 9.1)   |

### 12.3 Lifecycle

1. **Generation.** A MoltSIM is generated at agent creation or
   re-provisioning. The private key is displayed **once** and MUST
   NOT be stored by the carrier after delivery.
2. **Re-provisioning.** Generating a new MoltSIM rotates the Ed25519
   keypair, changing the public key stored in the database. The old
   MoltSIM is instantly revoked — signatures from the old key will
   fail verification.
3. **QR Code.** Carriers MAY provide the MoltSIM as a QR code for
   easy import into MoltUA applications.

### 12.4 MoltSIM vs Agent Card

| Aspect      | MoltSIM (private)              | Agent Card (public)          |
| ----------- | ------------------------------ | ---------------------------- |
| Audience    | The agent itself               | Other agents / clients       |
| Contains    | Private key, carrier endpoints | Name, skills, inbound URL    |
| Shown       | Once, at creation or re-prov.  | Always, via `agent.json`     |
| Purpose     | Operate as the agent           | Discover and contact agent   |
| Shared field| `molt_number`                 | `molt_number`               |

---

## 13. Direct Connections

Initial contact between agents always flows through the carrier. After
mutual consent, agents MAY upgrade to direct A2A connections —
bypassing the carrier for subsequent communication.

### 13.1 Direct Connection Policy

Each agent sets a `directConnectionPolicy`:

| Policy              | Behavior                                            |
| ------------------- | --------------------------------------------------- |
| `direct_on_consent` | Default. Both parties agree → carrier shares endpoints. |
| `direct_on_accept`  | Target opts in to receive direct connection offers. |
| `carrier_only`      | All traffic always through carrier. Endpoint never shared. |

### 13.2 Upgrade Handshake

```
1. Caller sends task with molt.propose_direct = true in metadata.
2. Target responds with molt.accept_direct = true and a one-time
   molt.upgrade_token in metadata.
3. Carrier validates the token and shares the target's endpointUrl
   with the caller.
4. Post-upgrade: agents communicate directly via A2A. The carrier
   is out of the loop.
```

The `endpointUrl` is NEVER included in any public response (Agent Card,
MoltPage, or API). It is only visible in the agent owner's settings
and during the upgrade handshake.

### 13.3 Security Considerations for Direct Connections

- Direct connections bypass carrier identity verification. Both agents
  SHOULD verify each other's Ed25519 signatures directly.
- The upgrade token is one-time use — replay MUST be rejected.
- Agents with `carrier_only` policy MUST NOT participate in the
  upgrade handshake. The carrier MUST NOT share their endpoint.
- `carrier_only` relay traffic is a paid feature — the target's owner
  bears the relay cost in exchange for topology hiding and audit trail.

---

## 14. Presence

Agents signal liveness by sending periodic heartbeats to the carrier.

### 14.1 Heartbeat

```
POST /{number}/presence/heartbeat
```

Authenticated via Ed25519 (Section 6). The carrier updates the agent's
`lastSeenAt` timestamp.

### 14.2 Online Threshold

An agent is considered **online** if:

```
now - lastSeenAt ≤ PRESENCE_ONLINE_SECONDS
```

| Constant                   | Value | Description                     |
| -------------------------- | ----- | ------------------------------- |
| `PRESENCE_ONLINE_SECONDS`  | 300   | Online threshold (5 minutes)    |

Agents SHOULD send heartbeats at intervals shorter than the online
threshold (RECOMMENDED: every 60 seconds).

### 14.3 Implicit Heartbeats

Inbox polling (`GET /{number}/tasks`) also updates `lastSeenAt`. An
agent that regularly polls its inbox does not need separate heartbeats.

---

## 15. Error Codes

MoltProtocol uses structured error codes modeled on SIP response codes.
Errors are returned as JSON-RPC 2.0 error objects:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": 404,
    "message": "Agent not found"
  },
  "id": null
}
```

### 15.1 Client Errors (4xx)

| Code | Constant              | Meaning              | SIP Analog  |
| ---- | --------------------- | -------------------- | ----------- |
| 400  | `MOLT_BAD_REQUEST`    | Malformed request    | 400         |
| 401  | `MOLT_AUTH_REQUIRED`  | Authentication needed| 401         |
| 403  | `MOLT_POLICY_DENIED`  | Policy blocked       | 403         |
| 404  | `MOLT_NOT_FOUND`      | Number not found     | 404         |
| 409  | `MOLT_CONFLICT`       | State conflict       | —           |
| 410  | `MOLT_DECOMMISSIONED` | Number deactivated   | 410         |
| 429  | `MOLT_RATE_LIMITED`   | Too many requests    | —           |

### 15.2 Target Unavailable (4xx, SIP-Inspired)

| Code | Constant                | Meaning                   | SIP Analog  |
| ---- | ----------------------- | ------------------------- | ----------- |
| 480  | `MOLT_OFFLINE`          | Agent offline (queued)    | 480         |
| 486  | `MOLT_BUSY`             | Max concurrent (queued)   | 486         |
| 487  | `MOLT_DND`              | Do Not Disturb (queued)   | 487         |
| 488  | `MOLT_FORWARDING_FAILED`| Forwarding chain failed   | 488         |

Codes 480, 486, and 487 indicate that the task has been **queued** —
the caller receives a `task_id` and MAY poll for status. These are not
terminal failures.

### 15.3 Server Errors (5xx)

| Code | Constant                | Meaning              | SIP Analog  |
| ---- | ----------------------- | -------------------- | ----------- |
| 500  | `MOLT_INTERNAL_ERROR`   | Carrier error        | 500         |
| 502  | `MOLT_WEBHOOK_FAILED`   | Webhook delivery fail| 502         |
| 504  | `MOLT_WEBHOOK_TIMEOUT`  | Webhook timed out    | 504         |

### 15.4 Error Response Format

All error responses MUST include:

- `code` — One of the constants above.
- `message` — Human-readable description.

Error responses MAY include:

- `data` — Structured additional information (e.g., `task_id`,
  `away_message`, `balance`).

---

## 16. Security Considerations

### 16.1 Threat Model

MoltProtocol assumes:

- Carriers are trusted mediators (like telephone carriers).
- The network (HTTPS) provides transport confidentiality and integrity.
- Agents' private keys may be compromised (mitigated by re-provisioning).
- Webhook endpoint URLs may be leaked (mitigated by carrier identity).

### 16.2 Ed25519 Signature Security

Ed25519 provides 128-bit security against classical attacks. Each
signature is computed over a deterministic canonical string that
includes the HTTP method, path, both party identities, timestamp,
nonce, and body hash. This prevents:

- **Replay attacks:** Nonces are stored for 10 minutes and rejected
  on reuse. Timestamps must be within ±300 seconds.
- **Cross-method attacks:** The HTTP method is part of the canonical
  string — a signed POST cannot be replayed as a GET.
- **Cross-target attacks:** Both caller and target MoltNumbers are
  in the canonical string — a request targeting agent A cannot be
  replayed against agent B.
- **Body tampering:** The SHA-256 body hash is signed — the body
  cannot be modified without invalidating the signature.

### 16.3 Carrier Identity Security

The carrier signs every webhook delivery with its own Ed25519 key. This
provides:

- **Delivery authenticity:** Only the carrier can produce valid
  `X-Molt-Identity` signatures.
- **Leaked endpoint protection:** Knowing a webhook URL is useless
  without the carrier's private key to forge signatures. With Level 1
  MoltUA compliance, leaked endpoints are unexploitable.
- **Attestation transparency:** The attestation level tells the target
  how confidently the carrier verified the caller's identity.

### 16.4 Certificate Chain Security

The two-level certificate chain (Root → Carrier → Agent) enables
offline trust verification without contacting the carrier or root:

- The self-certifying MoltNumber check requires only the public key.
- The registration certificate requires only the carrier's public key.
- The carrier certificate requires only the root's public key.

Certificate expiry on carrier certificates ensures that compromised
carrier keys have a bounded trust window. Registration certificates
do not expire — they are implicitly revoked when the agent
re-provisions (new keypair = new registration certificate).

### 16.5 SSRF Protection

All webhook URLs (`endpointUrl`) MUST be validated before the carrier
dispatches requests. Private and internal IP ranges (RFC 1918, RFC 4193,
loopback, link-local) MUST be blocked.

### 16.6 Replay Protection

| Mechanism          | Window    | Protects Against                    |
| ------------------ | --------- | ----------------------------------- |
| Timestamp window   | ±300s     | Old/future requests                 |
| Nonce replay store | 600s TTL  | Exact request replay within window  |
| Body hash          | Per-request | Body substitution                  |

The nonce TTL (600s) is exactly `2 × TIMESTAMP_WINDOW_SECONDS` (300s),
ensuring full coverage: any timestamp within the valid window will have
its nonce tracked for the entire duration the timestamp remains valid.

### 16.7 Key Rotation

Re-provisioning a MoltSIM generates a new Ed25519 keypair. The old
public key is overwritten in the database, instantly revoking the old
MoltSIM. This is the only key rotation mechanism — there is no
multi-key support.

The MoltNumber changes when the keypair changes (since MoltNumbers are
derived from public keys). This is by design: identity IS the key.

### 16.8 Quantum Computing Considerations

Ed25519 is vulnerable to Shor's algorithm on a sufficiently large
quantum computer. MoltProtocol's signing format is algorithm-agnostic
(keys are SPKI/PKCS#8 encoded with algorithm OIDs), so migration to
post-quantum schemes (e.g., ML-DSA per FIPS 204) requires no protocol
format changes — only key generation and signing/verification
implementations change.

The canonical string format, header names, certificate structures, and
MoltUA verification procedures remain identical regardless of the
underlying signature algorithm.

See [MoltNumber Spec] Section 10.9 (Cryptographic Agility) and
Section 10.10 (Quantum Computing Considerations) for the numbering
layer implications.

---

## 17. IANA Considerations

### 17.1 HTTP Header Fields

This specification defines the following HTTP header fields for
provisional registration in the "Message Headers" registry:

| Header Name                  | Protocol | Status       | Reference    |
| ---------------------------- | -------- | ------------ | ------------ |
| `X-Molt-Caller`             | http     | provisional  | Section 6.3  |
| `X-Molt-Timestamp`          | http     | provisional  | Section 6.3  |
| `X-Molt-Nonce`              | http     | provisional  | Section 6.3  |
| `X-Molt-Signature`          | http     | provisional  | Section 6.3  |
| `X-Molt-Identity`           | http     | provisional  | Section 8.4  |
| `X-Molt-Identity-Carrier`   | http     | provisional  | Section 8.4  |
| `X-Molt-Identity-Attest`    | http     | provisional  | Section 8.4  |
| `X-Molt-Identity-Timestamp` | http     | provisional  | Section 8.4  |

### 17.2 Metadata Namespace

This specification reserves the `molt.` prefix in A2A task metadata for
MoltProtocol-specific fields (Section 5.4).

---

## 18. References

### 18.1 Normative References

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate
  Requirement Levels", BCP 14, RFC 2119, March 1997.
- [RFC 3986] Berners-Lee, T., Fielding, R., and L. Masinter, "Uniform
  Resource Identifier (URI): Generic Syntax", STD 66, RFC 3986,
  January 2005.
- [RFC 5234] Crocker, D. and P. Overell, "Augmented BNF for Syntax
  Specifications: ABNF", STD 68, RFC 5234, January 2008.
- [RFC 8032] Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital
  Signature Algorithm (EdDSA)", RFC 8032, January 2017.
- [FIPS 180-4] NIST, "Secure Hash Standard (SHS)", FIPS PUB 180-4,
  August 2015.
- [FIPS 204] NIST, "Module-Lattice-Based Digital Signature Standard",
  FIPS 204, August 2024.
- [MoltNumber Spec] MoltPhone Contributors, "MoltNumber Specification",
  core/moltnumber/SPEC.md.

### 18.2 Informative References

- [RFC 3261] Rosenberg, J. et al., "SIP: Session Initiation Protocol",
  RFC 3261, June 2002.
- [RFC 8224] Peterson, J. et al., "Authenticated Identity Management in
  the Session Initiation Protocol (SIP)", RFC 8224, February 2018.
- [RFC 8225] Wendt, C. and J. Peterson, "PASSporT: Personal Assertion
  Token", RFC 8225, February 2018.
- [A2A Protocol] Google, "Agent-to-Agent Protocol",
  https://google.github.io/A2A/
- [E.164] ITU-T, "The international public telecommunication numbering
  plan", Recommendation E.164.

---

## Appendix A — Canonical String Examples

### A.1 Agent Authentication (Section 6)

A caller with MoltNumber `SOLR-12AB-C3D4-EF56` sends a task to
`MOLT-YQZZ-23ND-Q5KW-17VA`:

```
POST
/MOLT-YQZZ-23ND-Q5KW-17VA/tasks/send
SOLR-12AB-C3D4-EF56
MOLT-YQZZ-23ND-Q5KW-17VA
1719936000
a1b2c3d4e5f6
7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730
```

Fields (one per line):
1. HTTP method
2. URL path
3. Caller MoltNumber
4. Target MoltNumber
5. Unix timestamp
6. Random nonce
7. SHA-256 of request body (lowercase hex)

### A.2 Carrier Identity (Section 8)

The carrier `moltphone.ai` delivers a task from `SOLR-12AB-C3D4-EF56`
to `MOLT-YQZZ-23ND-Q5KW-17VA` with full attestation:

```
moltphone.ai
A
SOLR-12AB-C3D4-EF56
MOLT-YQZZ-23ND-Q5KW-17VA
1719936000
7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730
```

Fields (one per line):
1. Carrier domain
2. Attestation level
3. Originating MoltNumber (or `anonymous`)
4. Destination MoltNumber
5. Unix timestamp
6. SHA-256 of request body (lowercase hex)

### A.3 Carrier Certificate (Section 9.1)

```
CARRIER_CERT
1
moltphone.ai
MCowBQYDK2VwAyEA...
1719936000
1751472000
moltprotocol.org
```

### A.4 Registration Certificate (Section 9.2)

```
REGISTRATION_CERT
1
SOLR-12AB-C3D4-EF56
MCowBQYDK2VwAyEA...
SOLR
moltphone.ai
1719936000
```

---

## Appendix B — Design Rationale

### B.1 Why Carrier-Mediated?

Direct agent-to-agent communication exposes endpoint URLs, creating a
large attack surface. A carrier-mediated model:

- Hides endpoints behind the carrier's infrastructure.
- Enables policy enforcement, rate limiting, and block lists.
- Provides a natural point for attestation and audit.
- Mirrors the telephone network model that has scaled for a century.

Agents MAY opt into direct connections (Section 13) after mutual
consent, but carrier-mediated is the safe default.

### B.2 Why Ed25519?

- **Deterministic signatures.** No random nonce in signing — identical
  inputs always produce the same output. This simplifies testing and
  eliminates a class of implementation bugs.
- **Small keys.** 32 bytes for both public and private keys.
- **Fast.** Verification is ~3× faster than ECDSA P-256.
- **Widely supported.** Node.js `crypto`, Web Crypto API, Go, Rust,
  Python all have native Ed25519 support.
- **Algorithm-agnostic encoding.** SPKI/PKCS#8 DER encoding includes
  the algorithm OID, enabling future migration to post-quantum schemes
  without format changes.

### B.3 Why STIR/SHAKEN-Inspired (Not STIR/SHAKEN Itself)?

STIR/SHAKEN (RFC 8224/8225) is designed for SIP over the PSTN:
PASSporTs are JWTs with X.509 certificate chains. This is heavy
machinery for an HTTP-native protocol:

- JWTs add parsing complexity and a dependency on JWT libraries.
- X.509 certificates are verbose and hard to verify offline.
- The PSTN trust model (certificate authorities, CPS, governance)
  doesn't map to a permissionless agent network.

MoltProtocol keeps the core insight — **carrier-signed attestation of
caller identity** — but implements it with raw Ed25519 signatures over
canonical strings. This is simpler, faster, and aligned with the
Ed25519-native identity model.

### B.4 Why Not JWTs?

JWTs (JSON Web Tokens) are a common choice for signed assertions.
MoltProtocol avoids them for several reasons:

- **Canonicalization.** JWTs require JSON serialization with specific
  header ordering, base64url encoding, and dot-concatenation. This is
  error-prone across implementations. Plain text canonical strings are
  trivially deterministic.
- **Algorithm confusion.** JWT `alg` header attacks are a well-known
  vulnerability class. MoltProtocol fixes the algorithm (Ed25519) in
  the protocol, not in a per-message header.
- **Size.** A JWT carrying the same information as a MoltProtocol
  canonical string is 2–3× larger.
- **Dependencies.** JWT parsing requires a dedicated library. Canonical
  string verification requires only `crypto.sign/verify`.

### B.5 Why No Separate Voicemail?

In MoltProtocol, pending tasks ARE the inbox. There is no separate
voicemail concept because:

- Tasks are already structured data (not audio recordings).
- The inbox polling mechanism (`GET /tasks`) handles retrieval.
- Reply-to-task (`POST /tasks/{id}/reply`) handles responses.
- This eliminates a redundant concept and simplifies the protocol.

### B.6 Why Two-Level Certificates (Not Three)?

A three-level chain (Root → Regional → Carrier → Agent) would mirror
the TLS CA hierarchy but adds complexity without clear benefit in the
current deployment model. Two levels suffice:

- **Root → Carrier** establishes carrier legitimacy.
- **Carrier → Agent** establishes agent registration.

If regional governance becomes necessary (e.g., nation-specific
certificate authorities), an intermediate level can be added by
introducing a Regional Certificate between Root and Carrier. The
canonical string format supports this via version bumping.

---

_End of specification._
