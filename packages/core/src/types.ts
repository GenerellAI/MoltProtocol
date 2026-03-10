/**
 * MoltProtocol — core protocol types.
 *
 * MoltProtocol is the telephony layer that sits on top of A2A, like SIP sits
 * on top of TCP/IP.  It defines how agents are addressed, authenticated, and
 * routed in a carrier-mediated network.
 *
 * Stack: A2A (generic agent transport) → MoltProtocol (telephony semantics)
 *        → MoltPhone (one carrier implementing MoltProtocol)
 *
 * This file defines ONLY the open-standard types.  Carrier-specific
 * implementation lives in the carrier codebase (moltphone.ai), which imports
 * from here.  This package NEVER imports from the carrier.
 */

// ── Intent ───────────────────────────────────────────────

/** The intent of a task.  `call` = multi-turn, `text` = fire-and-forget. */
export type TaskIntent = 'call' | 'text';

// ── Task status (A2A states) ─────────────────────────────

/** A2A-aligned task lifecycle states. */
export type TaskStatus =
  | 'submitted'     // ringing / queued
  | 'working'       // connected / in-progress
  | 'input-required' // callee's turn to respond
  | 'completed'     // hung up / done
  | 'canceled'      // caller hung up
  | 'failed';       // error

// ── Message parts ────────────────────────────────────────

export interface TextPart {
  type: 'text';
  text: string;
}

export interface DataPart {
  type: 'data';
  data: Record<string, unknown>;
}

export interface FilePart {
  type: 'file';
  mimeType: string;
  uri: string;
}

export type MessagePart = TextPart | DataPart | FilePart;

// ── molt.* metadata namespace ────────────────────────────

/**
 * Protocol-level metadata carried in every A2A request.
 * All fields are optional at the type level; individual endpoints enforce
 * which fields are required.
 */
export interface MoltMetadata {
  /** Caller's MoltNumber. */
  'molt.caller'?: string;
  /** Ed25519 signature of the canonical string, base64url-encoded. */
  'molt.signature'?: string;
  /** Task intent. */
  'molt.intent'?: TaskIntent;
  /** Number of forwarding hops so far. */
  'molt.forwarding_hops'?: number;
  /** Propose direct connection upgrade. */
  'molt.propose_direct'?: boolean;
  /** Accept direct connection upgrade. */
  'molt.accept_direct'?: boolean;
  /** One-time upgrade token (returned with molt.accept_direct). */
  'molt.upgrade_token'?: string;

  // ── Carrier Identity (STIR/SHAKEN-inspired, RFC 8224) ──

  /** Carrier identity signature (base64url Ed25519). Set by carrier on delivery. */
  'molt.identity'?: string;
  /** Carrier domain that signed the delivery. */
  'molt.identity.carrier'?: string;
  /** Attestation level: A (full), B (partial), C (gateway). STIR/SHAKEN §4. */
  'molt.identity.attest'?: 'A' | 'B' | 'C';

  /** Carrier may include additional metadata under its own namespace. */
  [key: string]: unknown;
}

// ── Direct connection policy ─────────────────────────────

export type DirectConnectionPolicy =
  | 'direct_on_consent' // default — upgrade after mutual consent
  | 'direct_on_accept'  // upgrade automatically on first accept
  | 'carrier_only';     // never upgrade; always relay through carrier

// ── Agent Card x-molt extensions ────────────────────────

/**
 * `x-molt` extension block embedded in a standard A2A Agent Card.
 * Carrier-neutral; defined by MoltProtocol.
 */
export interface XMoltExtension {
  /** MoltNumber of this agent. */
  molt_number: string;
  /** Nation code. */
  nation: string;
  /** Nation type — trust-relevant signal for verifiers. */
  nation_type: 'carrier' | 'org' | 'open';
  /** Ed25519 public key (base64url). */
  public_key: string;
  /** Timestamp window for signature verification (seconds). */
  timestamp_window_seconds: number;
  /** Inbound policy. */
  inbound_policy: 'public' | 'registered_only' | 'allowlist';
  /** Direct connection policy. */
  direct_connection_policy: DirectConnectionPolicy;
  /** Registration certificate — proves carrier registered this agent. */
  registration_certificate?: RegistrationCertificateJSON;
  /** URL to the carrier's certificate (root-signed). */
  carrier_certificate_url?: string;
  /** URL to fetch this agent's Lexicon Pack (terminology dictionary). */
  lexicon_url?: string;
  /** Delegation certificate — proves nation owner authorized this carrier (org/carrier nations). */
  delegation_certificate?: DelegationCertificateJSON;
  /** Previous MoltNumbers held by this agent, for identity continuity after porting or key rotation. */
  previous_numbers?: string[];
}

// ── MoltSIM profile type ─────────────────────────────────

/**
 * MoltSIM profile — machine-readable credential for autonomous agents.
 * Contains everything a MoltUA needs to operate: carrier endpoints,
 * Ed25519 keypair, and carrier public key for delivery verification.
 */
export interface MoltSIMProfile {
  version: string;
  carrier: string;
  agent_id: string;
  molt_number: string;
  /** Nation type of the agent's nation (carrier/org/open). */
  nation_type: 'carrier' | 'org' | 'open';
  carrier_call_base: string;
  inbox_url: string;
  task_reply_url: string;
  task_cancel_url: string;
  presence_url: string;
  public_key: string;
  private_key?: string; // Only present on initial provisioning (shown once)
  /** Carrier's Ed25519 public key for verifying X-Molt-Identity signatures. */
  carrier_public_key: string;
  signature_algorithm: 'Ed25519';
  canonical_string: string;
  timestamp_window_seconds: number;
  /** Registration certificate — carrier's signature proving this agent was registered. */
  registration_certificate?: RegistrationCertificateJSON;
  /** Carrier certificate — root authority's signature proving this carrier is authorized. */
  carrier_certificate?: CarrierCertificateJSON;
}

/** JSON-serializable carrier certificate (root → carrier). */
export interface CarrierCertificateJSON {
  version: '1';
  carrier_domain: string;
  carrier_public_key: string;
  issued_at: number;
  expires_at: number;
  issuer: string;
  signature: string;
}

/** JSON-serializable registration certificate (carrier → agent). */
export interface RegistrationCertificateJSON {
  version: '1';
  molt_number: string;
  agent_public_key: string;
  nation_code: string;
  carrier_domain: string;
  issued_at: number;
  signature: string;
}

/** JSON-serializable delegation certificate (nation → carrier). */
export interface DelegationCertificateJSON {
  version: '1';
  nation_code: string;
  nation_public_key: string;
  carrier_domain: string;
  carrier_public_key: string;
  issued_at: number;
  expires_at?: number;
  signature: string;
}

// ── Carrier routing protocol constants ──────────────────

/** Maximum number of forwarding hops before failing. */
export const MAX_FORWARDING_HOPS = 3;

/** Timestamp tolerance window for signature verification (seconds). */
export const TIMESTAMP_WINDOW_SECONDS = 300;
