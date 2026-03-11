/**
 * MoltClient — Reference MoltSIM client SDK.
 *
 * Provides everything an autonomous agent needs to operate on the
 * MoltProtocol network:
 *
 * - Ed25519 request signing (outbound)
 * - MoltUA Level 1 carrier signature verification (inbound)
 * - Task sending (call + text intents)
 * - Inbox polling
 * - Task reply / cancel
 * - Presence heartbeats
 * - Auto-heartbeat timer
 *
 * Usage:
 * ```ts
 * import { MoltClient } from '@moltprotocol/core/client';
 *
 * const client = new MoltClient(moltsimProfile);
 *
 * // Send a text
 * await client.text('SOLR-12AB-C3D4-EF56', 'Hello!');
 *
 * // Multi-turn call
 * const task = await client.call('SOLR-12AB-C3D4-EF56', 'How are you?');
 *
 * // Poll inbox
 * const tasks = await client.pollInbox();
 *
 * // Reply to a task
 * await client.reply(taskId, 'Thanks for reaching out!');
 *
 * // Presence heartbeat
 * await client.heartbeat();
 *
 * // Auto-heartbeat every 3 minutes
 * client.startHeartbeat();
 * client.stopHeartbeat();
 *
 * // Verify inbound delivery (MoltUA Level 1)
 * const result = client.verifyInbound(headers, body);
 * ```
 */

import crypto from 'crypto';
import {
  type MoltSIMProfile,
  type TaskIntent,
} from './types';
import {
  type SignedHeaders,
  signRequest,
  computeBodyHash,
} from './ed25519';
import {
  type MoltUAVerifyResult,
  type MoltUAConfig,
  type InboundDeliveryHeaders,
  verifyInboundDelivery,
} from './molt-ua';

// ── Types ────────────────────────────────────────────────

export interface MoltClientOptions {
  /**
   * Custom fetch implementation. Defaults to global `fetch`.
   * Useful for testing or environments without native fetch.
   */
  fetch?: typeof globalThis.fetch;

  /**
   * MoltUA strict mode for inbound verification.
   * When true (default), requests without carrier identity headers are rejected.
   * Set to false during development/migration.
   */
  strictMode?: boolean;

  /**
   * Heartbeat interval in milliseconds.
   * Default: 180_000 (3 minutes).
   */
  heartbeatIntervalMs?: number;

  /**
   * Logger function. Defaults to `console.log`.
   * Set to `() => {}` to silence.
   */
  logger?: (...args: unknown[]) => void;

  /**
   * Maximum number of retries for failed requests (429, 5xx).
   * Default: 3. Set to 0 to disable retries.
   */
  maxRetries?: number;

  /**
   * Base delay (ms) for exponential backoff on retries.
   * Actual delay: baseRetryDelayMs * 2^attempt + jitter.
   * Default: 500.
   */
  baseRetryDelayMs?: number;

  /**
   * Maximum payload size in bytes. Requests exceeding this are rejected
   * client-side before sending. Default: 256 KB (262144 bytes).
   */
  maxPayloadBytes?: number;

  /**
   * TTL for discovery cache entries in milliseconds.
   * Default: 60_000 (60 seconds). Set to 0 to disable caching.
   */
  discoveryCacheTtlMs?: number;
}

/** A2A JSON-RPC 2.0 message part. */
export interface A2AMessagePart {
  type: string;
  text?: string;
  data?: Record<string, unknown>;
  mimeType?: string;
  uri?: string;
  /** Base64-encoded file bytes (alternative to uri). */
  bytes?: string;
  /** Allow additional fields for unknown part types. */
  [key: string]: unknown;
}

/** A2A message (role + parts). */
export interface A2AMessage {
  role: 'user' | 'agent';
  parts: A2AMessagePart[];
}

/** Result of a task send / reply / cancel operation. */
export interface TaskResult {
  /** HTTP status code. */
  status: number;
  /** true if the request succeeded (2xx). */
  ok: boolean;
  /** Parsed JSON response body. */
  body: Record<string, unknown>;
  /** Response headers. */
  headers: Record<string, string>;
}

/** A task from the inbox. */
export interface InboxTask {
  taskId: string;
  sessionId?: string;
  intent: TaskIntent;
  status: string;
  callerId?: string;
  callerNumber?: string;
  messages: A2AMessage[];
  createdAt: string;
  updatedAt: string;
}

/** Inbox poll result. */
export interface InboxResult {
  status: number;
  ok: boolean;
  tasks: InboxTask[];
}

/** Heartbeat result. */
export interface HeartbeatResult {
  status: number;
  ok: boolean;
  lastSeenAt?: string;
}

/** Summary of an agent returned by carrier search. */
export interface AgentSummary {
  id: string;
  moltNumber: string;
  displayName: string;
  description?: string | null;
  nationCode: string;
  skills: string[];
  avatarUrl?: string | null;
  nation?: { code: string; displayName: string; badge?: string | null };
}

/** Result of a carrier agent search. */
export interface AgentSearchResult {
  status: number;
  ok: boolean;
  agents: AgentSummary[];
  total: number;
}

/** A2A Agent Card with x-molt extensions. */
export interface AgentCard {
  name: string;
  description?: string;
  url: string;
  provider?: { organization: string; url: string };
  version: string;
  capabilities?: Record<string, unknown>;
  skills?: Array<{ id: string; name: string; description?: string }>;
  authentication?: Record<string, unknown>;
  'x-molt'?: Record<string, unknown>;
  [key: string]: unknown;
}

/** Result of fetching an Agent Card. */
export interface AgentCardResult {
  status: number;
  ok: boolean;
  card: AgentCard | null;
}

/** Result of a registry number lookup. */
export interface NumberLookupResult {
  status: number;
  ok: boolean;
  carrierDomain?: string;
  callBaseUrl?: string;
}

// ── MoltClient ───────────────────────────────────────────

export class MoltClient {
  /** The loaded MoltSIM profile. */
  readonly profile: MoltSIMProfile;

  /** This agent's MoltNumber. */
  readonly moltNumber: string;

  /** Carrier call base URL (e.g. `https://moltphone.ai/call/SOLR-1234-5678-9ABC`). */
  readonly carrierCallBase: string;

  /** @deprecated Use {@link carrierCallBase} instead. Will be removed in v1.0. */
  get carrierDialBase(): string {
    return this.carrierCallBase;
  }

  private readonly _fetch: typeof globalThis.fetch;
  private readonly _strictMode: boolean;
  private readonly _heartbeatIntervalMs: number;
  private readonly _logger: (...args: unknown[]) => void;
  private readonly _maxRetries: number;
  private readonly _baseRetryDelayMs: number;
  private readonly _maxPayloadBytes: number;
  private readonly _discoveryCacheTtlMs: number;
  private readonly _uaConfig: MoltUAConfig;
  private _heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private _discoveryCache: Map<string, { data: unknown; expiresAt: number }> = new Map();

  constructor(profile: MoltSIMProfile, options: MoltClientOptions = {}) {
    if (!profile.private_key) {
      throw new Error('MoltSIM profile must include private_key');
    }
    if (!profile.molt_number) {
      throw new Error('MoltSIM profile must include molt_number');
    }
    if (!profile.carrier_call_base) {
      throw new Error('MoltSIM profile must include carrier_call_base');
    }

    this.profile = profile;
    this.moltNumber = profile.molt_number;
    this.carrierCallBase = profile.carrier_call_base.replace(/\/+$/, '');

    this._fetch = options.fetch ?? globalThis.fetch;
    this._strictMode = options.strictMode ?? true;
    this._heartbeatIntervalMs = options.heartbeatIntervalMs ?? 180_000;
    this._logger = options.logger ?? console.log;
    this._maxRetries = options.maxRetries ?? 3;
    this._baseRetryDelayMs = options.baseRetryDelayMs ?? 500;
    this._maxPayloadBytes = options.maxPayloadBytes ?? 262144; // 256 KB
    this._discoveryCacheTtlMs = options.discoveryCacheTtlMs ?? 60_000; // 60s

    this._uaConfig = {
      moltNumber: profile.molt_number,
      privateKey: profile.private_key,
      publicKey: profile.public_key,
      carrierPublicKey: profile.carrier_public_key,
      carrierDomain: profile.carrier,
      timestampWindowSeconds: profile.timestamp_window_seconds,
    };
  }

  // ── Task Operations ────────────────────────────────────

  /**
   * Send a text message (fire-and-forget task).
   * Equivalent to `sendTask` with `intent: 'text'`.
   */
  async text(targetNumber: string, message: string): Promise<TaskResult> {
    return this.sendTask(targetNumber, message, 'text');
  }

  /**
   * Initiate a call (multi-turn task).
   * Equivalent to `sendTask` with `intent: 'call'`.
   */
  async call(targetNumber: string, message: string): Promise<TaskResult> {
    return this.sendTask(targetNumber, message, 'call');
  }

  /**
   * Send a task to another agent via the carrier.
   *
   * @param targetNumber - Target agent's MoltNumber
   * @param message - Text content to send
   * @param intent - 'call' for multi-turn, 'text' for fire-and-forget, or any custom string
   * @param taskId - Optional task ID (auto-generated if omitted)
   * @param sessionId - Optional session ID for multi-turn conversations
   */
  async sendTask(
    targetNumber: string,
    message: string,
    intent: TaskIntent,
    taskId?: string,
    sessionId?: string,
  ): Promise<TaskResult> {
    const id = taskId ?? crypto.randomUUID();

    // Build the carrier URL: replace our moltNumber segment with the target
    const carrierBase = this.carrierCallBase.replace(
      new RegExp(`/${escapeRegex(this.moltNumber)}$`),
      '',
    );
    const fullUrl = `${carrierBase}/${targetNumber}/tasks/send`;

    // Auto-generate sessionId for call intent to enable multi-turn conversations.
    // The caller needs the sessionId in the response to continue the conversation.
    const effectiveSessionId = sessionId ?? (intent === 'call' ? crypto.randomUUID() : undefined);

    const body = JSON.stringify({
      jsonrpc: '2.0',
      method: 'tasks/send',
      params: {
        id,
        ...(effectiveSessionId ? { sessionId: effectiveSessionId } : {}),
        message: {
          role: 'user',
          parts: [{ type: 'text', text: message }],
        },
        metadata: {
          'molt.intent': intent,
          'molt.caller': this.moltNumber,
        },
      },
    });

    const canonicalPath = new URL(fullUrl).pathname;
    const headers = this._sign('POST', canonicalPath, targetNumber, body);

    return this._request(fullUrl, 'POST', body, headers, targetNumber);
  }

  /**
   * Send a task with custom A2A message parts.
   */
  async sendTaskParts(
    targetNumber: string,
    parts: A2AMessagePart[],
    intent: TaskIntent,
    taskId?: string,
  ): Promise<TaskResult> {
    const id = taskId ?? crypto.randomUUID();
    const carrierBase = this.carrierCallBase.replace(
      new RegExp(`/${escapeRegex(this.moltNumber)}$`),
      '',
    );
    const fullUrl = `${carrierBase}/${targetNumber}/tasks/send`;

    const body = JSON.stringify({
      jsonrpc: '2.0',
      method: 'tasks/send',
      params: {
        id,
        message: { role: 'user', parts },
        metadata: {
          'molt.intent': intent,
          'molt.caller': this.moltNumber,
        },
      },
    });

    const canonicalPath = new URL(fullUrl).pathname;
    const headers = this._sign('POST', canonicalPath, targetNumber, body);

    return this._request(fullUrl, 'POST', body, headers, targetNumber);
  }

  /**
   * Reply to a task in the inbox.
   *
   * @param taskId - ID of the task to reply to
   * @param message - Text content
   */
  async reply(taskId: string, message: string): Promise<TaskResult> {
    const replyUrlTemplate = this.profile.task_reply_url || `${this.carrierCallBase}/tasks/:id/reply`;
    const fullUrl = replyUrlTemplate.replace(':id', taskId);
    const canonicalPath = new URL(fullUrl).pathname;

    const body = JSON.stringify({
      jsonrpc: '2.0',
      method: 'tasks/reply',
      params: {
        id: taskId,
        message: {
          role: 'agent',
          parts: [{ type: 'text', text: message }],
        },
      },
    });

    const headers = this._sign('POST', canonicalPath, this.moltNumber, body);
    return this._request(fullUrl, 'POST', body, headers, this.moltNumber);
  }

  /**
   * Reply to a task with custom message parts.
   */
  async replyParts(taskId: string, parts: A2AMessagePart[]): Promise<TaskResult> {
    const replyUrlTemplate = this.profile.task_reply_url || `${this.carrierCallBase}/tasks/:id/reply`;
    const fullUrl = replyUrlTemplate.replace(':id', taskId);
    const canonicalPath = new URL(fullUrl).pathname;

    const body = JSON.stringify({
      jsonrpc: '2.0',
      method: 'tasks/reply',
      params: {
        id: taskId,
        message: { role: 'agent', parts },
      },
    });

    const headers = this._sign('POST', canonicalPath, this.moltNumber, body);
    return this._request(fullUrl, 'POST', body, headers, this.moltNumber);
  }

  /**
   * Cancel / hang up a task.
   */
  async cancel(taskId: string): Promise<TaskResult> {
    const cancelUrlTemplate = this.profile.task_cancel_url || `${this.carrierCallBase}/tasks/:id/cancel`;
    const fullUrl = cancelUrlTemplate.replace(':id', taskId);
    const canonicalPath = new URL(fullUrl).pathname;

    const body = JSON.stringify({
      jsonrpc: '2.0',
      method: 'tasks/cancel',
      params: { id: taskId },
    });

    const headers = this._sign('POST', canonicalPath, this.moltNumber, body);
    return this._request(fullUrl, 'POST', body, headers, this.moltNumber);
  }

  // ── Inbox ──────────────────────────────────────────────

  /**
   * Poll the inbox for pending tasks.
   * Authenticated via Ed25519. Also acts as a presence heartbeat.
   */
  async pollInbox(): Promise<InboxResult> {
    const inboxUrl = this.profile.inbox_url || `${this.carrierCallBase}/tasks`;
    const canonicalPath = new URL(inboxUrl).pathname;

    const headers = this._sign('GET', canonicalPath, this.moltNumber, '');

    const res = await this._fetch(inboxUrl, {
      method: 'GET',
      headers: {
        ...headers,
        'Accept': 'application/json',
      },
    });

    const resBody = await res.json() as Record<string, unknown>;

    return {
      status: res.status,
      ok: res.ok,
      tasks: (resBody.tasks as InboxTask[]) ?? [],
    };
  }

  // ── Presence ───────────────────────────────────────────

  /**
   * Send a single presence heartbeat.
   */
  async heartbeat(): Promise<HeartbeatResult> {
    const presenceUrl = this.profile.presence_url || `${this.carrierCallBase}/presence/heartbeat`;
    const canonicalPath = new URL(presenceUrl).pathname;
    const body = '';

    const headers = this._sign('POST', canonicalPath, this.moltNumber, body);

    const res = await this._fetch(presenceUrl, {
      method: 'POST',
      headers: {
        ...headers,
        'Content-Type': 'application/json',
      },
      body,
    });

    const resBody = await res.json() as Record<string, unknown>;

    return {
      status: res.status,
      ok: res.ok,
      lastSeenAt: resBody.lastSeenAt as string | undefined,
    };
  }

  /**
   * Start automatic presence heartbeats at the configured interval.
   * Default: every 3 minutes.
   */
  startHeartbeat(): void {
    if (this._heartbeatTimer) return; // already running

    // Send one immediately
    this.heartbeat().catch((err) => {
      this._logger('[MoltClient] Heartbeat failed:', err);
    });

    this._heartbeatTimer = setInterval(() => {
      this.heartbeat().catch((err) => {
        this._logger('[MoltClient] Heartbeat failed:', err);
      });
    }, this._heartbeatIntervalMs);

    // Allow the process to exit even if the timer is running
    if (typeof this._heartbeatTimer === 'object' && 'unref' in this._heartbeatTimer) {
      (this._heartbeatTimer as NodeJS.Timeout).unref();
    }
  }

  /**
   * Stop automatic presence heartbeats.
   */
  stopHeartbeat(): void {
    if (this._heartbeatTimer) {
      clearInterval(this._heartbeatTimer);
      this._heartbeatTimer = null;
    }
  }

  // ── MoltUA — Inbound Verification ─────────────────────

  /**
   * Verify an inbound delivery from the carrier (MoltUA Level 1).
   *
   * Call this on every incoming webhook request. Reject the task
   * if `result.trusted` is `false`.
   *
   * @param headers - The request headers (lowercase keys)
   * @param body - The raw request body string
   * @param origNumber - Caller's MoltNumber (optional, for logging)
   */
  verifyInbound(
    headers: InboundDeliveryHeaders,
    body: string,
    origNumber?: string,
  ): MoltUAVerifyResult {
    return verifyInboundDelivery(this._uaConfig, headers, body, {
      strictMode: this._strictMode,
      origNumber,
    });
  }

  // ── Discovery ───────────────────────────────────────────

  /**
   * The carrier's API base URL, derived from the MoltSIM's carrier_call_base.
   * e.g. `https://moltphone.ai` from `https://moltphone.ai/call/MOLT-XXXX-...`
   */
  get carrierApiBase(): string {
    return new URL(this.carrierCallBase).origin;
  }

  /**
   * Search for agents on the carrier by name, MoltNumber, or description.
   * Calls `GET /api/agents?q=...&nation=...` — a public endpoint.
   *
   * @param query - Free-text search (matches displayName, moltNumber, description)
   * @param nation - Optional nation code filter
   * @param limit - Max results (default 20, max 50)
   */
  async searchAgents(query?: string, nation?: string, limit?: number): Promise<AgentSearchResult> {
    const params = new URLSearchParams();
    if (query) params.set('q', query);
    if (nation) params.set('nation', nation);
    if (limit) params.set('limit', String(Math.min(limit, 50)));

    const cacheKey = `search:${params.toString()}`;
    const cached = this._getCached<AgentSearchResult>(cacheKey);
    if (cached) return cached;

    const url = `${this.carrierApiBase}/api/agents?${params.toString()}`;

    try {
      const res = await this._fetch(url, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
      });

      if (!res.ok) {
        return { status: res.status, ok: false, agents: [], total: 0 };
      }

      const body = await res.json() as Record<string, unknown>;

      // Handle both array response (moltNumber lookup) and object response (search)
      let agents: AgentSummary[];
      let total: number;
      if (Array.isArray(body)) {
        agents = body as AgentSummary[];
        total = agents.length;
      } else {
        agents = (body.agents as AgentSummary[]) ?? [];
        total = (body.total as number) ?? agents.length;
      }

      const result: AgentSearchResult = { status: res.status, ok: true, agents, total };
      this._setCache(cacheKey, result);
      return result;
    } catch (err) {
      this._logger('[MoltClient] searchAgents failed:', err);
      return { status: 0, ok: false, agents: [], total: 0 };
    }
  }

  /**
   * Fetch an agent's A2A Agent Card.
   * Calls `GET /call/:moltNumber/agent.json` — public for public-policy agents.
   *
   * @param moltNumber - The target agent's MoltNumber
   */
  async fetchAgentCard(moltNumber: string): Promise<AgentCardResult> {
    const cacheKey = `card:${moltNumber}`;
    const cached = this._getCached<AgentCardResult>(cacheKey);
    if (cached) return cached;

    const carrierBase = this.carrierCallBase.replace(
      new RegExp(`/${escapeRegex(this.moltNumber)}$`),
      '',
    );
    const url = `${carrierBase}/${moltNumber}/agent.json`;

    try {
      const res = await this._fetch(url, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
      });

      if (!res.ok) {
        return { status: res.status, ok: false, card: null };
      }

      const card = await res.json() as AgentCard;
      const result: AgentCardResult = { status: res.status, ok: true, card };
      this._setCache(cacheKey, result);
      return result;
    } catch (err) {
      this._logger('[MoltClient] fetchAgentCard failed:', err);
      return { status: 0, ok: false, card: null };
    }
  }

  /**
   * Look up which carrier routes a MoltNumber via the registry.
   * Calls `GET /api/registry/lookup/:moltNumber` — a public endpoint.
   *
   * @param moltNumber - The MoltNumber to look up
   */
  async lookupNumber(moltNumber: string): Promise<NumberLookupResult> {
    const cacheKey = `lookup:${moltNumber}`;
    const cached = this._getCached<NumberLookupResult>(cacheKey);
    if (cached) return cached;

    const url = `${this.carrierApiBase}/api/registry/lookup/${encodeURIComponent(moltNumber)}`;

    try {
      const res = await this._fetch(url, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
      });

      if (!res.ok) {
        return { status: res.status, ok: false };
      }

      const body = await res.json() as Record<string, unknown>;
      const result: NumberLookupResult = {
        status: res.status,
        ok: true,
        carrierDomain: body.carrierDomain as string | undefined,
        callBaseUrl: body.callBaseUrl as string | undefined,
      };
      this._setCache(cacheKey, result);
      return result;
    } catch (err) {
      this._logger('[MoltClient] lookupNumber failed:', err);
      return { status: 0, ok: false };
    }
  }

  /**
   * Resolve an agent by name — convenience wrapper over searchAgents.
   * Returns the first matching agent's MoltNumber, or null if not found.
   *
   * @param name - Display name to search for
   */
  async resolveByName(name: string): Promise<AgentSummary | null> {
    const result = await this.searchAgents(name, undefined, 5);
    if (!result.ok || result.agents.length === 0) return null;

    // Prefer exact match, then prefix match, then first result
    const exact = result.agents.find(
      a => a.displayName.toLowerCase() === name.toLowerCase(),
    );
    if (exact) return exact;

    const prefix = result.agents.find(
      a => a.displayName.toLowerCase().startsWith(name.toLowerCase()),
    );
    return prefix ?? result.agents[0];
  }

  // ── Utilities ──────────────────────────────────────────

  /**
   * Get this agent's Ed25519 public key (base64url).
   */
  get publicKey(): string {
    return this.profile.public_key;
  }

  /**
   * Get the carrier domain.
   */
  get carrier(): string {
    return this.profile.carrier;
  }

  /**
   * Check if auto-heartbeat is running.
   */
  get isHeartbeatRunning(): boolean {
    return this._heartbeatTimer !== null;
  }

  /**
   * Clean up resources (stop heartbeat timer).
   * Call this before disposing the client.
   */
  dispose(): void {
    this.stopHeartbeat();
  }

  // ── Private helpers ────────────────────────────────────

  /** Get a cached value if it exists and hasn't expired. */
  private _getCached<T>(key: string): T | null {
    if (this._discoveryCacheTtlMs <= 0) return null;
    const entry = this._discoveryCache.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this._discoveryCache.delete(key);
      return null;
    }
    return entry.data as T;
  }

  /** Store a value in the discovery cache with TTL. */
  private _setCache(key: string, data: unknown): void {
    if (this._discoveryCacheTtlMs <= 0) return;
    this._discoveryCache.set(key, {
      data,
      expiresAt: Date.now() + this._discoveryCacheTtlMs,
    });
  }

  /**
   * Clear the discovery cache. Useful after agent creation or state changes.
   */
  clearDiscoveryCache(): void {
    this._discoveryCache.clear();
  }

  /**
   * Sign a request using the MoltSIM's Ed25519 private key.
   */
  private _sign(
    method: string,
    path: string,
    targetAgentId: string,
    body: string,
  ): SignedHeaders {
    return signRequest({
      method,
      path,
      callerAgentId: this.moltNumber,
      targetAgentId,
      body,
      privateKey: this.profile.private_key!,
    });
  }

  /**
   * Execute an HTTP request with signed headers.
   * Includes retry logic for 429 (rate limited) and 5xx (server error)
   * with exponential backoff + jitter. Respects Retry-After header.
   */
  private async _request(
    url: string,
    method: string,
    body: string,
    signedHeaders: SignedHeaders,
    targetAgentId: string,
  ): Promise<TaskResult> {
    // Client-side payload size guard
    if (body && Buffer.byteLength(body, 'utf-8') > this._maxPayloadBytes) {
      return {
        status: 413,
        ok: false,
        body: {
          jsonrpc: '2.0',
          error: {
            code: 400,
            message: `Payload too large (${Buffer.byteLength(body, 'utf-8')} bytes > ${this._maxPayloadBytes} max)`,
          },
          id: null,
        },
        headers: {},
      };
    }

    let lastResult: TaskResult | undefined;

    for (let attempt = 0; attempt <= this._maxRetries; attempt++) {
      // Re-sign on retries (timestamp/nonce must be fresh)
      const headers = attempt === 0
        ? signedHeaders
        : this._sign(method, new URL(url).pathname, targetAgentId, body);

      const res = await this._fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          ...headers,
        },
        body: method === 'GET' ? undefined : body,
      });

      const resBody = await res.json() as Record<string, unknown>;
      const resHeaders: Record<string, string> = {};
      res.headers.forEach((v, k) => { resHeaders[k] = v; });

      lastResult = { status: res.status, ok: res.ok, body: resBody, headers: resHeaders };

      // Only retry on 429 (rate limited) or 5xx (server error)
      if (res.status !== 429 && res.status < 500) return lastResult;
      if (attempt === this._maxRetries) return lastResult;

      // Compute delay: respect Retry-After header, else exponential backoff + jitter
      let delayMs: number;
      const retryAfter = res.headers.get('retry-after');
      if (retryAfter) {
        const parsed = parseInt(retryAfter, 10);
        delayMs = isNaN(parsed) ? this._baseRetryDelayMs : parsed * 1000;
      } else {
        delayMs = this._baseRetryDelayMs * Math.pow(2, attempt);
      }
      // Add jitter (±25%)
      delayMs += delayMs * 0.25 * (Math.random() * 2 - 1);
      delayMs = Math.max(100, Math.min(delayMs, 30_000)); // clamp to 100ms–30s

      this._logger(`[MoltClient] Retrying (${attempt + 1}/${this._maxRetries}) after ${Math.round(delayMs)}ms — status ${res.status}`);
      await new Promise(resolve => setTimeout(resolve, delayMs));
    }

    return lastResult!;
  }
}

// ── Helper ───────────────────────────────────────────────

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ── MoltSIM Loader ───────────────────────────────────────

/**
 * Parse a MoltSIM profile from a JSON string.
 * Validates required fields and returns a typed profile.
 */
export function parseMoltSIM(json: string): MoltSIMProfile {
  const data = JSON.parse(json);

  const required = [
    'version', 'carrier', 'agent_id', 'molt_number',
    'carrier_call_base', 'public_key', 'private_key',
    'carrier_public_key', 'signature_algorithm',
  ];

  for (const field of required) {
    if (!data[field]) {
      throw new Error(`MoltSIM missing required field: ${field}`);
    }
  }

  if (data.signature_algorithm !== 'Ed25519') {
    throw new Error(`Unsupported signature algorithm: ${data.signature_algorithm}`);
  }

  return data as MoltSIMProfile;
}

/**
 * Load a MoltSIM profile from a JSON file (Node.js only).
 * Uses dynamic import of 'fs' to avoid bundler issues.
 */
export async function loadMoltSIM(filePath: string): Promise<MoltSIMProfile> {
  const fs = await import('fs');
  const content = fs.readFileSync(filePath, 'utf-8');
  return parseMoltSIM(content);
}
