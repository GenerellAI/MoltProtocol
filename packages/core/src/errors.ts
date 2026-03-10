/**
 * MoltProtocol — structured error codes.
 *
 * Inspired by SIP response codes.  These are protocol-level error codes
 * carried inside JSON-RPC 2.0 error objects.  Carriers MUST use these codes
 * for interoperability.
 *
 * The HTTP status code on the response SHOULD match where possible, but
 * the authoritative code is always inside the JSON-RPC error object.
 */

// ── Error code constants ─────────────────────────────────

/** Caller errors (4xx range) */
export const MOLT_BAD_REQUEST = 400;
export const MOLT_AUTH_REQUIRED = 401;
export const MOLT_POLICY_DENIED = 403;
export const MOLT_NOT_FOUND = 404;
export const MOLT_CONFLICT = 409;
export const MOLT_DECOMMISSIONED = 410;
export const MOLT_RATE_LIMITED = 429;

/** Target unavailable (480 range — SIP-inspired) */
export const MOLT_OFFLINE = 480;
export const MOLT_BUSY = 486;
export const MOLT_DND = 487;
export const MOLT_FORWARDING_FAILED = 488;

/** Carrier errors (5xx range) */
export const MOLT_INTERNAL_ERROR = 500;
export const MOLT_WEBHOOK_FAILED = 502;
export const MOLT_WEBHOOK_TIMEOUT = 504;

// ── Error type ───────────────────────────────────────────

/**
 * JSON-RPC 2.0 error object extended with MoltProtocol fields.
 *
 * Shape:
 * ```json
 * {
 *   "jsonrpc": "2.0",
 *   "error": {
 *     "code": 404,
 *     "message": "Number not found",
 *     "data": { "molt_number": "SOLR-AAAA-BBBB-CCCC-DDDD" }
 *   },
 *   "id": null
 * }
 * ```
 */
export interface MoltError {
  /** MoltProtocol error code (matches constants above). */
  code: number;
  /** Human-readable error message. */
  message: string;
  /** Optional structured data with additional context. */
  data?: Record<string, unknown>;
}

// ── Human-readable default messages ──────────────────────

export const ERROR_MESSAGES: Record<number, string> = {
  [MOLT_BAD_REQUEST]: 'Bad request',
  [MOLT_AUTH_REQUIRED]: 'Authentication required',
  [MOLT_POLICY_DENIED]: 'Policy denied',
  [MOLT_NOT_FOUND]: 'Not found',
  [MOLT_CONFLICT]: 'Conflict',
  [MOLT_DECOMMISSIONED]: 'Number decommissioned',
  [MOLT_RATE_LIMITED]: 'Rate limited',
  [MOLT_OFFLINE]: 'Agent offline (task queued)',
  [MOLT_BUSY]: 'Agent busy (task queued)',
  [MOLT_DND]: 'Agent on DND (task queued)',
  [MOLT_FORWARDING_FAILED]: 'Forwarding failed',
  [MOLT_INTERNAL_ERROR]: 'Internal error',
  [MOLT_WEBHOOK_FAILED]: 'Webhook delivery failed',
  [MOLT_WEBHOOK_TIMEOUT]: 'Webhook timed out',
};

// ── Factory helper (protocol-level, no HTTP dependency) ──

/**
 * Create a MoltError object.
 *
 * @param code   One of the MOLT_* constants.
 * @param message  Override the default human-readable message.
 * @param data   Optional structured context.
 */
export function moltError(
  code: number,
  message?: string,
  data?: Record<string, unknown>,
): MoltError {
  return {
    code,
    message: message ?? ERROR_MESSAGES[code] ?? 'Unknown error',
    ...(data ? { data } : {}),
  };
}
