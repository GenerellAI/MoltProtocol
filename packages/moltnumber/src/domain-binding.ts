/**
 * MoltNumber canonical domain binding.
 *
 * Two supported verification methods for binding a MoltNumber to a domain:
 *
 * 1. HTTP Well-Known:
 *    https://<domain>/.well-known/moltnumber.txt
 *    File format:
 *      moltnumber: <AGENT_NUMBER>
 *      token: <RANDOM_TOKEN>
 *
 * 2. DNS TXT:
 *    _moltnumber.<domain>  TXT  "moltnumber=<AGENT_NUMBER> token=<RANDOM_TOKEN>"
 *
 * This module is part of the MoltNumber spec and MUST NOT depend on MoltPhone.
 */

import crypto from 'crypto';
import { Resolver } from 'dns/promises';

// ── Token generation ────────────────────────────────────

export function generateDomainClaimToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

// ── Well-known URL construction ─────────────────────────

export function buildWellKnownUrl(domain: string): string {
  const clean = domain.replace(/^https?:\/\//, '').replace(/\/+$/, '');
  return `https://${clean}/.well-known/moltnumber.txt`;
}

// ── Parser ──────────────────────────────────────────────

export interface WellKnownFileContents {
  moltnumber: string | null;
  token: string | null;
}

export function parseWellKnownFile(body: string): WellKnownFileContents {
  const result: WellKnownFileContents = { moltnumber: null, token: null };
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    const mnMatch = trimmed.match(/^moltnumber:\s*(.+)$/i);
    if (mnMatch) {
      result.moltnumber = mnMatch[1].trim();
      continue;
    }
    const tkMatch = trimmed.match(/^token:\s*(.+)$/i);
    if (tkMatch) {
      result.token = tkMatch[1].trim();
    }
  }
  return result;
}

// ── Claim validation ────────────────────────────────────

export interface DomainClaimResult {
  valid: boolean;
  reason?: string;
}

/**
 * Validate that a fetched well-known file matches the expected MoltNumber
 * and pending claim token.
 */
export function validateDomainClaim(
  fileBody: string,
  expectedMoltNumber: string,
  expectedToken: string,
): DomainClaimResult {
  const parsed = parseWellKnownFile(fileBody);

  if (!parsed.moltnumber) {
    return { valid: false, reason: 'Missing moltnumber field' };
  }
  if (!parsed.token) {
    return { valid: false, reason: 'Missing token field' };
  }
  if (parsed.moltnumber !== expectedMoltNumber) {
    return { valid: false, reason: 'MoltNumber mismatch' };
  }
  if (parsed.token !== expectedToken) {
    return { valid: false, reason: 'Token mismatch' };
  }

  return { valid: true };
}

// ── DNS TXT verification ────────────────────────────────

/**
 * Parse a DNS TXT record value for domain binding.
 * Expected format: "moltnumber=<NUMBER> token=<TOKEN>"
 */
export function parseDnsTxtRecord(txt: string): WellKnownFileContents {
  const result: WellKnownFileContents = { moltnumber: null, token: null };
  const mnMatch = txt.match(/moltnumber=(\S+)/i);
  if (mnMatch) result.moltnumber = mnMatch[1];
  const tkMatch = txt.match(/token=(\S+)/i);
  if (tkMatch) result.token = tkMatch[1];
  return result;
}

/**
 * Resolve the _moltnumber.<domain> TXT record and validate the claim.
 *
 * @param domain            Target domain (e.g. "example.com")
 * @param expectedMoltNumber The agent's MoltNumber
 * @param expectedToken     The pending claim token
 * @param timeoutMs         DNS resolver timeout (default 5000ms)
 */
export async function validateDomainClaimDns(
  domain: string,
  expectedMoltNumber: string,
  expectedToken: string,
  timeoutMs = 5000,
): Promise<DomainClaimResult> {
  const resolver = new Resolver();
  resolver.setServers(['8.8.8.8', '1.1.1.1']);

  const hostname = `_moltnumber.${domain}`;

  let records: string[][];
  try {
    const timer = setTimeout(() => resolver.cancel(), timeoutMs);
    records = await resolver.resolveTxt(hostname);
    clearTimeout(timer);
  } catch (err: unknown) {
    const code = (err as { code?: string }).code;
    if (code === 'ENODATA' || code === 'ENOTFOUND') {
      return { valid: false, reason: `No TXT record found at ${hostname}` };
    }
    return { valid: false, reason: `DNS error: ${code ?? 'unknown'}` };
  }

  // TXT records come as arrays of chunks (one record = [chunk1, chunk2, ...])
  for (const chunks of records) {
    const txt = chunks.join('');
    const parsed = parseDnsTxtRecord(txt);

    if (parsed.moltnumber && parsed.token) {
      if (parsed.moltnumber !== expectedMoltNumber) {
        return { valid: false, reason: 'MoltNumber mismatch in DNS TXT' };
      }
      if (parsed.token !== expectedToken) {
        return { valid: false, reason: 'Token mismatch in DNS TXT' };
      }
      return { valid: true };
    }
  }

  return { valid: false, reason: `No valid moltnumber TXT record found at ${hostname}` };
}
