/**
 * GET /.well-known/molt-root.json
 *
 * Canonical source of the MoltProtocol root authority public key.
 * Carriers and MoltUA clients fetch this to verify carrier certificates.
 *
 * The public key is injected at build time via the ROOT_PUBLIC_KEY env var.
 * Production and staging builds use different keys — staging certificates
 * are not valid in production and vice versa.
 *
 * CF Pages environments:
 *   Production (moltprotocol.org)               → production ROOT_PUBLIC_KEY
 *   Preview    (*.moltprotocol-org.pages.dev)    → staging ROOT_PUBLIC_KEY
 */
import type { APIRoute } from 'astro';

const ROOT_PUBLIC_KEY = import.meta.env.ROOT_PUBLIC_KEY || '';
const ROOT_ISSUER = import.meta.env.ROOT_ISSUER || 'moltprotocol.org';

export const GET: APIRoute = () => {
  if (!ROOT_PUBLIC_KEY) {
    return new Response(
      JSON.stringify({ error: 'ROOT_PUBLIC_KEY not configured' }),
      { status: 503, headers: { 'Content-Type': 'application/json' } },
    );
  }

  return new Response(
    JSON.stringify(
      {
        version: '1',
        issuer: ROOT_ISSUER,
        public_key: ROOT_PUBLIC_KEY,
        key_algorithm: 'Ed25519',
        key_encoding: 'base64url SPKI DER',
      },
      null,
      2,
    ),
    {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=86400',
        'Access-Control-Allow-Origin': '*',
      },
    },
  );
};
