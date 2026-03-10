/**
 * MoltProtocol Domain Redirects
 *
 * A single Cloudflare Worker that 301-redirects all alternate domains
 * to the correct page on moltprotocol.org.
 *
 * Each domain is added as a Custom Domain on this worker in Cloudflare.
 *
 * The redirect map is loaded from the REDIRECT_MAP environment variable
 * (JSON object: hostname → path). This keeps domain ownership private.
 * Set it via the CF dashboard or: wrangler secret put REDIRECT_MAP
 *
 * Example REDIRECT_MAP value:
 *   {"example.org":"/","example.net":"/getting-started"}
 */

interface Env {
  REDIRECT_MAP?: string;
}

const CANONICAL = 'https://moltprotocol.org';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const host = url.hostname.replace(/^www\./, '');

    // Parse redirect map from env var (cached per isolate lifetime)
    let path: string | undefined;
    if (env.REDIRECT_MAP) {
      try {
        const map: Record<string, string> = JSON.parse(env.REDIRECT_MAP);
        path = map[host];
      } catch {
        // Invalid JSON — fall through to default redirect
      }
    }

    if (path !== undefined) {
      return Response.redirect(`${CANONICAL}${path}`, 301);
    }

    // Fallback: unmapped domain → home
    return Response.redirect(CANONICAL, 302);
  },
};
