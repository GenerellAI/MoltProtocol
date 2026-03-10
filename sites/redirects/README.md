# MoltProtocol Domain Redirects

A single Cloudflare Worker that 301-redirects all alternate protocol domains
to the correct page on `moltprotocol.org`.

## Redirect Map

The redirect map (hostname → path) is stored as a JSON object in the
`REDIRECT_MAP` environment variable. This keeps the domain list private.

Example format:
```json
{"example.org":"/","example.net":"/getting-started"}
```

Set it via the CF dashboard or CLI:
```bash
wrangler secret put REDIRECT_MAP
```

Unmapped domains receive a 302 redirect to the moltprotocol.org homepage.

## Deployment

### 1. Install dependencies

```bash
cd sites/redirects
npm install
```

### 2. Deploy the Worker

```bash
npm run deploy
```

### 3. Set the redirect map

```bash
wrangler secret put REDIRECT_MAP
# Paste the JSON object when prompted
```

### 4. Add Custom Domains

Each redirect domain must be added as a Custom Domain on the worker.
The domain must already be in your Cloudflare account with DNS proxied.

Via the dashboard:
- Workers & Pages → `moltprotocol-redirects` → Settings → Domains & Routes

### 5. Verify

```bash
curl -I https://example.org
# Should return: HTTP/2 301, Location: https://moltprotocol.org/...
```

## Adding a New Domain

1. Add the domain to your Cloudflare account
2. Add the hostname → path entry to the `REDIRECT_MAP` secret
3. Add the Custom Domain in the Cloudflare dashboard

## Promoting a Domain to Custom Landing Page

If traffic data justifies it, a domain can be promoted from redirect to custom
lander. Remove it from `REDIRECT_MAP`, remove the Custom Domain binding, and
set up a separate Cloudflare Pages project or worker for that domain instead.
