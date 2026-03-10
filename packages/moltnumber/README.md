# MoltNumber

Self-certifying identity standard for AI agents.

**Website:** [moltnumber.org](https://moltnumber.org)  
**Formal Specification:** [SPEC.md](SPEC.md)

---

## What is MoltNumber?

MoltNumber is a self-certifying numbering and identity standard that assigns globally unique, URL-safe identifiers to AI agents. Each MoltNumber is cryptographically derived from an Ed25519 public key — anyone can verify identity by hashing the key and comparing. No registry, no CA, no carrier needed.

Like Bitcoin addresses or Tor .onion domains, the number IS the identity.

MoltNumber defines:

1. **Number format** — `NATION-AAAA-BBBB-CCCC-DDDD`
2. **Self-certifying derivation** — subscriber = `Crockford32(SHA-256(nation + ":" + publicKey))[0:80 bits]`
3. **Domain binding** — prove a MoltNumber belongs to a domain via `/.well-known/moltnumber.txt` or DNS TXT
4. **Social verification** — optional badges (X, GitHub) linking a MoltNumber to public accounts

MoltNumber does **not** define call routing, voicemail, MoltSIM provisioning, or any carrier-level functionality. Those are the responsibility of carrier implementations like [MoltPhone](https://github.com/GenerellAI/moltphone.ai).

---

## Number Format

```
NATION-AAAA-BBBB-CCCC-DDDD
```

| Segment | Description |
|---------|-------------|
| `NATION` | 4 uppercase letters (A–Z). Identifies the namespace / network. |
| `AAAA-BBBB-CCCC-DDDD` | 16-character subscriber ID in Crockford Base32, derived from SHA-256(nation + ":" + publicKey). 80 bits of entropy. |

### Self-Certifying Property

The subscriber portion is the first 80 bits of `SHA-256(nationCode + ":" + publicKey)`, encoded as Crockford Base32. This means:

- **Trustless verification** — hash the public key with the nation, compare to the number. Done.
- **Nation binding** — the nation code is included in the hash, so the same key produces different numbers in different nations.
- **No check digit** — the hash itself is the integrity check. If you mistype a character, it won't match any public key.
- **Vanity mining** — generate keypairs until you find a subscriber that starts with a desired prefix (like Bitcoin vanity addresses).

### Rules

- **No `+` prefix.** MoltNumbers are not phone numbers.
- **Dashes are mandatory separators.** Always 4 dashes total.
- **Stored and compared uppercase.** Normalization strips whitespace and uppercases.
- **URL-safe.** `encodeURIComponent(moltnumber) === moltnumber` — always.
- **Crockford Base32 alphabet:** `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (excludes I, L, O to avoid ambiguity).

### Examples

```
MOLT-7K3P-M2Q9-H8D6-4R2E
AION-ABCD-EFGH-JKMN-PQ01
CLAW-9V8W-3X4Y-5Z67-8A9B
```

---

## Domain Binding

An agent can prove it controls a domain via HTTP Well-Known or DNS TXT record.

### Method 1: HTTP Well-Known

```
https://<domain>/.well-known/moltnumber.txt
```

File format:

```
moltnumber: MOLT-7K3P-M2Q9-H8D6-4R2E
token: <random-hex-token>
```

### Method 2: DNS TXT

```
_moltnumber.<domain>  TXT  "moltnumber=<MOLTNUMBER> token=<TOKEN>"
```

### Verification flow

1. Agent requests a domain claim → receives a random `token` and instructions for both methods.
2. Agent publishes verification via HTTP (`.well-known/moltnumber.txt`) or DNS TXT (`_moltnumber.<domain>`).
3. Verifier checks the chosen method over HTTPS or DNS and confirms `moltnumber` and `token` match.

Social badges (X, GitHub) are evidence, not proof. Domain binding is the cryptographic anchor.

---

## Installation

```bash
npm install moltnumber
```

## Usage

```typescript
import {
  generateMoltNumber,
  verifyMoltNumber,
  validateMoltNumber,
  parseMoltNumber,
  normalizeMoltNumber,
} from 'moltnumber';

// Generate a self-certifying MoltNumber from a nation code and public key
const num = generateMoltNumber('MOLT', publicKey);
// => "MOLT-7K3P-M2Q9-H8D6-4R2E"

// Verify: does this number match this public key? (the core self-certifying property)
verifyMoltNumber(num, publicKey); // => true
verifyMoltNumber(num, differentKey); // => false

// Validate format only (no key needed)
validateMoltNumber(num); // => true
validateMoltNumber('MOLT-XXXX-YYYY-ZZZZ-0'); // => false (wrong length)

// Parse into components
const parts = parseMoltNumber(num);
// => { nation: "MOLT", subscriber: "7K3PM2Q9H8D64R2E", formatted: "MOLT-7K3P-M2Q9-H8D6-4R2E" }

// Normalize user input
normalizeMoltNumber('  molt-aaaa-bbbb-cccc-dddd  ');
// => "MOLT-AAAA-BBBB-CCCC-DDDD"
```

### Domain binding

```typescript
import {
  generateDomainClaimToken,
  buildWellKnownUrl,
  parseWellKnownFile,
  validateDomainClaim,
} from 'moltnumber/domain-binding';

// 1. Generate a claim token
const token = generateDomainClaimToken();
// => "a3f8...64-char hex..."

// 2. Build the URL the agent should publish at
const url = buildWellKnownUrl('example.com');
// => "https://example.com/.well-known/moltnumber.txt"

// 3. After the agent publishes, fetch and validate
const body = await fetch(url).then(r => r.text());
const result = validateDomainClaim(body, 'MOLT-7K3P-M2Q9-H8D6-4R2E', token);
// => { valid: true } or { valid: false, reason: "..." }
```

---

## API Reference

### Format (`moltnumber` or `moltnumber/format`)

| Export | Description |
|--------|-------------|
| `generateMoltNumber(nationCode, publicKey)` | Generate a self-certifying MoltNumber from nation + Ed25519 public key. |
| `verifyMoltNumber(number, publicKey)` | Verify that a number was derived from the given public key. Returns `boolean`. |
| `validateMoltNumber(number)` | Validate format only (no key needed). Returns `boolean`. |
| `normalizeMoltNumber(input)` | Trim, uppercase, strip whitespace. |
| `parseMoltNumber(number)` | Parse into `{ nation, subscriber, formatted }` or `null`. |
| `deriveSubscriber(nationCode, publicKey)` | Derive the 16-char subscriber from nation + key (low-level). |
| `CROCKFORD_ALPHABET` | The 32-character Crockford Base32 alphabet string. |

### Domain Binding (`moltnumber/domain-binding`)

| Export | Description |
|--------|-------------|
| `generateDomainClaimToken()` | Generate a 64-char hex token for domain verification. |
| `buildWellKnownUrl(domain)` | Build the canonical `/.well-known/moltnumber.txt` URL. |
| `parseWellKnownFile(body)` | Parse the file into `{ moltnumber, token }`. |
| `validateDomainClaim(body, expectedMoltNumber, expectedToken)` | Validate a fetched HTTP well-known file. Returns `{ valid, reason? }`. |
| `validateDomainClaimDns(domain, expectedToken)` | Validate via DNS TXT record at `_moltnumber.<domain>`. Returns `{ valid, reason? }`. |

---

## Running Tests

```bash
npm test
```

---

## License

MIT — see [LICENSE](LICENSE).
