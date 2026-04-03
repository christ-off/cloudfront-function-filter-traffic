# CloudFront Function – Traffic Filter

A [CloudFront Function](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-functions.html) (JS 2.0 runtime) that filters incoming requests before they reach the origin or cache. It handles four categories of traffic:

## What the function does

### 1. Always-allow paths
`/robots.txt` and `/ads.txt` are returned immediately regardless of any other rule — including a blocked user-agent. This ensures crawlers that respect these files can always fetch them.

### 2. Chrome cache traffic-advice
Requests to `/.well-known/traffic-advice` receive a crafted `200` response with an `application/trafficadvice+json` body. This opts the site into Chrome's prefetch/prerender behaviour while disabling Topics API and prefetch-proxy exposure.

### 3. Security scan blocking (404)
Requests that match obvious automated-scan patterns are returned a `404 Not Found` with a one-year `cache-control` header so the response is cached at the edge:

- **PHP probes** — any URI ending in `.php`
- **Common scanner folders** — URIs whose first path segment is one of:
  `images`, `image`, `img`, `wp-includes`, `static`, `wp`, `wordpress`, `old`, `new`, `blog`, `backup`, `cgi-bin`

URI matching is case-insensitive (the URI is lowercased before any check).

### 4. AI bot / scraper blocking (403)
Requests whose `User-Agent` header matches a curated list of known AI crawlers and scrapers are returned a `403 Forbidden`. The response includes:
- `cache-control: max-age=31536000` — edge-cached for one year
- `x-robots-tag: noindex, nofollow` — signals to any indexer that slips through

Blocked agents include (among many others): `GPTBot`, `ClaudeBot`, `Anthropic-AI`, `CCBot`, `ByteSpider`, `PerplexityBot`, `SemrushBot`, `meta-externalagent`, `DiffBot`, and `YandexAdditional`.

### 5. Pass-through
All other requests are forwarded to the origin unchanged.

---

## Why a CloudFront Function (not Lambda@Edge)?

CloudFront Functions run at **every edge location** with sub-millisecond startup and are ~6× cheaper than Lambda@Edge. They are the right tool for stateless, CPU-light request manipulation that requires no network I/O, no large runtimes, and no response body streaming. This filter fits that profile exactly: pure string matching, no external calls.

The trade-off is a restricted runtime — no `setTimeout`, no `fetch`, no Node.js built-ins. The function is written deliberately to stay within those constraints.

---

## Deployment

Copy the body of `function.js` into the CloudFront Functions editor in the AWS Console (or deploy via AWS CLI / CDK / Terraform). Associate the function with the **viewer request** event of your distribution.

> **Important:** remove the `export { handler }` line before deploying — CloudFront's JS 2.0 runtime does not support ES module `export` syntax. That line exists solely so Vitest can import the function during testing.

---

## Test framework

Tests are written with **[Vitest](https://vitest.dev/)**.

Vitest was chosen over Jest for this project because:

- **Native ESM support** — no Babel transform needed. The function uses `export { handler }` which works out of the box with `"type": "module"` in `package.json`.
- **Zero config** — no `jest.config.js`, no transform pipeline to maintain.
- **Fast** — Vitest starts in milliseconds; the full suite runs in under 250 ms.
- **Jest-compatible API** — `describe`, `it`, `expect`, `it.each` are identical, so the syntax is familiar.

### Running the tests

```bash
npm test           # run once
npm run test:watch # watch mode (re-runs on file save)
```

### Test structure

`function.test.js` covers all five behaviours with 51 tests:

| Suite | What is tested |
|---|---|
| Always-allow paths | `/robots.txt`, `/ads.txt`, URI trim & lowercase normalisation, bot UA ignored |
| Traffic-advice | Status 200, correct content-type, valid JSON body, cache header |
| PHP blocking | Root and sub-directory paths, case-insensitivity, no false positives |
| Bad folder blocking | All 12 folder names, bare folder (no trailing slash), no false positives on similar prefixes |
| AI bot blocking | 15 representative agents (one per regex line), case-insensitivity, response headers |
| Pass-through | Root path and normal page paths |

Each test builds a minimal CloudFront event object (`{ request: { uri, headers } }`) and asserts on the return value — either the original `request` object (pass-through) or a synthetic response with `statusCode`, `headers`, and `body`.
