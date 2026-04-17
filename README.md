[![CodeQL](https://github.com/christ-off/cloudfront-function-filter-traffic/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/christ-off/links-checker/actions/workflows/codeql.yml) [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=christ-off_cloudfront-function-filter-traffic&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=christ-off_cloudfront-function-filter-traffic)

# CloudFront Function – Traffic Filter

A [CloudFront Function](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-functions.html) (JS 2.0 runtime) designed to protect a **static website hosted on AWS S3** (no PHP). It filters incoming requests before they reach the origin or cache, handling four categories of traffic:

## What the function does

### 1. Always-allow paths
`/robots.txt` and `/ads.txt` are returned immediately regardless of any other rule, including a blocked user-agent.

### 2. Chrome cache traffic-advice
Requests to `/.well-known/traffic-advice` receive a crafted `200` response with an `application/trafficadvice+json` body. This opts the site into Chrome's prefetch/prerender behaviour while disabling Topics API and prefetch-proxy exposure.

### 3. Security scan blocking (404)
Requests that match obvious automated-scan patterns are returned a `404 Not Found`:

- **Probes by extension** — URIs ending in `.php`, `.sql`, `.bak`, `.phtml`, `.phar`
- **Common scanner folders** — first path segment is one of:
  `images`, `image`, `img`, `wp-includes`, `static`, `wp`, `wordpress`, `old`, `new`, `blog`, `backup`, `cgi-bin`, `admin`, `administrator`, `wp-admin`, `phpmyadmin`, `pma`
- **Sensitive paths** — `/.env*`, `/.git*`, `/ip`

URI matching is case-insensitive (the URI is lowercased before any check).

### 4. AI bot / scraper blocking (404)
Requests whose `User-Agent` matches any of the following are returned a `404 Not Found`:

- **AI crawlers** — a curated list of 80+ known AI bots and scrapers: `GPTBot`, `CCBot`, `ByteSpider`, `PerplexityBot`, `meta-externalagent`, `Cohere`, etc.
- **Scraper bots** — `DataForSEO`, `ev-crawler`, `ptst/`, `YaApp_Android`, and similar.

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

## Pre-push validation (Claude Code hook)

A Claude Code `PreToolUse` hook automatically validates `function.js` against the live `cloudfront-js-2.0` runtime before every `git push`. It uploads the local code to the DEVELOPMENT stage and runs `aws cloudfront test-function`, blocking the push if any syntax or runtime error is detected.

### Setup

**1. Set your function name**

```
echo "Block_Intrusions" > .cloudfront-function-name
```

**2. Configure the test event**

Edit `test-event.json` to match a representative viewer request for your distribution. The default covers a standard `GET` with a `User-Agent` header.

**3. AWS credentials**

Ensure your shell has credentials with at least these permissions:

```json
{
  "Effect": "Allow",
  "Action": [
    "cloudfront:DescribeFunction",
    "cloudfront:UpdateFunction",
    "cloudfront:TestFunction"
  ],
  "Resource": "*"
}
```

### How it works

On each `git push` Claude Code will:

1. Fetch the current ETag via `aws cloudfront describe-function`
2. Upload local `function.js` to the DEVELOPMENT stage via `aws cloudfront update-function`
3. Run `aws cloudfront test-function --stage DEVELOPMENT`
4. Block the push and display the error if the runtime rejects the function

The hook script is at `.claude/hooks/cloudfront-pre-push.sh`.

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

`function.test.js` covers all five behaviours with 75 tests:

| Suite | What is tested |
|---|---|
| Always-allow paths | `/robots.txt`, `/ads.txt`, URI trim & lowercase normalisation, bot UA ignored |
| Traffic-advice | Status 200, correct content-type, valid JSON body, cache header |
| Security scan URIs | PHP/SQL/BAK extensions, scanner folders, `.env`/`.git` paths, admin folders |
| AI bot blocking | representative agents, case-insensitivity |
| Scraper bot blocking | DataForSEO, ev-crawler, YaApp_Android, ptst/ |
| Pass-through | Root path and normal page paths |

Each test builds a minimal CloudFront event object (`{ request: { uri, headers } }`) and asserts on the return value — either the original `request` object (pass-through) or a synthetic response with `statusCode`, `headers`, and `body`.
