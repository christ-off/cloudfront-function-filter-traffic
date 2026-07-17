# CloudFront Function – Traffic Filter

A [CloudFront Function](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-functions.html) (JS 2.0 runtime) designed to protect a **static website hosted on AWS S3** (no PHP). It filters incoming requests before they reach the origin or cache.

[![CodeQL](https://github.com/christ-off/cloudfront-function-filter-traffic/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/christ-off/links-checker/actions/workflows/codeql.yml) 
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=christ-off_cloudfront-function-filter-traffic&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=christ-off_cloudfront-function-filter-traffic) 
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=christ-off_cloudfront-function-filter-traffic&metric=coverage)](https://sonarcloud.io/summary/new_code?id=christ-off_cloudfront-function-filter-traffic)

## What the function does

### 1. Missing user-agent blocking (404)
Requests with no `User-Agent` header, an empty value, or whitespace-only value return `404`. This check runs first and cannot be bypassed.

### 2. Security scan blocking (404)
Requests matching automated-scan patterns return `404`:
- URI extensions: `.php*`, `.sql`, `.bak`, `.phtml`, `.phar`
- Common scanner folders: `/admin`, `/wp-admin`, `/phpmyadmin`, `/backup`, etc.
- Sensitive paths: `/.env`, `/.git`, `/ip`

### 3. Malformed Firefox user-agent blocking (404)
Requests with mismatched `rv:` and `firefox/` versions return `404`.

### 4. Bot / scraper blocking
Requests matching `blockedBotPatterns` normally return `404`. But on well-known paths, blocked bots get harmless cached responses instead:

- **`/robots.txt`** — `200 OK` with deny-all `robots.txt` body, ETag, cache headers
- **`/feed.xml`** — `200 OK` with empty Atom feed, ETag, cache headers
- **`/sitemap.xml`** — `200 OK` with empty sitemap, ETag, cache headers

Subsequent requests with matching `If-None-Match` or `If-Modified-Since` receive `304 Not Modified`.

**Blocked patterns include:** scrapers (Scrapy, PetalBot, DataForSEO, etc.), old browser tokens (Trident, Presto, CriOS, FxiOS), stale Chrome (≤124), end-of-life iOS (1–9), and 80+ other known bots/crawlers.

### 5. Always-allow paths
`/ads.txt` bypasses all checks and returns immediately (requires non-empty user-agent).

### 6. Trailing slash redirect
Requests missing a trailing slash on folder-like paths are redirected with a custom page.

### 7. Pass-through
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

`function.test.js` covers all behaviours with 141 tests:

| Suite | What is tested |
|---|---|
| Always-allow paths | `/ads.txt`; URI trim & lowercase normalisation |
| Security scan blocking | File extensions, scanner folders, sensitive paths |
| Blocked bots | Deny-all `/robots.txt`; empty `/feed.xml`; empty `/sitemap.xml`; 304 Not Modified on cache headers |
| Bot patterns | 80+ patterns matched case-insensitively |
| Stale Chrome blocking | Chrome ≤124 blocked; Chrome 125+ pass |
| End-of-life iOS blocking | iOS 1–9 blocked; iOS 10+ pass |
| Malformed Firefox UA | Mismatched `rv:` and `firefox/` versions blocked |
| Null / empty UA blocking | Missing/empty/whitespace user-agent |
| Trailing slash redirect | Folder paths redirected with custom page |
| Pass-through | Normal requests forwarded unchanged |

Each test builds a minimal CloudFront event object (`{ request: { uri, headers } }`) and asserts on the return value — either the original `request` object (pass-through) or a synthetic response with `statusCode`, `headers`, and `body`.
