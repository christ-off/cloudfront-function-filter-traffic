# CloudFront Function – Traffic Filter

A [CloudFront Function](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-functions.html) (JS 2.0 runtime) designed to protect a **static website hosted on AWS S3** (no PHP). It filters incoming requests before they reach the origin or cache.

[![CodeQL](https://github.com/christ-off/cloudfront-function-filter-traffic/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/christ-off/links-checker/actions/workflows/codeql.yml) 
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=christ-off_cloudfront-function-filter-traffic&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=christ-off_cloudfront-function-filter-traffic) 
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=christ-off_cloudfront-function-filter-traffic&metric=coverage)](https://sonarcloud.io/summary/new_code?id=christ-off_cloudfront-function-filter-traffic)

## What the function does

### 1. Missing user-agent blocking (404)
Requests with no `User-Agent` header, an empty value, or a whitespace-only value are returned a `404 Not Found`. This check runs first and is not bypassed by any other rule, including always-allow paths.

### 2. Always-allow paths
`/robots.txt` and `/ads.txt` are returned immediately, bypassing all subsequent checks (security scan, bot blocking). Requires a non-empty `User-Agent`.

### 3. Security scan blocking (404)
Requests that match obvious automated-scan patterns are returned a `404 Not Found`:

- **Probes by extension** — URIs ending in `.php`, `.sql`, `.bak`, `.phtml`, `.phar`
- **Common scanner folders** — first path segment is one of:
  `images`, `image`, `img`, `wp-includes`, `static`, `wp`, `wordpress`, `old`, `new`, `blog`, `backup`, `cgi-bin`, `admin`, `administrator`, `wp-admin`, `phpmyadmin`, `pma`
- **Sensitive paths** — `/.env*`, `/.git*`, `/ip`
- **Percent-encoded bypass prevention** — the URI is decoded with `decodeURIComponent` before matching; malformed encodings return `404` immediately.

URI matching is case-insensitive (the URI is lowercased before any check).

### 4. Google referrer gate → warning page (200)

Requests with a `Referer` header matching any `*.google.*` domain are returned a **custom HTML warning page** instead of being passed through to the origin. The page (in French) informs the visitor that the site will soon be removed from Google's index, with a link back to the original page.

The original URL is extracted from Google's `?url=` redirect parameter when present; otherwise the current requested URI is used as the link target. The page includes `Cache-Control: no-cache, no-store` headers to prevent caching.

### 5. Bot blocking implementation — array of patterns vs. single regex

Bot user-agents are matched using an **array of string/regex patterns** rather than one big regex. A single regex is ~3.6× faster in microbenchmarks (49 ms vs 176 ms over 1 million calls), but the difference per real request is ~0.00013 ms — negligible at this scale. The array form was chosen because it keeps cognitive complexity low enough to satisfy SonarQube's threshold, and makes it trivial to add, remove, or comment out individual patterns.

### 6. Bot / scraper blocking (404)
Requests whose `User-Agent` matches any entry in `blockedBotPatterns` are returned a `404 Not Found`. Patterns are ordered by observed frequency (most frequent first) for faster average matching. Current entries include:

- **Scrapers & crawlers** — `PetalBot`, `SleepBot`, `got`, `DataForSEO`, `ev-crawler`, `WebScraperBot`, `PiMeyes`, `ShapBot`, `Scrapy`, `BuiltWith`, `WebTrackrCrawler`, `SpiderLing`, `Timpibot`, `Seamus the Search Engine`
- **Legacy / unwanted browser tokens** — `Trident` (IE), `Presto` (old Opera), `CriOS` (Chrome for iOS), `FxiOS` (Firefox for iOS), `YaApp_Android`, `YaSearchBrowser`, `ptst/`
- **Stale Chrome** — Chrome < 110 (pre-Feb 2023) — treated as a bot indicator
- **End-of-life iOS** — iOS 1–9 — all versions are end-of-life and rarely used by real browsers

### 7. Stale Chrome blocking (404)
Requests with a Chrome version below 110 (released Feb 2023) are returned a `404 Not Found`. Chrome versions this old are rarely seen in legitimate browsers in 2026 and are treated as a strong bot indicator.

### 8. End-of-life iOS blocking (404)
Requests with an iOS version between 1 and 9 are returned a `404 Not Found`. All such versions are end-of-life and are predominantly used by automated tools rather than real browsers.

### 9. Pass-through
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

`function.test.js` covers all behaviours with 104 tests:

| Suite | What is tested |
|---|---|
| Always-allow paths | `/robots.txt`, `/ads.txt`; URI trim & lowercase normalisation |
| PHP file blocking | `.php`, `.php5`, `.php7`, `.phtml`, `.phar` extensions, case-insensitivity |
| Google referrer gate | `google.com`, `google.fr`, `google.co.uk`, `google.de` → warning page; non-Google → pass-through; URL extraction from `?url=` param; HTML structure; fallback to current URI |
| Bad folder blocking | Scanner folders, admin folders, bare folder paths |
| `.env` / `.git` URI blocking | Sensitive path prefixes |
| `.sql` / `.bak` file blocking | Database and backup file extensions |
| Admin folder blocking | `/admin`, `/wp-admin`, `/phpmyadmin`, etc. |
| Bot blocking | All `blockedBotPatterns` entries, case-insensitivity |
| Stale Chrome blocking | Chrome 89, 94, 99 blocked; 100, 110, 115 pass |
| End-of-life iOS blocking | iOS 9 blocked; iOS 10 passes |
| Null / empty UA blocking | Missing header, empty value, whitespace-only value, robots.txt with no UA |
| Percent-encoded URI handling | Encoded dots, encoded characters, malformed encodings |
| Always-allow bypass of UA checks | `/ads.txt` passes even with a blocked bot UA |
| Pass-through | Root path and normal page paths |

Each test builds a minimal CloudFront event object (`{ request: { uri, headers } }`) and asserts on the return value — either the original `request` object (pass-through) or a synthetic response with `statusCode`, `headers`, and `body`.
