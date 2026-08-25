# CloudFront Function – Traffic Filter

A [CloudFront Function](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-functions.html) (JS 2.0 runtime) designed to protect a **static website hosted on AWS S3** (no PHP). It filters incoming requests before they reach the origin or cache.

[![CodeQL](https://github.com/christ-off/cloudfront-function-filter-traffic/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/christ-off/links-checker/actions/workflows/codeql.yml) 
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=christ-off_cloudfront-function-filter-traffic&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=christ-off_cloudfront-function-filter-traffic) 
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=christ-off_cloudfront-function-filter-traffic&metric=coverage)](https://sonarcloud.io/summary/new_code?id=christ-off_cloudfront-function-filter-traffic)

## What the function does

### 1. Missing user-agent blocking (404)
Requests with no `User-Agent` header, an empty value, or whitespace-only value return `404`. This check runs first, before URI decoding, and cannot be bypassed.

### 2. Security scan blocking (404)
Requests matching automated-scan patterns return `404`:
- URI extensions: `.php*`, `.sql`, `.bak`, `.phtml`, `.config`, `.ya?ml`, `.toml`, `.conf`, `.key`, `.pem`, `.axd`, `.boto`, `.s3cfg`, `.npmrc`, `.htpasswd`, `.tfstate`
- Common scanner folders: `/admin`, `/wp-admin`, `/phpmyadmin`, `/backup`, `/wp-content`, `/wp-json`, etc.
- Sensitive paths: `/.env`, `/.git`, `/.docker/`, known credential-scan filenames (`/secrets.json`, `/config.json`, `/service-account.json`, etc.), and `/ip`

### 3. Spoofed / malformed / stale Chrome UA blocking (404)
- Two exact full-UA templates for spoofed Chrome-on-macOS and Chrome-on-Windows strings
- A truncated Windows UA that stops right after `AppleWebKit/537.36` instead of continuing with the real Chrome/Safari tail
- Any UA containing `chrome/` without `applewebkit` immediately before it — every real Chromium browser emits `AppleWebKit/537.36 (KHTML, like Gecko)` right before the `Chrome/` token, so its absence marks a hand-built UA
- A `Chrome/` major version below 99 (shipped March 2022) — logs.db shows no organic traffic below this floor (no real asset loads, or loads confined to a single bot/monitoring IP cluster), while majors 99+ show genuine multi-country sessions

### 4. Malformed / outdated Firefox user-agent blocking (404)
Requests with a `Firefox/` major version below 100, or a mismatched `rv:` vs. `Firefox/` version, return `404`. Exempted: Google Image Proxy's hardcoded `Firefox/11.0` UA (legitimate embedded-image fetching, not a scraper).

### 5. Bot / scraper blocking
Requests matching 60+ known bot/scraper user-agent patterns return `404` on every path — **except** `/robots.txt` (a real `200` disallow-all body), `/sitemap.xml` (a real `200` empty `<urlset>` body), and `/feed.xml` (a real `200` empty Atom `<feed>` body), instead of a 404, so a blocked scraper checking any of these gets a correct answer. The same exception applies to any other bad actor (security-scan URI or spoofed/stale-browser UA) landing on those paths.

**Blocked patterns include:** scrapers (Scrapy, PetalBot, DataForSEO, Bytespider, etc.), old browser tokens (Trident, Presto), generic HTTP clients (`python-requests`, `aiohttp`, `got`), and more, matched case-insensitively against the User-Agent header.

### 6. Pass-through
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

`function.test.js` covers all behaviours with 208 tests:

| Suite | What is tested |
|---|---|
| PHP / bad folder / security scan blocking | File extensions, scanner folders, sensitive/credential paths, `/ip` |
| Scrapper bot blocking by user-agent | 60+ bot/scraper patterns, matched case-insensitively |
| robots.txt disallow-all for blocked bots | Blocked bots and bad actors get a 200 disallow-all body on `/robots.txt`; normal browsers pass through untouched |
| sitemap.xml empty urlset for blocked bots | Blocked bots and bad actors get a 200 empty `<urlset>` body on `/sitemap.xml`; normal browsers pass through untouched |
| feed.xml empty atom feed for blocked bots | Blocked bots and bad actors get a 200 empty `<feed>` body on `/feed.xml`; normal browsers pass through untouched |
| Null / empty user-agent blocking | Missing/empty/whitespace user-agent |
| Percent-encoded URI handling | URI decoding before pattern matching |
| ads.txt and llms.txt | Follow normal UA blocking rules (no special bypass) |
| Pass-through | Normal requests forwarded unchanged |

Each test builds a minimal CloudFront event object (`{ request: { uri, headers } }`) and asserts on the return value — either the original `request` object (pass-through) or a synthetic response with `statusCode`, `headers`, and `body`.
