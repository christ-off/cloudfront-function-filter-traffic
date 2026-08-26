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

## Blocking rules — rationale

`function.js` keeps only a one-line pointer comment for anything longer than a
sentence; the full reasoning (evidence, edge cases, why a pattern is shaped
the way it is) lives here instead, to keep the deployed file under
CloudFront's 10 KB function-size limit. Each heading below matches the
identifier the code points at.

### uri-decoding
Only ~3% of URIs contain a `%`-escape (per `logs.db`); the rest skip the
`decodeURIComponent` call entirely.

### bad-actor-response-mapping
`/robots.txt`, `/sitemap.xml` and `/feed.xml` get a real disallow-all / empty
sitemap / empty feed instead of a 404 for bad actors and blocked bots alike —
a correct, on-brand "you're not welcome here" rather than a generic miss.

### bad-actor-check-order
`isBadActor` runs security scans, then truncated/malformed/full-version
Chrome UAs, then outdated Firefox UAs, ordered most- to least-frequent per
`logs.db` so common cases short-circuit before rarer, costlier checks run.

### known-bad-exact-uas
UAs structurally indistinguishable from real traffic but confirmed bad by
request pattern (bursty `/.php` and `/` from a few IPs), not by structure —
unlike the Chrome-version checks below, this does **not** generalize to a
template. Current entry: `Chrome/120.0.0.0` on Windows — logs.db's older
aggregate showed this string as mostly organic, but recent request-pattern
evidence (bursty scans from a handful of IPs over 3 months) overrides that
for this exact UA.

### security-scan-regex
Combined into a single precompiled regex: one pass over the URI covers
extensions, folder prefixes, `/.env`, `/.git`, `/.docker` and known
credential-scan filenames. The trailing `.json` group is **not** a blanket
`.json$` rule — `/about/data/*.json` and `/pagefind/*.json` are real,
legitimately-served site data — so only known credential-scan filenames
(`secrets.json`, `config.json`, `service-account.json`, etc.) are matched
there.

### truncated-chrome-ua
A real browser always continues past `AppleWebKit/537.36` with
`(KHTML, like Gecko) Chrome/... Safari/...`. A string that stops dead right
after `AppleWebKit/537.36` is a bot with a copy-pasted, incomplete UA, not a
real Chrome/Edge. The shared literal fragments (`UA_OPEN`, `CLOSE_APPLEWEBKIT`,
`WINDOWS_PLATFORM`) are factored out for readability and composed into a
`RegExp` once at parse time, not rebuilt per request.

An exact-template match on OS/engine string plus a Chrome major-version range
used to be treated as "spoofed" here, but real Chrome (which freezes its UA
to `major.0.0.0`) produces this exact template too — logs.db showed the two
most common UAs in real traffic matching it. Structure alone can't tell real
Chrome from spoofed Chrome (see `CLAUDE.md`: never block Chrome solely on the
`.0.0.0` minor/patch version) — see [min-chrome-major](#min-chrome-major) for
a separate, evidence-backed floor on the version number itself.

### malformed-chrome-claim
Every real Chromium browser emits `AppleWebKit/537.36 (KHTML, like Gecko)`
immediately before the `Chrome/` token, so a UA with `chrome/` but no
`applewebkit` is a hand-built/incomplete UA, not a browser — catches
malformed strings the exact-template regexes above don't cover (e.g.
`Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0`).

### full-version-chrome-ua
Chrome's User-Agent Reduction (fully rolled out by Chrome 113, 2023) froze
the Chrome token to `major.0.0.0` for every platform — real Chrome 113+ never
reports its actual build/patch number anymore, so a full version there (e.g.
`Chrome/130.0.6723.70`) is a scraper/HTTP client using a stale, pre-freeze UA
template. Two exclusions keep this from false-positiving:
- below `CHROME_UA_FREEZE_MAJOR` (113), full versions were the real, expected
  format — see `Chrome/99.0.4844.51` in the pass-through fixtures.
- a `compatible;` token means the UA is a self-identifying crawler (e.g.
  Bingbot ships `Chrome/116.0.1938.76` as part of its documented template,
  not a spoofed browser).

### min-chrome-major
Below Chrome/99 (shipped March 2022), `logs.db` shows no organic signal at
all: every major from 70–98 either never fetches this site's real assets
(`main.css`, `bootstrap.bundle.min.js`) or does so only from a single narrow
IP/country cluster (headless-browser monitoring tools, not real users). From
99 up, genuine multi-country sessions loading real assets appear (confirmed
at 106, 110, 116, 131) despite those majors being well over a year stale —
Chrome users lag updates far more than Firefox users, so this floor is
deliberately much lower than [min-firefox-major](#min-firefox-major).

### min-firefox-major
Firefox auto-updates, so a stale major version is a scraper with a
hardcoded UA, not a real user. 100 shipped in May 2022 and every
still-maintained ESR is far above it; Tor Browser also reports an ESR major
(115+), so privacy users are unaffected.

### blocked-bot-regex
Plain substrings matched against the (already lowercased) User-Agent header,
as ONE regex literal. Written out literally rather than built at runtime
from an array: a literal is compiled when the script is parsed, whereas
`new RegExp(list.map(escape).join('|'))` re-does the escape calls, a map, a
join and a pattern compile on every script evaluation — pure compute we were
paying for. Alternatives are ordered most- to least-frequent per `logs.db` so
common bots exit early (non-matching UAs still try every alternative).

To add a bot: append `|your-token` (escaping `.`, `(`, `)` and `/` as
`\.`, `\(`, `\)`, `\/`) and add a UA sample to the `blockedAgents` fixture in
`function.test.js`.

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

`function.test.js` covers all behaviours with 209 tests:

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
