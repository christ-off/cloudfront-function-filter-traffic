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
- A truncated Windows UA that stops right after `AppleWebKit/537.36` instead of continuing with the real Chrome/Safari tail
- Any UA containing `chrome/` without `applewebkit` immediately before it — every real Chromium browser emits `AppleWebKit/537.36 (KHTML, like Gecko)` right before the `Chrome/` token, so its absence marks a hand-built UA
- A full build/patch `Chrome/` version (e.g. `130.0.6723.70`) on Chrome 113+ — post-UA-reduction Chrome only ever reports `major.0.0.0`, so a real build/patch number there is a stale, pre-freeze template (self-identifying crawlers using `compatible;`, e.g. Bingbot, are exempted)
- A `Chrome/` major version below 149 — logs.db shows the site's real audience only from 149 up; the "asset-loading" traffic on 145–148 is a single rotating-UA cloud fleet (Tencent/Huawei/GCP/AWS ranges). Exempted: self-identifying crawlers with `compatible;` (Bingbot, Googlebot…), Samsung Internet (ships a lagging Chromium), and Feeder (`feeder.co`, an RSS service with a hardcoded `Chrome/106`)

### 4. Outdated Firefox user-agent blocking (404)
Requests with a `Firefox/` major version below 139 return `404`. Exempted: major `115`, Mozilla's actively-maintained legacy ESR train (Windows 7/8.1/macOS 10.12-10.14 support, extended through March 2027).

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
  format (e.g. `Chrome/99.0.4844.51`); those majors are now caught by
  [min-chrome-major](#min-chrome-major) anyway, but the guard still matters
  for UAs that floor exempts.
- a `compatible;` token means the UA is a self-identifying crawler (e.g.
  Bingbot ships `Chrome/116.0.1938.76` as part of its documented template,
  not a spoofed browser).

### min-chrome-major
Floor set from `logs.db` (June–Sept 2026, Chrome 152 current) by counting
distinct IPs that load the site's real assets (`main.css`,
`bootstrap.bundle.min.js`) per Chrome major, then checking *who* they are.
Majors 145–148 look organic at first glance (~300 asset-loading IPs) but
are one bot fleet: the same Tencent/Huawei-cloud `/16`s (116.204, 1.92,
113.44, 81.70, 43.138…) appear on all four majors, rotating UAs, plus
GCP/AWS monitoring ranges on 148. The site's actual audience (FR/BE/CH/CA,
~70 % of real sessions) is essentially absent below 149 in the last 30 days
and shows up at 149 exactly (7 IPs), then 41 at 150, 95 at 151. Below 145
the picture is the same as it always was: no asset loads, or a single
narrow IP/country cluster.

Cost/benefit at 149: blocks ~92 % of non-crawler "Chrome ≥ 99" requests
(~30 k/month — mostly the `Chrome/120` and `Chrome/148` fleets) for zero
observed real-audience sessions in the last month. Real collateral found
over three months and handled via
[chrome-floor-exemptions](#chrome-floor-exemptions): Samsung Internet and
Feeder. Not worth exempting: Opera on 147/148 (5 FR IPs, but Opera tracks
Chromium within 1–2 majors so those were fresh at the time), one Electron
app on `Chrome/124`.

This floor is ~3 majors behind current and **needs raising periodically**:
the fleet will eventually move its UAs up, and every Chrome release
(monthly, or faster) widens the gap. Re-run the per-major asset-loading-IP
query before each bump.

### chrome-floor-exemptions
UAs skipped by [min-chrome-major](#min-chrome-major) (checked as one regex,
same reason as [blocked-bot-regex](#blocked-bot-regex)):
- `compatible;` — self-identifying crawlers: every Bingbot variant in
  `logs.db` (7 UA shapes, ~6.9 k requests) carries it and reports
  `Chrome/116`; Googlebot, YouBot, meta-webindexer, Google-InspectionTool
  likewise. Crawlers that are unwanted are blocked by name in
  [blocked-bot-regex](#blocked-bot-regex) regardless.
- `samsungbrowser/` — Samsung Internet ships a Chromium several majors
  behind Chrome (`SamsungBrowser/30` → `Chrome/143`, `/28` → `130`,
  `/27` → `125`); a handful of real FR/BE/NL users over three months.
- `feeder.co;` — Feeder, an RSS service, polls `/feed.xml` with a hardcoded
  `Chrome/106` desktop UA (~1.2 k requests from 10 IPs, active daily).
  Blocking it would silently drop its subscribers.

### min-firefox-major
Firefox auto-updates, so a stale major version is a scraper with a
hardcoded UA, not a real user. 139 shipped in June 2025 and is below every
Firefox release still in general support (current ESR is 140+); the one
still-maintained release below it is carved out separately, see
[firefox-esr-115-exemption](#firefox-esr-115-exemption).

### firefox-esr-115-exemption
Firefox ESR 115 is normally end-of-life, but Mozilla has repeatedly extended
its security updates for Windows 7/8.1 and old macOS versions (currently
through March 2027) — a real, still-patched browser used by a legacy-OS
population, not a scraper. Its major is exempted by exact match rather than
folded into the min-version floor, so it doesn't drag the floor down for
everything else. Tor Browser also reports an ESR major (115 or higher), so
privacy users on the current Tor ESR base remain unaffected either way.

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

`seojuice-searchbot/` (SEOJuice, `seojuice.io`) is blocked because it does
not obey `robots.txt`.

`coccocbot` (Coc Coc, `coccoc.com`, a Vietnamese search engine crawler) is
blocked at the user's request.

`hubspot crawler` (HubSpot's own crawler, `hubspot.com`) is blocked at the
user's request.

`yandex` (all Yandex bots — YandexBot, YandexNews, YandexImages, etc.,
`yandex.com`) is blocked at the user's request; the bare substring catches
every Yandex bot variant rather than listing each one.

`domain-harvester/` (`github.com/esc-city/domain-harvester`) is blocked at
the user's request.

`mapthenetbot/` (`mapthenet.org`) is blocked at the user's request.

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

`function.test.js` covers all behaviours with 222 tests:

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
