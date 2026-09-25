# CloudFront Function – Traffic Filter

A [CloudFront Function](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-functions.html) (JS 2.0 runtime) designed to protect a **static website hosted on AWS S3** (no PHP). It filters incoming requests before they reach the origin or cache.

[![CodeQL](https://github.com/christ-off/cloudfront-function-filter-traffic/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/christ-off/links-checker/actions/workflows/codeql.yml) 
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=christ-off_cloudfront-function-filter-traffic&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=christ-off_cloudfront-function-filter-traffic) 
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=christ-off_cloudfront-function-filter-traffic&metric=coverage)](https://sonarcloud.io/summary/new_code?id=christ-off_cloudfront-function-filter-traffic)

## What the function does

### 0. URI allowlist (pass-through)
A short list of exact paths (currently `/backup.zip`, `/robots.txt`, `/ads.txt`) always pass through
to the origin, checked before every other rule — nothing below can block them.

### 1. Missing user-agent blocking (404)
Requests with no `User-Agent` header, an empty value, or whitespace-only value return `404`. This check runs first, before URI decoding, and cannot be bypassed.

### 2. Security scan blocking (404)
Requests matching automated-scan patterns return `404`:
- URI extensions: `.php*`, `.sql`, `.bak`, `.phtml`, `.config`, `.ya?ml`, `.toml`, `.conf`, `.key`, `.pem`, `.axd`, `.boto`, `.s3cfg`, `.npmrc`, `.htpasswd`, `.tfstate`, `.old`, `.env`, `.map`, `.webmanifest` (backup copies, env files, source maps; the static site has no PWA manifest and no `.map` files)
- Common scanner folders: `/userfiles`, Laravel/Go/Apache debug endpoints (`/telescope`, `/horizon`, `/storage`, `/debug`, `/console`, `/server-status`, `/server-info`, `/manage`), `/graphql`, `/v1`, `/health`, `/proc`, `/var`, `/Dockerfile`, `/admin`, `/wp-admin`, `/phpmyadmin`, `/backup`, `/wp-content`, `/wp-json`, `/api` (all `/api/*` paths are security scans against this static site), etc.
- Any dotfile/dot-directory path (`/.env`, `/.git`, `/.docker/`, `/.netrc`, `/.yarnrc`, `/.aws/credentials`, `/.ssh/id_rsa`, `/.well-known/...`, etc. — this site serves no content under a dot-prefixed path, no exceptions), known credential-scan filenames (`/secrets.json`, `/config.json`, `/service-account.json`, etc.), and `/ip`

### 3. Spoofed / malformed / stale Chrome/Edge UA blocking (404)
- A truncated Windows UA that stops right after `AppleWebKit/537.36` instead of continuing with the real Chrome/Safari tail
- Any UA containing `chrome/` without `applewebkit` immediately before it — every real Chromium browser emits `AppleWebKit/537.36 (KHTML, like Gecko)` right before the `Chrome/` token, so its absence marks a hand-built UA
- A full build/patch `Chrome/` version (e.g. `130.0.6723.70`) on Chrome 113+ — post-UA-reduction Chrome only ever reports `major.0.0.0`, so a real build/patch number there is a stale, pre-freeze template (self-identifying crawlers using `compatible;`, e.g. Bingbot, are exempted)
- A `Chrome/` major version below 149 — logs.db shows the site's real audience only from 149 up; the "asset-loading" traffic on 145–148 is a single rotating-UA cloud fleet (Tencent/Huawei/GCP/AWS ranges). Exempted: self-identifying crawlers with `compatible;` (Bingbot, Googlebot…), Samsung Internet (ships a lagging Chromium), and Feeder (`feeder.co`, an RSS service with a hardcoded `Chrome/106`)
- An `Edg/` (desktop Edge) major version below 150 — same stale-UA-fleet pattern as Chrome, checked independently since a scraper can fake either token. Same exemptions as the Chrome floor.

### 4. Outdated Firefox user-agent blocking (404)
Requests with a `Firefox/` major version below 139 return `404`. Exempted: major `115`, Mozilla's actively-maintained legacy ESR train (Windows 7/8.1/macOS 10.12-10.14 support, extended through March 2027).

### 5. IP range blocking (404)
Requests from known-malicious IP ranges return `404` on every path, regardless of User-Agent — same as bad actors and blocked bots below. Currently blocks Techoff SRV Limited's ranges: `45.148.10.0/24`, `93.123.109.0/24`, `195.178.110.0/24`; Feo Prest SRL (AS208137, Aachen DE): `213.177.179.0/24`, `62.60.131.0/24`, `213.209.159.0/24`; TC Datacenter Limited (AS218785, Warsaw PL): `45.138.12.0/24`, `185.218.86.0/24`.

**Pending (not yet blocked):** `31.57.216.50` — AS197769, VPS Dedicated LLC, Ljubljana, SI.

### 6. Bot / scraper blocking
Requests matching 60+ known bot/scraper user-agent patterns return `404` on every path — no exceptions. Same for any other bad actor (security-scan URI or spoofed/stale-browser UA).

**Blocked patterns include:** scrapers (Scrapy, DataForSEO, Bytespider, etc.), old browser tokens (Trident, Presto), generic HTTP clients (`python-requests`, `aiohttp`, `got`), and more, matched case-insensitively against the User-Agent header.

### 7. JSON allowlist (404)
Any path ending in `.json` returns `404` unless it is one of: `/about/data/blogs.json`, `/about/data/pages.json`, `/about/data/visitors.json`, `/human.json`, `/pagefind/pagefind-entry.json`. This runs last, after all bot/security filtering.

### 8. JS allowlist (404)
Any path ending in `.js` returns `404` unless it is one of: `/javascript/recommended-blogs.js`, `/javascript/chart.umd.min.js`, `/javascript/bootstrap.bundle.min.js`, `/pagefind/pagefind.js`, `/pagefind/pagefind-worker.js`, `/pagefind/pagefind-ui.js`. Runs last, like the JSON allowlist.

### 9. Pass-through
All other requests are forwarded to the origin unchanged. A directory-style path without a trailing slash (e.g. `/about`) is not rewritten: the origin replies with a `301` to `/about/`. That `301` indicates the path **exists**, whereas a missing path gets a `404`.

## Compute utilization baseline

Measured 2026-09-23 at commit `2bc8248` (`function.js` 9,298 bytes) with
`aws cloudfront test-function` on the DEVELOPMENT stage, using `test-event.json`
(UA `Mozilla/5.0 (compatible; test)`) and only `request.uri` changed. Scale 0–100
(hard limit 100, above which CloudFront throttles):

| URI | Result | Utilization |
|---|---|---|
| `/index.html` | pass-through | 15 |
| `/about/x/y/z/page.html` | pass-through | 15 |
| `/id_rsa` | blocked | 11 |
| `/wp-config.old` | blocked | 10 |

Re-measure after adding rules and compare against this table; pass-through is
the worst case since it runs every check. Note: `ComputeUtilization` is coarse
and can vary by a point or two between runs.

---

## Blocking rules — rationale

`function.js` keeps only a one-line pointer comment for anything longer than a
sentence; the full reasoning (evidence, edge cases, why a pattern is shaped
the way it is) lives here instead, to keep the deployed file under
CloudFront's 10 KB function-size limit. Each heading below matches the
identifier the code points at.

### allowlisted-uris
Requests for these exact URIs pass straight through to the origin, before
even the missing-user-agent check — nothing below this point can block them,
including the IP-range and bot-UA checks. Case-insensitive exact-path match.

- `/backup.zip` — allowed at the user's request. Do not live-test this rule
  against the deployed function (e.g. `aws cloudfront test-function`); verify
  it with the unit tests only.

- `/robots.txt`, `/ads.txt` — always served, even to blocked UAs/IPs.

To add a URI: add `|your-path` (escape `.`) inside the group of `allowlistedUriRegex`.

### uri-decoding
Only ~3% of URIs contain a `%`-escape (per `logs.db`); the rest skip the
`decodeURIComponent` call entirely. Decoding loops (capped at 3 rounds) rather
than running once, so a double-encoded probe like `/admin%252F.env` — which a
single decode only turns into `/admin%2F.env`, leaving the `/` hidden from the
dotfile/prefix checks — still ends up fully decoded before matching.

### bad-actor-response-mapping
Bad actors and blocked bots get a plain 404 on every path except the
`allowlisted-uris`. `/robots.txt` is not faked: the origin's robots.txt already
disallows everything and allowlists specific bots. `/feed.xml` always gets a `200`
fake Atom `<feed>` instead of a 404/410: a blocked source polls it every minute
and ignores `max-age`, and a feed is preferable to an error. It holds one bait
entry linking `/backup.zip` (honeypot: any later request for it, in `logs.db`,
comes from a client that parsed the feed).

**Experiment (started 2026-09-25):** the goal is to see whether scrapers react
to a `410 Gone` (unlike a 404, it means "permanently removed", so well-behaved
clients should stop retrying). Every "404" above (`createNotFoundResponse`)
therefore answers `404` or `410` at random (50/50, `Math.random()`); `/feed.xml`
is excluded and always answers the fake `200` feed. Compare request rates per
user-agent/IP in `logs.db` before and after. If nothing changes, revert to a
constant 404 and drop the `createGoneResponse` branches.

### bad-actor-check-order
`isBadActor` runs path traversal, then dotfile paths, then security scans,
then truncated/malformed Chrome UAs, then outdated Chrome/Edge/Firefox UAs,
ordered most- to least-frequent per `logs.db` so common cases short-circuit
before rarer, costlier checks run.

### dotfile-path
Any path containing `/.` (a dotfile or dot-directory segment) is blocked
unconditionally, no exceptions — this includes `/.well-known/...`: the site
has no ACME HTTP-01 challenge (certs are provisioned another way) and serves
nothing else under a dot-prefixed path, so there's nothing there worth
excepting. A single generic rule covers `/.env`, `/.git`, `/.docker/`,
`/.netrc`, `/.yarnrc`, `/.aws/credentials`, `/.ssh/`, and any other
credential/config dotfile a scanner might probe for, without needing a
per-filename entry.

### security-scan-regex
Combined into a single precompiled regex: one pass over the URI covers
extensions, folder prefixes, and known credential-scan filenames (dotfiles
are handled separately by [dotfile-path](#dotfile-path)). The trailing
`.json` group is **not** a blanket `.json$` rule — `/about/data/*.json` and
`/pagefind/*.json` are real, legitimately-served site data — so only known
credential-scan filenames (`secrets.json`, `config.json`,
`service-account.json`, etc.) are matched there.

Any path starting with `/_` is blocked (`_ignition`, `_debugbar`, `_profiler`,
`__debug__`, `__vite`, `_astro`…): this site serves nothing under an underscore
prefix, so one bare prefix replaces per-framework entries. `/id_` (`/id_rsa`,
`/id_ed25519`, `.pub`…) is the same kind of bare prefix: scanners hunting for
SSH private keys at the web root.

Scanner probes by family, all matched as whole first segments (`(\/|$)`, so
`/variables-explained/` is safe) except extensions: `.old`/`.env`/`.map`/
`.webmanifest` (backup copies like `wp-config.php.old`, `secrets.env`, source
maps, a PWA manifest this site doesn't have); `userfiles` (upload dirs);
`telescope`, `horizon`, `storage` (Laravel); `debug`, `console`,
`server-status`, `server-info`, `manage` (Go/Apache/Java); `graphql`, `v1`,
`health` (API probes); `proc`, `var`, `dockerfile` (container/host internals).
The site is static and serves none of them.

`actuator` is in the folder-prefix group — Spring Boot's Actuator endpoints
(`/actuator/configprops`, `/actuator/env`, etc.) are only ever probed by
scanners against this static site, never served legitimately.

`api` is in the folder-prefix group — every `/api/*` path against this static
site is a security scan (the origin is an S3 static website with no API
backend). Probes like `/api/v2/config`, `/api/v1/users`, etc. are automated
scanners looking for API endpoints that don't exist here.

`read-document` is in the folder-prefix group — a new scan pattern first seen
2026-09-17 (38 requests to `/read-document` in one day), presumably probing
for a document-reading/SSRF-style endpoint that doesn't exist on this static
site.

`swp` (vim swap file) and a bare trailing `~` (generic editor backup, e.g.
`wp-config.php~`) are both classic backup-file scan suffixes appended after
a real filename/extension, so they're matched separately from the `\.ext$`
group rather than folded into it.

`@fs`, `@vite` and `@id` are Vite dev-server internal endpoints (`@fs` in
particular serves arbitrary files off the host filesystem, e.g.
`/@fs/home/ec2-user/.aws/credentials`) — this is a static site with no Vite
dev server behind it, so any request for these paths is a scanner, full stop.

### path-traversal
A literal `..` anywhere in the (already-decoded) URI path is blocked
unconditionally, rather than only matching specific traversal targets
(`.env`, `.aws/credentials`, etc.). A static site never legitimately needs
`..` in a path segment, and this also catches multi-encoded evasion attempts
(e.g. `..%25252f..%25252f...`) — the literal `..` survives even when the
attacker double/triple-encodes the surrounding slashes to dodge a single
`decodeURIComponent` pass.

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

### min-edge-major
Desktop Edge (`Edg/`) is Chromium underneath, so it gets the same
stale-fleet treatment as [min-chrome-major](#min-chrome-major), checked
independently rather than folded into the Chrome floor — a scraper can hold
one token fixed while bumping the other. Per the user's own `logs.db`
analysis, real Edge sessions only appear from major 150 up; below that is
the same rotating cloud-fleet pattern as sub-149 Chrome. Reuses
[chrome-floor-exemptions](#chrome-floor-exemptions) rather than a separate
list — NewsBlur's hardcoded fetcher UA (see below) carries both a stale
`Chrome/147` and a stale `Edg/147`, so the same exemption has to cover both
tokens or it breaks.

### chrome-floor-exemptions
UAs skipped by [min-chrome-major](#min-chrome-major) and
[min-edge-major](#min-edge-major) (checked as one regex, same reason as
[blocked-bot-regex](#blocked-bot-regex)):
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
- `newsblur.com` — NewsBlur's Feed Fetcher and Page Fetcher self-identify
  with `NewsBlur ... - https://www.newsblur.com/site/... (Mozilla/5.0 ...
  Chrome/147.0.0.0 ... Edg/147.0.0.0)`; the domain in the prefix is the
  identifying token, the parenthetical is a hardcoded browser-like UA that
  will drift stale over time same as Feeder's.
- `chrome-lighthouse` — Google Lighthouse (and PageSpeed Insights, which
  runs it) appends ` Chrome-Lighthouse` to whatever UA it's invoked with,
  which is often an old hardcoded Chrome major. The token is public and
  documented, not a secret, so this isn't security-by-obscurity — it's
  safe to exempt because unwanted crawlers are still blocked by name in
  [blocked-bot-regex](#blocked-bot-regex) regardless of what Chrome
  version they claim, and a scraper wanting past the floor could just
  claim a current Chrome major instead of bothering to fake this token.

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

The same regex also exempts `googleimageproxy` (ggpht.com's GoogleImageProxy,
e.g. `Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko Firefox/11.0 (via ggpht.com
GoogleImageProxy)`) — Google's proxy that fetches remote images for Gmail/
Google services. It hardcodes an ancient Firefox/IE-era UA rather than a
real browser's, but it's a legitimate fetcher identified by its own token, not
a scraper impersonating a browser, so it's exempted the same way as the
Chrome floor's named exemptions in
[chrome-floor-exemptions](#chrome-floor-exemptions).

### min-safari-major
Floor set at the user's request rather than derived from `logs.db` (unlike
[min-chrome-major](#min-chrome-major)/[min-edge-major](#min-edge-major),
which are log-backed). Safari majors track the OS/App Store, not an
auto-update cadence, so a hardcoded old major is a reasonable scraper signal
the same way a stale Firefox major is (see
[min-firefox-major](#min-firefox-major)) — Safari 17 shipped September 2023,
so anything below it is years stale. Floor lowered from 18 to 17 at the
user's request. Note Apple's version-numbering jump: Safari went from the
18.x line straight to 26 (aligned to the iOS/macOS release year), so there's
no 19–25 range to worry about.

Matched on `version\/(\d+)\.`, not `safari\/`: the `Safari/` token in a
Safari UA is a fixed WebKit build number (`605.1.15` desktop, `604.1`
mobile) that doesn't track the browser release, so it can't be used as a
version signal — see [safari-floor-exemptions](#safari-floor-exemptions) for
why other WebKit-based browsers need excluding from this check.

### safari-floor-exemptions
UAs skipped by [min-safari-major](#min-safari-major):
- `compatible;` — same self-identifying-crawler reasoning as
  [chrome-floor-exemptions](#chrome-floor-exemptions).
- `crios\/`, `fxios\/`, `opios\/` — Chrome/Firefox/Opera for iOS are
  Apple-mandated to use WebKit (hence the `Safari/604.1` tail) but don't
  carry a `Version/` token in their real UA, so these never actually match;
  listed defensively in case a future variant adds one.
- `edgios\/` — Edge for iOS *does* carry both `Version/` (WebKit's, stale
  and unrelated to Edge's own release) and `EdgiOS/` (its real version), so
  without this exemption a current Edge-for-iOS user gets floored by a
  `Version/` number that was never meant to signal anything.
- `duckduckgo`, `ucbrowser\/` — other WebKit-based iOS/Android browsers with
  the same stale-`Version/`-token shape as Edge for iOS.

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

`domain-harvester/` (`github.com/esc-city/domain-harvester`) is blocked at
the user's request.

`mapthenetbot/` (`mapthenet.org`) is blocked at the user's request.

`expansel-monitor/` (`expansel.com`) is blocked at the user's request.

`fogbot/` is blocked at the user's request.

`newsletterformresearchbot/` is blocked at the user's request.

`srchs-research-bot/` is blocked at the user's request.

`aionbot/` is blocked at the user's request.

`tiktokspider` (no `/`-separated version in its UA token) is blocked at the
user's request.

`opentheboxbot/` is blocked at the user's request.

`webapp-mapper/` is blocked at the user's request.

`ironfountain-leads/` is blocked at the user's request.

`what10bot/` (What10Bot, what10.com/bot) does not obey `robots.txt`.

`konqueror/` (`Mozilla/5.0 (compatible; Konqueror/3; Linux)`): a KDE browser UA no real visitor sends anymore; only scrapers spoof it.

`veryhip/` (`veryhip.com`) is blocked at the user's request.

`cms-security-auditor/` is blocked at the user's request, despite
self-identifying as an "authorized self-check" — the origin has no
allowlist for it, so it's treated like any other unsolicited scanner.

`censysinspect/` (Censys internet-scanning bot, `about.censys.io`) is
blocked at the user's request.

`petalbot` (Huawei's search crawler, `webmaster.petalsearch.com`) is no
longer blocked: it honors the `robots.txt` disallow list, so it's allowed
through like any other well-behaved crawler.

`publicwwwbot/` (PublicWWW, `publicwww.com`, a source-code search engine
crawler) is blocked at the user's request.

`wp2shell` (a WordPress vulnerability scanner/exploit tool) is blocked at
the user's request.

`webatlabot` (`https://webatla.com/bot`) is blocked at the user's request.

`ssi-nutch/` (SSI's broad web crawler, `https://ssi.inc/`, run by
`adi@ssi.inc`) is blocked at the user's request. Matched on the `ssi-nutch/`
name token only, version number dropped, per the standard pattern in
[blocked-bot-regex](#blocked-bot-regex).

`variableratio-publicassetresearch/` is blocked at the user's request.
Matched on the `variableratio-publicassetresearch/` name token only, version
number (`1.0`) dropped, per the standard pattern in
[blocked-bot-regex](#blocked-bot-regex).

`baiduspider` (Baidu's search crawler, including the `Baiduspider-render`
variant, `baidu.com/search/spider.html`) is blocked at the user's request.
Matched on the `baiduspider` name token only (no trailing `/`, since the
`-render` variant has no slash before its version number), per the standard
pattern in [blocked-bot-regex](#blocked-bot-regex).

`HaloBot/1.0` is blocked at the user's request. Matched on the `halobot/`
name token only, version number (`1.0`) dropped, per the standard pattern in
[blocked-bot-regex](#blocked-bot-regex).

`Flowb0t-ContentEngine/1.0` is blocked at the user's request. Matched on the
`flowb0t-contentengine/` name token only, version number (`1.0`) dropped, per
the standard pattern in [blocked-bot-regex](#blocked-bot-regex).

`ClarityBot/0.1 (https://clarity.surf/bot)` is an AI crawler that does not
consult `robots.txt`, and its bot info page is missing — blocked at the
user's request. Matched on the `claritybot/` name token only, version number
(`0.1`) dropped, per the standard pattern in
[blocked-bot-regex](#blocked-bot-regex).

`undici` (the Node.js HTTP client) is blocked at the user's request — it does
not fetch `robots.txt` and the traffic observed operates from DigitalOcean,
LLC · Toronto, CA, a hosting provider rather than a residential/ISP network.
Matched on the `undici` name token only, per the standard pattern in
[blocked-bot-regex](#blocked-bot-regex).

`ExaSearchBot` (`Mozilla/5.0 (compatible; ExaSearchBot/1.0; https://crawler.exa.ai/)`, the
Exa AI search crawler) is blocked at the user's request as scraper behaviour.
Matched on the `exasearchbot/` name token only, per the standard pattern in
[blocked-bot-regex](#blocked-bot-regex).

`serpex-index` (`Mozilla/5.0 (compatible; serpex-index/1.0; https://serpex.dev)`) is
blocked at the user's request — it documents no `robots.txt` policy. Matched on the
`serpex-index/` name token only, per the standard pattern in
[blocked-bot-regex](#blocked-bot-regex).

`compatible; crawler)` (full UA: `Mozilla/5.0 (compatible; crawler)`) is blocked at
the user's request. Its self-identifying name is the bare word "crawler", too
generic to match alone — it appears inside other, legitimate bots' self-ID URLs
(e.g. `ExaSearchBot`'s `https://crawler.exa.ai/`) — so the match is anchored to the
full `compatible; crawler)` substring instead of the usual bare name-token pattern
in [blocked-bot-regex](#blocked-bot-regex).

`colly` (`colly - https://github.com/gocolly/colly/v2`, the "Elegant scraper and
crawler framework for Golang") is blocked at the user's request as scraper behaviour.
Matched on the bare `colly` name token (its UA has no `name/version` form), per
the standard pattern in
[blocked-bot-regex](#blocked-bot-regex).

`jscrawler` (`Mozilla/5.0 (compatible; jscrawler/0.1; https://github.com/)`) is
blocked at the user's request as scraper behaviour. Matched on the
`jscrawler/` name token only, per the standard pattern in
[blocked-bot-regex](#blocked-bot-regex).

`Linkwarden (Server-Side Fetch)` (the self-hosted link manager,
`linkwarden.app`, fetching link previews/archives on behalf of its users) must
**not** be blocked — it's legitimate self-hosted server-side traffic, not a
scraper.

`Synapse (bot; https://github.com/matrix-org/synapse)` must **not** be
blocked — Synapse is an open-source Matrix homeserver fetching URL previews
on behalf of its users, not a scraper. It isn't currently matched by
[blocked-bot-regex](#blocked-bot-regex) (no generic `bot` substring is
matched, only specific named tokens), noted here so it stays excluded if the
regex is ever extended.

### ip-range-blocking
`event.viewer.ip` (the client IP CloudFront Functions exposes on every viewer
request/response) is matched against a blocklist of known-malicious network
ranges via `blockedIpRangeRegex` — a plain string-prefix regex, same style as
[blocked-bot-regex](#blocked-bot-regex), not integer/bitmask CIDR math. This
only works because every current range is `/24` (octet-aligned): the regex
alternatives are literal `first.second.third.` prefixes, so a match on
`45.148.10.` covers exactly `45.148.10.0`–`45.148.10.255`. Folded into the
same condition as [bad-actor-response-mapping](#bad-actor-response-mapping)
so a blocked IP is treated like any other bad actor, regardless of what
User-Agent it sends.

Currently blocked: `45.148.10.0/24`, `93.123.109.0/24`, `195.178.110.0/24`
(Techoff SRV Limited); `213.177.179.0/24`, `62.60.131.0/24`, `213.209.159.0/24`
(Feo Prest SRL, AS208137, Aachen DE); `45.138.12.0/24`, `185.218.86.0/24`
(TC Datacenter Limited, AS218785, Warsaw PL). Blocked at the user's request.

If a future range isn't octet-aligned (e.g. a `/25` or `/22`), the
string-prefix trick stops working and the check needs real integer/bitmask
CIDR matching instead — don't force a non-aligned range into this regex.

To add a range: append `|a\.b\.c\.` (escaping the dots) to
`blockedIpRangeRegex` for a `/24`, or `|a\.b\.` for a `/16`, and add an IP
sample to the `blockedIps` fixture in `function.test.js`.

### json-allowlist
Scanners probe for `.json` files (`/package.json`, `/composer.json`,
`/config.json`, ...). Only the five real JSON files the site serves are
allowed; every other `.json` path gets `404`. The check runs last, after the
bad-actor/bot/IP checks, so a blocked bot gets its `404` from those rules
first and only a legitimate-looking client can reach a real JSON file. It
matches the decoded, lowercased `uriLower` exactly (no query string is part
of `uri`).

To allow another file, add it to `allowedJsonRegex` and the test fixture.

### js-allowlist
Same approach as [json-allowlist](#json-allowlist): scanners probe for
`.js` files (`/app.js`, `/main.js`, `/config.js`, ...), so only the six real
scripts the site serves are allowed and every other `.js` path gets `404`.
Runs last, after the bad-actor/bot/IP checks. Matches the decoded, lowercased
`uriLower` exactly; `.json` paths are handled by the JSON rule, not this one.

To allow another file, add it to `allowedJsRegex` and the test fixture.

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

`function.test.js` covers all behaviours with 279 tests:

| Suite | What is tested |
|---|---|
| PHP / bad folder / security scan blocking | File extensions, scanner folders, sensitive/credential paths, `/ip` |
| Scrapper bot blocking by user-agent | 60+ bot/scraper patterns, matched case-insensitively |
| IP range blocking | Known-malicious `/24` ranges blocked regardless of UA; boundary IPs just outside a range pass through |
| robots.txt for blocked bots | Allowlisted: always passes through, even for blocked bots and bad actors |
| sitemap.xml for blocked bots | Blocked bots get a plain 404 on `/sitemap.xml`; normal browsers pass through untouched |
| Null / empty user-agent blocking | Missing/empty/whitespace user-agent |
| Percent-encoded URI handling | URI decoding before pattern matching |
| ads.txt and llms.txt | `/ads.txt` is allowlisted; `/llms.txt` follows normal UA blocking |
| Pass-through | Normal requests forwarded unchanged |

Each test builds a minimal CloudFront event object (`{ request: { uri, headers } }`) and asserts on the return value — either the original `request` object (pass-through) or a synthetic response with `statusCode`, `headers`, and `body`.
