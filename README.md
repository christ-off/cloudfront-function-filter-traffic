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

### 3. Spoofed / malformed Chrome UA blocking (404)
- A truncated Windows UA that stops right after `AppleWebKit/537.36` instead of continuing with the real Chrome/Safari tail
- Any UA containing `chrome/` without `applewebkit` immediately before it — every real Chromium browser emits `AppleWebKit/537.36 (KHTML, like Gecko)` right before the `Chrome/` token, so its absence marks a hand-built UA

### 4. IP range blocking (404)
Requests from known-malicious IP ranges return `404` on every path, regardless of User-Agent — same as bad actors and blocked bots below. Currently blocks Techoff SRV Limited's ranges: `45.148.10.0/24`, `93.123.109.0/24`, `195.178.110.0/24`; Feo Prest SRL (AS208137, Aachen DE): `213.209.159.0/24`, `213.177.179.0/24`, `62.60.131.0/24`; TC Datacenter Limited (AS218785, Warsaw PL): `45.138.12.0/24`, `185.218.86.0/24`.

**Pending (not yet blocked):** `31.57.216.50` — AS197769, VPS Dedicated LLC, Ljubljana, SI.

### 5. ASN blocking (404)
Requests whose `CloudFront-Viewer-ASN` header (added by the `Viewer-ASN` origin request policy) is a blocked AS — `16509` (AMAZON-02) or `14618` (AMAZON-AES) — `215125` (Church of Cyberology, NL scraper) — `29222` (Infomaniak, CH feed scraper) — or `396982` (Google Cloud, NL) — return `404` on every path, regardless of User-Agent. A missing header fails open. Exception: the Birchfeed and Claude-SearchBot user agents are allowlisted and pass even from a blocked ASN.

### 6. Bot / scraper blocking
Requests matching 60+ known bot/scraper user-agent patterns return `404` on every path — no exceptions. Same for any other bad actor (security-scan URI or truncated/malformed Chrome UA).

**Blocked patterns include:** scrapers (Scrapy, DataForSEO, Bytespider, etc.), old browser tokens (Trident, Presto), generic HTTP clients (`python-requests`, `aiohttp`, `got`), and more, matched case-insensitively against the User-Agent header.

### 7. JSON allowlist (404)
Any path ending in `.json` returns `404` unless it is one of: `/about/data/blogs.json`, `/about/data/pages.json`, `/about/data/visitors.json`, `/human.json`, `/pagefind/pagefind-entry.json`. This runs last, after all bot/security filtering.

### 8. JS allowlist (404)
Any path ending in `.js` returns `404` unless it is one of: `/javascript/recommended-blogs.js`, `/javascript/chart.umd.min.js`, `/javascript/bootstrap.bundle.min.js`, `/pagefind/pagefind.js`, `/pagefind/pagefind-worker.js`, `/pagefind/pagefind-ui.js`. Runs last, like the JSON allowlist.

### 9. Cover referer check (404)
`.webp` files under `/assets/posts/` and `/assets/posts_640/` (post covers) return `404` unless the `Referer` header starts with `https://post-tenebras-lire.net/`. Other assets (`/assets/svgs/`, `/assets/posts_other/`, ...) are not filtered. Runs last.

### 10. Pass-through
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
disallows everything and allowlists specific bots.

### bad-actor-check-order
`isBadActor` runs path traversal, then dotfile paths, then security scans,
then truncated/malformed Chrome UAs, ordered most- to least-frequent per
`logs.db` so common cases short-circuit before rarer, costlier checks run.
In `handler`, the cheap anchored IP-range check runs before the large
bot-name regex.

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

`swp` (vim swap file) and a bare trailing `~` (generic editor backup, e.g.
`wp-config.php~`) are both classic backup-file scan suffixes appended after
a real filename/extension, so they're matched separately from the `\.ext$`
group rather than folded into it.

`@fs` and `@vite` are Vite dev-server internal endpoints (`@fs` in
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
real Chrome/Edge. Matched by exact string equality against the lowercased UA.

Structure alone can't tell real Chrome from spoofed Chrome — real Chrome freezes
its UA to `major.0.0.0` — so no browser has a minimum version and only truncated
or `AppleWebKit`-less forms are blocked (see `AGENTS.md`: never block Chrome
solely on the `.0.0.0` minor/patch version).

### malformed-chrome-claim
Every real Chromium browser emits `AppleWebKit/537.36 (KHTML, like Gecko)`
immediately before the `Chrome/` token, so a UA with `chrome/` but no
`applewebkit` is a hand-built/incomplete UA, not a browser — catches
malformed strings the exact-template regexes above don't cover (e.g.
`Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0`).

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

`httpx - open-source project` (ProjectDiscovery httpx, `github.com/projectdiscovery/httpx`): its UA has no `/`-separated
version, so the name phrase is matched. Blocked at the user's request.

`tiktokspider` (no `/`-separated version in its UA token) is blocked at the
user's request.

`opentheboxbot/` is blocked at the user's request.

`brightbot` (UA is `Brightbot 1.0`, no `/`) is blocked at the user's request.

`rust-scrape/` is blocked at the user's request.

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

`ExaSearchBot` (`Mozilla/5.0 (compatible; ExaSearchBot/1.0; +https://crawler.exa.ai/)`, the
Exa AI search crawler) was previously blocked but is now deliberately allowed: the
user permits Exa to learn from the blog. It is intentionally absent from
[blocked-bot-regex](#blocked-bot-regex); do not re-add it.

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

`crawl-engine/0.1 (https://abuse.creasource.dev/; abuse-report@creasource.dev)`
is blocked at the user's request — it does not respect `robots.txt`. Matched
on the `crawl-engine/` name token only, version number (`0.1`) dropped, per
the standard pattern in [blocked-bot-regex](#blocked-bot-regex).

`KeenableBot/1.0` (`https://keenable.ai/`) does not respect `robots.txt` and
is blocked. Matched on the `keenablebot/` name token only, version number
(`1.0`) dropped, per the standard pattern in
[blocked-bot-regex](#blocked-bot-regex).

`WordPress/6.4.3` (the generic self-hosted-WordPress UA sent by pingbacks/
XML-RPC requests, version varies per site) is blocked at the user's request.
Matched on the `wordpress/` name token only, version number (`6.4.3`)
dropped, per the standard pattern in [blocked-bot-regex](#blocked-bot-regex).

`curl/8.6.0` (the curl CLI default UA) is blocked at the user's request —
no legitimate need to curl the site. Matched on the `curl/` name token only,
version number (`8.6.0`) dropped, per the standard pattern in
[blocked-bot-regex](#blocked-bot-regex).

`tphotobot/` is blocked at the user's request.

`WebsiteResearch/1.0` is blocked at the user's request. Matched on the
`websiteresearch/` name token only, version dropped, per the standard pattern in
[blocked-bot-regex](#blocked-bot-regex).

`SurdotlyBot/1.0` (`sur.ly/bot.html`) is blocked: it ignores robots.txt despite claiming to obey it. Matched on the `surdotlybot/` name token only, version dropped, per the standard pattern in [blocked-bot-regex](#blocked-bot-regex).

`AonsightMetaBot/1.0` (`aonsight.com/bot`) is blocked at the user's request. Matched on the `aonsightmetabot/` name token only, version dropped, per the standard pattern in [blocked-bot-regex](#blocked-bot-regex).

All `Baiduspider` variants are blocked (`Baiduspider/2.0`, `Baiduspider-image`, `Baiduspider-render/2.0`, ...): the render variant fetches a post, then downloads the covers with the post URL as `Referer`, so it passes [cover-referer](#cover-referer), and blocking only it is pointless when the family is unwanted anyway. Matched on the bare `baiduspider` name token, which covers every suffix.

### feedfetcher-google
`FeedFetcher-Google; (+http://www.google.com/feedfetcher.html)` (Google's feed reader) is allowed on
`/feed.xml` only and blocked everywhere else. It is handled in `isBlockedBot` rather than in
[blocked-bot-regex](#blocked-bot-regex), so it is not in the regex.

`SummalyBot/x.y.z` (Misskey's link-preview fetcher, run by many instances) must **not** be
blocked — it is used by fediverse tools to render link previews.

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

### asn-blocking
A scraper with a frozen Chrome 152 UA (`Chrome/152.0.0.0` on `X11; Linux x86_64`) crawls from a rotating pool of AWS
us-east-1 IPs (one IP per request), so [ip-range-blocking](#ip-range-blocking)
is useless against it. Blocking the network instead covers the whole pool and
survives a UA change. CloudFront adds `CloudFront-Viewer-ASN` only when an
origin request policy asks for it (`Viewer-ASN`, attached to the distribution),
and `blockedAsnRegex` matches the header value exactly (`^(16509|14618|215125|29222|396982)$`).
Folded into the same condition as
[bad-actor-response-mapping](#bad-actor-response-mapping), so blocked ASNs get
the usual 404. The URI allowlist runs first, so
`/robots.txt`, `/ads.txt` and `/backup.zip` stay reachable. If the header is
absent (policy not attached) nothing matches: fails open.

`allowedAsnBotRegex` is an allowlist of legitimate bots (`birchfeed\/`,
`claude-searchbot\/`) that happen to be hosted in a blocked ASN; a match skips
only the ASN check, all other rules still apply. Matched on the name token
without version, like the bot blocklist.

**Setup — getting the ASN header in AWS.** The function only sees
`CloudFront-Viewer-ASN` if the distribution requests it. This is done once per
distribution, and the header is not part of the cache key.

1. *Check the current policies.* Repeat for every cache behavior that uses the function (replace `<DISTRIBUTION_ID>`):
   ```bash
   aws cloudfront get-distribution-config --id <DISTRIBUTION_ID> \
     --query 'DistributionConfig.DefaultCacheBehavior.{ORP:OriginRequestPolicyId,Cache:CachePolicyId}'
   ```
2. *Create an origin request policy.*
   - `ORP` is `null` → create a policy with only the ASN header:
     ```bash
     aws cloudfront create-origin-request-policy --origin-request-policy-config '{
       "Name": "Viewer-ASN",
       "HeadersConfig": {"HeaderBehavior": "whitelist",
         "Headers": {"Quantity": 1, "Items": ["CloudFront-Viewer-ASN"]}},
       "CookiesConfig": {"CookieBehavior": "none"},
       "QueryStringsConfig": {"QueryStringBehavior": "none"}
     }'
     ```
   - A managed policy is already attached (e.g. `CORS-S3Origin`) → managed policies can't be edited: create a custom one that copies its headers **plus** `CloudFront-Viewer-ASN`.
3. *Attach it.* Console → CloudFront → your distribution → Behaviors → Edit → **Origin request policy** → `Viewer-ASN`, for every behavior using the function.

The header can't go in a cache policy; it must be an origin request policy.
There is no cache impact, and S3 ignores the unknown header (OAC signing is
unaffected). To check it works, temporarily log it from the function with
`console.log('asn=' + (h ? h.value : '-'))` and read the CloudWatch log group
`/aws/cloudfront/function/<FunctionName>` in us-east-1; `asn=-` means the policy
is not attached.

**Trade-off:** this blocks everything hosted on AWS, including Amazonbot and
any AWS-hosted SummalyBot / Linkwarden / Synapse instance. If such traffic
shows up, exempt those UA tokens inside `isBlockedAsn`. Some Amazon ranges are
announced from other ASNs (e.g. AS8987 EU): check bgp.he.net before extending.

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
(Techoff SRV Limited); `213.209.159.0/24`
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

### cover-referer
Post covers (`.webp` in `/assets/posts/` and `/assets/posts_640/`) are only
meant to be embedded by the site itself, so hotlinked or direct requests
(missing or foreign `Referer`) get `404`. `coverUriRegex` matches the decoded,
lowercased `uriLower`; the referer is compared case-insensitively against
`COVER_REFERER_PREFIX`. The `Referer` is client-supplied, so this only stops
casual hotlinking. Other `/assets/*` paths are intentionally unfiltered for now.

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

`function.test.js` covers all behaviours with 379 tests:

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
