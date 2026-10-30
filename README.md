# CloudFront Function – Traffic Filter

A [CloudFront Function](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-functions.html) (JS 2.0 runtime) designed to protect a **static website hosted on AWS S3** (no PHP). It filters incoming requests before they reach the origin or cache.

[![CodeQL](https://github.com/christ-off/cloudfront-function-filter-traffic/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/christ-off/links-checker/actions/workflows/codeql.yml) 
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=christ-off_cloudfront-function-filter-traffic&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=christ-off_cloudfront-function-filter-traffic) 
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=christ-off_cloudfront-function-filter-traffic&metric=coverage)](https://sonarcloud.io/summary/new_code?id=christ-off_cloudfront-function-filter-traffic)

## What the function does

Checks run in this order; the first match wins. Reasoning is under
[Blocking rules — rationale](#blocking-rules--rationale).

| # | Rule | Response |
|---|---|---|
| 0 | URI allowlist: `/backup.zip`, `/robots.txt`, `/ads.txt` bypass everything below | pass-through |
| 1 | Missing, empty or whitespace-only `User-Agent` | `410` |
| 2 | Bad actor: path traversal, dotfile paths, security-scan URIs, truncated/malformed Chrome UA | `410` |
| 3 | Blocked ASN ([asn-blocking](#asn-blocking)) | `410` |
| 4 | Blocked bot/scraper user-agent ([blocked-bot-regex](#blocked-bot-regex)) | `410` |
| 5 | `.json` / `.js` not on the allowlists, post covers without the site `Referer` | `404` |
| 6 | Anything else | pass-through |

Every `410` for `/feed.xml` becomes a `200` with an empty Atom feed
([fake-empty-feed](#fake-empty-feed)). A directory-style path without a trailing slash
(e.g. `/about`) is not rewritten: the origin replies `301` to `/about/`, which shows the
path **exists**, whereas a missing path gets a `404`.

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
including the bot-UA checks. Case-insensitive exact-path match.

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
Bad actors, ASNs and bots get a plain `410 Gone` on every path except the
`allowlisted-uris`. `/robots.txt` is not faked: the origin's robots.txt already
disallows everything and allowlists specific bots. `410` (permanent) rather
than `404` tells well-behaved crawlers to drop the URL; the `.json`/`.js`
allowlists, the cover referer check and undecodable URIs stay `404`, as those
are ordinary missing resources, not blocked clients.

### fake-empty-feed
Whenever the function would answer `410` and the URI is `/feed.xml` (case-insensitive), it
replies `200` with a valid but empty Atom feed (`application/atom+xml`, no entries, fixed
`updated` date) instead. Feed readers treat it as a feed with nothing new and keep polling
quietly, rather than treating the 410 as an error. A `301` to `/backup.zip` and a bodyless
`304` were both tried and rejected: the 301 was useless and a 304 is only valid as an answer
to a conditional request. This covers every 410 rule (missing UA, bad actor, ASN, bot).

### bad-actor-check-order
`isBadActor` runs path traversal, then dotfile paths, then security scans,
then truncated/malformed Chrome UAs, ordered most- to least-frequent per
`logs.db` so common cases short-circuit before rarer, costlier checks run.

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
Plain substrings matched against the lowercased User-Agent, as ONE regex literal.
A literal is compiled when the script is parsed, whereas building it at runtime
(`new RegExp(list.map(escape).join('|'))`) would redo the escapes, map, join and
compile on every evaluation. Alternatives are ordered most- to least-frequent per
`logs.db` so common bots exit early.

Match the bot's name token only and drop its version (`aionbot\/`, not
`aionbot\/1\.0`); see `AGENTS.md`. To add a bot: append `|your-token` (escape `.`, `(`,
`)` and `/` as `\.`, `\(`, `\)`, `\/`) and add a UA sample to the `blockedAgents`
fixture in `function.test.js`.

**Blocked at the user's request, no further reason:** `coccocbot` (Coc Coc),
`hubspot crawler`, `domain-harvester/`, `mapthenetbot/`, `expansel-monitor/`, `fogbot/`,
`newsletterformresearchbot/`, `srchs-research-bot/`, `aionbot/`, `tiktokspider` (no
`/`-separated version in its UA), `opentheboxbot/`, `brightbot` (UA is `Brightbot 1.0`),
`rust-scrape/`, `webapp-mapper/`, `ironfountain-leads/`, `veryhip/`, `censysinspect/`,
`publicwwwbot/`, `wp2shell` (WordPress exploit tool), `webatlabot`, `ssi-nutch/`,
`variableratio-publicassetresearch/`, `halobot/`, `flowb0t-contentengine/`, `tphotobot/`,
`websiteresearch/`, `aonsightmetabot/`, `wordpress/` (pingback/XML-RPC UA), `curl/` (no
legitimate need to curl the site), `httpx - open-source project` (ProjectDiscovery httpx;
its UA has no `/`-separated version, so the name phrase is matched).

**With a reason:**

| Token | Why |
|---|---|
| `cms-security-auditor/` | Claims to be an "authorized self-check", but the origin has no allowlist for it, so it is treated like any unsolicited scanner |
| `seojuice-searchbot/` | Ignores `robots.txt` |
| `what10bot/` | Ignores `robots.txt` |
| `surdotlybot/` | Ignores `robots.txt` despite claiming to obey it |
| `claritybot/` | AI crawler that ignores `robots.txt`; its bot info page is missing |
| `keenablebot/` | Ignores `robots.txt` |
| `crawl-engine/` | Ignores `robots.txt` |
| `serpex-index/` | Documents no `robots.txt` policy |
| `undici` | Node.js HTTP client; never fetches `robots.txt`, traffic comes from a hosting provider (DigitalOcean, Toronto) |
| `konqueror/` | `Mozilla/5.0 (compatible; Konqueror/3; Linux)`: no real visitor sends this UA anymore; only scrapers spoof it |
| `compatible; crawler)` | Full UA `Mozilla/5.0 (compatible; crawler)`. The bare word "crawler" is too generic (it appears in `https://crawler.exa.ai/`), so the whole substring is anchored |
| `baiduspider` | Every variant (`-image`, `-render/2.0`, ...). The render variant downloads covers with the post URL as `Referer`, so it passes [cover-referer](#cover-referer); blocking only it is pointless |

**Deliberately not blocked** (absent from the regex; do not add):
- `ExaSearchBot`: the user permits Exa to learn from the blog.
- `PetalBot` (Huawei): honors the `robots.txt` disallow list.
- `SummalyBot` (Misskey link previews), `Linkwarden (Server-Side Fetch)` (self-hosted link manager), `Synapse (bot; ...)` (Matrix URL previews): legitimate server-side fetchers on behalf of users. Synapse isn't matched anyway (no generic `bot` substring); noted so it stays excluded if the regex is ever extended.

### feedfetcher-google
`FeedFetcher-Google; (+http://www.google.com/feedfetcher.html)` (Google's feed reader) is allowed on
`/feed.xml` only and blocked everywhere else. It is handled in `isBlockedBot` rather than in
[blocked-bot-regex](#blocked-bot-regex), so it is not in the regex.

### asn-blocking
A scraper with a frozen Chrome 152 UA (`Chrome/152.0.0.0` on `X11; Linux x86_64`) crawls from a rotating pool of AWS
us-east-1 IPs (one IP per request), so blocking by IP is useless against it. Blocking the network instead covers the whole pool and
survives a UA change. CloudFront adds `CloudFront-Viewer-ASN` only when an
origin request policy asks for it (`Viewer-ASN`, attached to the distribution),
and `blockedAsnRegex` matches the header value exactly (anchored `^(...)$`).
Folded into the same condition as
[bad-actor-response-mapping](#bad-actor-response-mapping), so blocked ASNs get
the usual 410. The URI allowlist runs first, so
`/robots.txt`, `/ads.txt` and `/backup.zip` stay reachable. If the header is
absent (policy not attached) nothing matches: fails open.

Blocked ASNs (all at the user's request):

| ASN | Network |
|---|---|
| 16509, 14618 | AMAZON-02, AMAZON-AES |
| 215125 | Church of Cyberology, NL scraper |
| 29222 | Infomaniak, CH feed scraper |
| 396982 | Google Cloud, NL |
| 1299 | Arelion Sweden AB |
| 48090 | Techoff SRV Limited, Amsterdam NL |
| 8075 | Microsoft Corporation, HK |
| 4134 | CHINANET BACKBONE, Shijiazhuang CN |
| 23724 | IDC China Telecommunications, Beijing CN |
| 271315 | Netfusion Internet LTDA, Rio de Janeiro BR |
| 209334 | Modat B.V., security scanner, CA |
| 41608 | NextGenWebs, S.L., Oude Meer NL |
| 213230 | Hetzner Online GmbH, Ashburn US |

`allowedAsnBotRegex` is an allowlist of legitimate bots (Birchfeed, Claude-SearchBot, Bingbot) that happen to be hosted in a blocked ASN; a match skips
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

### json-allowlist
Scanners probe for `.json` files (`/package.json`, `/composer.json`,
`/config.json`, ...). Only the five real JSON files the site serves are
allowed; every other `.json` path gets `404`. The check runs last, after the
bad-actor/bot checks, so a blocked bot gets its `410` from those rules
first and only a legitimate-looking client can reach a real JSON file. It
matches the decoded, lowercased `uriLower` exactly (no query string is part
of `uri`).

To allow another file, add it to `allowedJsonRegex` and the test fixture.

### js-allowlist
Same approach as [json-allowlist](#json-allowlist): scanners probe for
`.js` files (`/app.js`, `/main.js`, `/config.js`, ...), so only the six real
scripts the site serves are allowed and every other `.js` path gets `404`.
Runs last, after the bad-actor/bot checks. Matches the decoded, lowercased
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

CloudFront Functions run at **every edge location** with sub-millisecond startup and are ~6× cheaper than Lambda@Edge. They suit stateless, CPU-light request filtering with no network I/O. This filter is pure string matching, so it fits; the trade-off is a restricted runtime (no `setTimeout`, no `fetch`, no Node.js built-ins).

---

## Deployment

Copy the body of `function.js` into the CloudFront Functions editor in the AWS Console (or deploy via AWS CLI / CDK / Terraform) and associate it with the **viewer request** event of your distribution.

> **Important:** remove the `export { handler }` line before deploying — the JS 2.0 runtime does not support ES module `export`. It exists only so Vitest can import the function.

---

## Tests

[Vitest](https://vitest.dev/) (native ESM, zero config, Jest-compatible API).

```bash
npm test           # run once
npm run test:watch # watch mode
```

`function.test.js` builds a minimal CloudFront event (`{ request: { uri, headers } }`) and asserts on the return value: the original `request` (pass-through) or a synthetic response with `statusCode`, `headers` and `body`. It covers every rule above: scanner URIs, bot UAs, ASNs, the allowlisted URIs, the fake `/feed.xml`, empty UAs, percent-encoded URIs and pass-through.
