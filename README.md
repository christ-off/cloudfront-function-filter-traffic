# CloudFront Function – Traffic Filter

A [CloudFront Function](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-functions.html) (JS 2.0 runtime) designed to protect a **static website hosted on AWS S3** (no PHP). It filters incoming requests before they reach the origin or cache.

[![CodeQL](https://github.com/christ-off/cloudfront-function-filter-traffic/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/christ-off/links-checker/actions/workflows/codeql.yml) 
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=christ-off_cloudfront-function-filter-traffic&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=christ-off_cloudfront-function-filter-traffic) 
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=christ-off_cloudfront-function-filter-traffic&metric=coverage)](https://sonarcloud.io/summary/new_code?id=christ-off_cloudfront-function-filter-traffic)

## What the function does

Checks run in this order; the first match wins. Every block is a plain `404` (no fake
`robots.txt` or empty feed). Reasoning is under
[Blocking rules — rationale](#blocking-rules--rationale).

```
request
 │
 ├─ no user agent ─────────────────────────────▶ 404
 ├─ URI undecodable ───────────────────────────▶ 404
 │
 ├─ security scan: traversal, dotfile, ────────▶ 404
 │    php/wp/env/… URI, bad Chrome UA
 ├─ bad-UA regex ──────────────────────────────▶ 404
 ├─ .json/.js not allowlisted, cover referer ──▶ 404
 │    (cover check exempts hosted-software UA)
 │
 ├─ ASN in function whitelist ─────────────────▶ pass
 ├─ hosted-software UA (mastodon, bingbot, ─────▶ pass
 │    bravebot, ibou, feed readers…)
 ├─ ASN in function blocklist ─────────────────▶ 404
 ├─ no ASN header ─────────────────────────────▶ pass (fail open)
 │
 └─ KV: exists(asn)?
        ├─ yes (ISP / research) ───────────────▶ pass
        ├─ no ─────────────────────────────────▶ 404
        └─ KV error ───────────────────────────▶ pass (fail open)
```

The ASN decision comes last so that the KeyValueStore is read only for requests that
survived every cheap check. The store is filled weekly by
[`asn-kvs-sync`](../asn-kvs-sync/) with the `isp` and `education_research` ASNs (about 34.4k
keys): **an ASN missing from the store is blocked**. Plan and history:
`asn-kvs-sync/docs/ASN blocking — consolidated plan.md`.

**Google is excluded on purpose.** Blocking Google (indexing, FeedFetcher, image fetcher)
is a voluntary decision to exclude Google tools from the blog: `googlebot`,
`google-cloudvertexbot`, `googleother`, `storebot-google`, `feedfetcher-google` and
`googleimageproxy` are in the bad-UA regex, and AS15169 is on the ASN blocklist. Do not
add a Google exception (for search ranking, the feed or images) without revisiting this
decision.

Rules behind the order:

- **"pass" before the KV only skips the lookup.** The `.json`/`.js` allowlist and the
  cover-referer check run earlier and apply to every request, whitelisted ASN or not — the
  cover check excepted for hosted-software UA ([asn-allowed-hosted-software](#asn-allowed-hosted-software)),
  which fetches without a referer.
- **The ASN whitelist** holds three ASNs: AS60653 (Feedly, used only by Feedly although
  the KV category is `business`), AS199064 (Qwant) and AS714 (Apple, Applebot). It runs after
  the bad-UA regex, so a blocked bot UA from a whitelisted ASN is still blocked.
- **The hosted-software UA check sits before the ASN blocklist.** Bingbot comes from AS8075
  (Microsoft), which is blocklisted on purpose because the network hosts other tools we do not
  want; only the UA tokens (`bingbot/`, `ibou-search/`, Mastodon, feed readers…) get through it.
  AS8075 is never whitelisted by ASN.
- **The ASN blocklist stays** next to the KV. It stops the lookup for known bad ASNs and blocks
  ASNs the KV marks `isp` that we still refuse (e.g. Chinese ISPs 4134, 23724). Hosting-only
  verification still applies before adding an ASN.
- **Fail open** when the `CloudFront-Viewer-ASN` header is absent or not a number, or when the
  KV read fails (`kvs.exists` inside `try/catch`).
- **Feeds are ordinary requests**: no ASN exemption and no `feedfetcher-google` exception.
- **The handler is `async`** and the KV must be associated with the function: the deploy
  workflow passes it from the `CLOUDFRONT_KVS_ARN` secret (`KeyValueStoreAssociations`).

**Size.** `function.js` is about 7.4 KB (limit 10 KB). The bad-UA regex (1.6 KB) stays: it saves
KV reads and catches scrapers on ISP ASNs that the KV lets through.

### Feed readers

The feed is a normal request, so a reader hosted on an ASN missing from the KV
gets `404` unless its user agent (or ASN) is whitelisted. `logs.db` (`/feed.xml` and `/rss.xml`,
Nov 11 22:00 UTC to Nov 18, ASN column populated) shows who is affected:

| Reader (UA token) | Hits | ASN | Outcome without a UA token whitelist (historical, before Nov 18) |
|---|---|---|---|
| `feedly` | 1,289 | 60653 (business, used only by Feedly) | passes via the ASN whitelist |
| `feedbin` | 572 | 6939 (Hurricane Electric) | blocked |
| `birchfeed` | 152 | 400940, 16509 (AWS, blocklisted) | blocked |
| `feeder.co` | 81 | 16276 (OVH), 14061 (DigitalOcean) | blocked |
| `rss-parser` | 62 | none (8 IPs, 6 hits from 16276 OVH, rest before ASN logging) | whitelisted Nov 18, 2026: Node library default UA, feed URLs only |
| `miniflux` | 74 | 12322 (`isp` in the KV) | passes via the KV |
| `freshrss` | 42 | 16276, 24940 (blocklisted), 8560 (not in the KV), 12322 (`isp`) | blocked on 16276, 24940, 8560 |
| `newsblur` | 35 | 24940 (Hetzner, blocklisted) | blocked |
| `flus/` | 16 | 24940 | blocked |
| `inoreader` | 8 | 8717 (`isp` in the KV) | passes via the KV |
| `kriss` | 1 | 50474 (not in the KV) | blocked |
| `reeder` | 39 | 3215 (`isp` in the KV) | passes via the KV |
| `ms-office` (Outlook) | 50 | 62044 (Zscaler, blocklisted) | blocked |
| `feedfetcher-google` | 42 | 15169 | blocked (exception removed) |

Feedly is covered by the ASN whitelist (below), not by a UA token. The UA whitelist
(`allowedHostedSoftwareRegex`) contains `feedbin`, `birchfeed`, `feeder.co`,
`newsblur`, `freshrss`, `flus/`, `kriss feed agent`, `rss-parser` and `miniflux` (name tokens only,
no versions). `miniflux` passes through the KV from AS12322, but self-hosted instances on a VPS would
not, so it is whitelisted anyway. `inoreader` passes through the KV and has no UA token. Not recoverable by a UA token: one Chrome-UA client polling from AS29222 (152
hits, blocklisted, UA identical to a normal browser), Outlook behind Zscaler, and unnamed
clients on hosting ASNs. `app::jupiter/` and `emacs/` are already in `blockedBotRegex`.

KV membership was checked on Nov 18 with `aws cloudfront-keyvaluestore get-key` against
`asn-allowed-categories`: 3215, 5410, 8717, 12322 and 18403 are `isp`; 60653, 6939, 16509,
16276, 14061, 24940, 8560, 12574, 62044, 15169, 29222 and 50474 are absent.

## Compute utilization

The 2026-09-23 baseline predates the KeyValueStore lookup and the `async` handler, so it was removed.
To measure, run `aws cloudfront test-function` on the DEVELOPMENT stage with `test-event.json`
(only `request.uri` changed; the event needs a `cloudfront-viewer-asn` header to exercise the KV read).
Scale 0–100 (hard limit 100, above which CloudFront throttles). Pass-through is the worst case since
it runs every check. `ComputeUtilization` is coarse and can vary by a point or two between runs.

---

## Blocking rules — rationale

`function.js` keeps only a one-line pointer comment for anything longer than a
sentence; the full reasoning (evidence, edge cases, why a pattern is shaped
the way it is) lives here instead, to keep the deployed file under
CloudFront's 10 KB function-size limit. Each heading below matches the
identifier the code points at.

### uri-decoding
Only ~3% of URIs contain a `%`-escape (per `logs.db`); the rest skip the
`decodeURIComponent` call entirely. Decoding loops (capped at 3 rounds) rather
than running once, so a double-encoded probe like `/admin%252F.env` — which a
single decode only turns into `/admin%2F.env`, leaving the `/` hidden from the
dotfile/prefix checks — still ends up fully decoded before matching.

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
`newsletterformresearchbot/`, `srchs-research-bot/`, `aionbot/`, `sqlspider/`, `goscan-mini/`, `googlebot` (all Google search crawlers, incl. `Googlebot-Image`; the site must not be indexed by Google), `storebot-google/` (Google Merchant Center crawler), `feedfetcher-google` (Google RSS/Atom feed fetcher, UA `FeedFetcher-Google; (+http://www.google.com/feedfetcher.html)`, no `/` version; blocking it stops Google fetching the site's feeds), `googleimageproxy` (Gmail/Google image proxy, UA `... (via ggpht.com GoogleImageProxy)`; also fetches images embedded in emails, so blocking it hides images in Gmail), `app::jupiter/` (Perl `App::` module UA), `tiktokspider` (no
`/`-separated version in its UA), `opentheboxbot/`, `brightbot` (UA is `Brightbot 1.0`),
`rust-scrape/`, `webapp-mapper/`, `ironfountain-leads/`, `veryhip/`, `censysinspect/`,
`publicwwwbot/`, `wp2shell` (WordPress exploit tool), `webatlabot`, `ssi-nutch/`,
`variableratio-publicassetresearch/`, `halobot/`, `flowb0t-contentengine/`, `tphotobot/`,
`websiteresearch/`, `aonsightmetabot/`, `giantcrawler/`, `wordpress/` (pingback/XML-RPC UA), `curl/` (no
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

### filtering-sequence
The order is in [What the function does](#what-the-function-does). Principle: cheapest checks first, the
ASN decision last because it can cost a KeyValueStore read (2M reads/month free, then $0.03 per million).
Responses are all a plain `404`: a blocked client cannot tell which rule matched, and there is no
fake robots.txt or fake feed (removed Nov 18, 2026, together with the `/backup.zip` allowlist and the
feed exemption from the ASN blocklist).

### asn-kvs
`kvsHandle.exists(asn)` answers "is this ASN an ISP or research network". The store is filled by
`asn-kvs-sync` and holds only the allowed categories, so absence means block. `exists` is used rather
than `get` because `get` throws on a missing key and the value is not needed. Any error fails open.

### asn-whitelist
ASNs that skip the blocklist and the KV: 60653 (Feedly: used only by Feedly, although the ipverse
category is `business`), 199064 (Qwant), 714 (Apple).
Not whitelisted on purpose: 8075 (Microsoft,
Bingbot passes by UA) and 15169 (Google, blocklisted).

### asn-blocking
A scraper with a frozen Chrome 152 UA (`Chrome/152.0.0.0` on `X11; Linux x86_64`) crawls from a rotating pool of AWS
us-east-1 IPs (one IP per request), so blocking by IP is useless against it. Blocking the network instead covers the whole pool and
survives a UA change. CloudFront adds `CloudFront-Viewer-ASN` only when an
origin request policy asks for it (`Viewer-ASN`, attached to the distribution),
and `blockedAsnRegex` matches the header value exactly (anchored `^(...)$`).
Blocked ASNs get the usual 404. The check runs after the
cheap URI/UA checks and the ASN whitelist, and before the KeyValueStore lookup
([filtering-sequence](#filtering-sequence)). If the header is
absent (policy not attached) nothing matches: fails open.

Blocked ASNs (all at the user's request):

| ASN | Network |
|---|---|
| 15169 | Google LLC — Google's own network (Googlebot, FeedFetcher…); excluded on purpose, see "Google is excluded on purpose" above |
| 16509, 14618 | AMAZON-02, AMAZON-AES |
| 215125 | Church of Cyberology, NL scraper |
| 29222 | Infomaniak, CH feed scraper |
| 396982 | Google Cloud, NL |
| 1299 | Arelion Sweden AB |
| 48090 | Techoff SRV Limited, Amsterdam NL |
| 8075 | Microsoft Corporation, HK — hosts other tools we do not want; Bingbot gets through by UA token only, never by ASN |
| 4134 | CHINANET BACKBONE, Shijiazhuang CN |
| 4837 | CHINA UNICOM China169 Backbone, Beijing CN — consumer ISP (in the KV as `isp`); added Nov 18, 2026: the only traffic seen since Nov 11 is Baiduspider (95 hits, 74 IPs) and a few scanners with malformed UAs |
| 4766 | Korea Telecom, Seoul KR — consumer and business ISP (in the KV as `isp`); added Nov 18, 2026 on request: the only traffic seen is scrapers |
| 23724 | IDC China Telecommunications, Beijing CN |
| 199457 | SolidCore Hosting LTD, Kerkrade NL — hosting provider; added Nov 18, 2026 on request: scraper-only traffic (seen from 45.115.26.203) |
| 271315 | Netfusion Internet LTDA, Rio de Janeiro BR |
| 209334 | Modat B.V., security scanner, CA |
| 41608 | NextGenWebs, S.L., Oude Meer NL |
| 213230 | Hetzner Online GmbH, Ashburn US |
| 212238 | Datacamp Limited, Trenton US |
| 20326 | TeraSwitch Networks Inc., London GB |
| 51167 | Contabo GmbH, Lauterbourg FR |
| 53667 | FranTech Solutions, New York City US |
| 218785 | TC DATACENTER LIMITED, Warsaw PL |
| 213438 | ColocaTel Inc., Utrecht NL |
| 132203 | Tencent Cloud (Tencent Building, Kejizhongyi Avenue), Singapore SG |
| 201738 | UFO Technologies Limited, Erith GB |
| 45102 | Alibaba (US) Technology Co., Ltd. (Alibaba Cloud), Singapore SG |
| 9534 | Binariang Berhad (Maxis), Kuala Lumpur MY |
| 24940 | Hetzner Online GmbH, Helsinki FI — Bravebot crawls from here and passes by UA token ([asn-allowed-hosted-software](#asn-allowed-hosted-software)) |
| 197540 | netcup GmbH, Vienna AT |
| 211619 | MAXKO d.o.o. (maxko-hosting.net), Sofia BG |
| 56655 | Gigahost AS, Sandefjord NO |
| 14593 | Space Exploration Technologies Corporation (Starlink), Harare ZW — consumer satellite ISP |
| 18779 | EGIHosting (Electronic Group International), Santa Clara US |
| 57043 | HOSTKEY B.V., Amsterdam NL — hosting provider (dedicated servers, VPS) |
| 60404 | Liteserver, Dronten NL — hosting provider (VPS, dedicated servers) |
| 7979 | Servers.com, Inc., Dallas US — hosting provider (dedicated servers, cloud) |
| 62874 | Web2Objects LLC, Dallas US — hosting provider (VPS, dedicated servers) |
| 200651 | FlokiNET ehf, Bucharest RO — hosting provider (VPS, dedicated servers) |
| 213790 | Limited Network LTD, Vilnius LT — hosting provider (VPS, dedicated servers) |
| 62044 | Zscaler Switzerland GmbH, Zürich CH — cloud security proxy (not a hosting provider) |
| 136907 | Huawei Clouds, Singapore SG — hosting provider (cloud compute) |
| 9009 | M247 Europe SRL, Secaucus US — hosting provider (VPS, dedicated servers; also VPN exit infrastructure) |
| 35830, 43444 | Fast Servers (Pty) Ltd, São Paulo BR / New York City US — hosting provider (VPS, dedicated servers) |
| 26548 | PureVoltage Hosting Inc., Seattle US — hosting provider (dedicated servers, VPS, DDoS-protected hosting) |
| 210906 | UAB "Bite Lietuva" (BITE-US), Dallas US — datacenter IP space (~23k IPv4) behind Psychz Networks (AS40676); not the Lithuanian consumer network (AS13194) |
| 46475 | Limestone Networks, Inc., Frankfurt DE — hosting provider (dedicated servers, colocation, cloud) |
| 12876 | Scaleway SAS, Milan IT — hosting provider (cloud instances, dedicated servers; formerly Online.net) |
| 212286 | LonConnect Ltd, London GB — small hosting/VPS provider (not verified against a registry in-session) |
| 213954 | Global Transit Systems LLC (GTS-AS), Helsinki FI / registered Miami US — shell hosting / IP-leasing network; new AS (created 2025-10-29), ~14.6k IPv4 addresses geolocated mostly across Europe (not New York), no customers or direct peering, upstream is a Finnish hosting company; one aggregator (ipregistry) classes it as hosting, another as ISP; likely hosting/proxy infrastructure, not a consumer/business ISP; not verified against a registry in-session |
| 59651 | QualityNetwork, hosting provider (registered IL, geolocated Vantaa FI; not verified against a registry in-session) |
| 19148 | Leaseweb USA, Inc., Phoenix US — hosting provider (dedicated servers, cloud, CDN; not a consumer/business ISP; not verified against a registry in-session) |
| 3257 | GTT Communications Inc., Ashburn US — Tier-1 IP transit carrier / business ISP (not hosting-only; also serves enterprise customers; not verified against a registry in-session) |
| 64249 | Charles River Operation (AS name ENDOFFICE), Boston US — classified as hosting by some sources and ISP by others; unclear, not verified against a registry in-session |
| 136258 | BrainStorm Network, Inc., Miami US — hosting provider (dedicated servers/VPS/colocation; not a consumer/business ISP; not verified against a registry in-session) |
| 30900 | Sternforth Ltd. t/a WebWorld, Dublin IE — believed to be an Irish web hosting/domain provider (hosting, VPS, colocation); could also serve business connectivity customers, so possibly not hosting-only; not verified against a registry in-session |
| 62387 | meerfarbig GmbH & Co. KG, Frankfurt am Main DE — hosting provider (web hosting, servers/colocation; not a consumer ISP; not verified against a registry in-session) |
| 138915 | Kaopu Cloud HK Limited (KAOPU-HK), Wan Chai HK — cloud/hosting provider (~185k IPv4 addresses; APNIC and quantcdn `hosting`; not a consumer/business ISP); seen scanning from a single IP, 367 requests all 404 |
| 60729 | Stiftung Erneuerbare Freiheit (TORSERVERS-NET), Berlin DE — runs the torservers.net / artikel10.org Tor exit relays (e.g. `berlin01.tor-exit.artikel10.org`); anonymising-proxy infrastructure, not a consumer/business ISP; not verified against a registry in-session (`asn_info` has no category for it) |
| 201341 | trafficforce, UAB (AS name Centurion-Internet-services), Lithuania, geolocated London GB — hosting network (RIPE, ASN type hosting; ~66k IPv4; peers with other hosting providers; not a consumer/business ISP; not verified against a registry in-session) |
| 216014 | BestDC Limited, Amsterdam NL — hosting/datacenter/VPS provider; the "business" tag comes from the ASN classification, not an indication of a business ISP (not verified against a registry in-session) |

### asn-allowed-hosted-software
`allowedHostedSoftwareRegex` is an allowlist of legitimate *hosted software*: server-side software
run by third parties (Bingbot, Bravebot, ibou-search, Mastodon, Friendica, Iceshrimp, Misskey, Catodon, Nextcloud Social, DuckDuckBot,
SummalyBot link previews; ibou-search is the crawler of ibou.com, whose servers are rented and may move, so it is matched by UA, not by ASN; Catodon
ships two UA forms (`Catodon/<version> ( <instance-url>)` and `Catodon (like Discordbot)`), so it is matched on the bare name token; Nextcloud
Social is matched on the full name phrase — the bare `nextcloud` would also match the distinct `Nextcloud-Server-Crawler` UA, which is
deliberately not allowlisted) and feed readers (Feedbin, Birchfeed, Feeder, NewsBlur, FreshRSS, Flus, KrISS, Miniflux, rss-parser)
that happens to be hosted in a blocked ASN, typically a cloud provider. The name says
what it holds: software that is acceptable even though its host is not. A match skips
the ASN blocklist and the KV lookup, all other rules still apply. Matched on the name token
without version, like the bot blocklist.

Since Nov 19, 2026 the same tokens also skip the [cover-referer](#cover-referer) check: these
fetchers are server-side and send no `Referer`, so the cover rule blocked exactly the traffic
the UA allowlist exists to accept.

**Bravebot (`bravebot\/`, name token only, added Nov 19, 2026).** Brave Search crawls from
Hetzner AS24940, which is blocklisted, so without this token every Bravebot page fetch would
get `404` and Brave's own index could never crawl the blog (its robots.txt fetches still pass —
robots.txt/feed.xml are served by the separate custom-response function). Goal: be indexed by
Brave on Brave's own index, not only through the Bing fallback. The genuine crawler UA is
`Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Bravebot/1.0;
https://search.brave.com/help/brave-search-crawler) Chrome/W.X.Y.Z Safari/537.36` — the
placeholder version `Chrome/W.X.Y.Z` is Brave's own documented format. The probes spoofing the
name (`Mozilla/5.0 (compatible; Bravebot/1.0; https://brave.com/search/)`, Google Cloud IPs,
`.env`/`@fs` targets) are still stopped by the dotfile and scan-URI rules. Accepted caveat,
same as Bingbot on AS8075: a scanner spoofing the token from a blocklisted ASN could reach a
page.

### asn-header-setup
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
any AWS-hosted Linkwarden / Synapse instance (SummalyBot is already allowed by UA). If such traffic
shows up, add those UA tokens to `allowedHostedSoftwareRegex`. Some Amazon ranges are
announced from other ASNs (e.g. AS8987 EU): check bgp.he.net before extending.

### json-allowlist
Scanners probe for `.json` files (`/package.json`, `/composer.json`,
`/config.json`, ...). Only the four real JSON files the site serves are
allowed; every other `.json` path gets `404`. The check runs last, after the
bad-actor/bot checks, so a blocked bot gets its `404` from those rules
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

Exception since Nov 19, 2026: a UA matching `allowedHostedSoftwareRegex` skips this check
([asn-allowed-hosted-software](#asn-allowed-hosted-software)). Fediverse and link-preview
fetchers (Mastodon, Misskey, Friendica/Iceshrimp/Catodon, SummalyBot) fetch covers server-side
and never send a `Referer`: `logs.db` (Aug 19 – Nov 19) counted 2,214 cover fetches without a
site referer served before Nov 18 (1,546 Mastodon, 147 Misskey, 109 Friendica-family, 354
browsers, 58 other) against 152 blocked after the Nov 18 deploy — without the exception, posts
shared there lose their preview images. A *foreign* referer still gets `404` even with an
allowlisted UA (fetchers send none, so a wrong one is suspicious), and browsers opening a cover
directly stay blocked.

---

## Why a CloudFront Function (not Lambda@Edge)?

CloudFront Functions run at **every edge location** with sub-millisecond startup and are ~6× cheaper than Lambda@Edge. They suit stateless, CPU-light request filtering with no network I/O. This filter is string matching plus one KeyValueStore read (the only I/O, a built-in sub-millisecond lookup), so it fits; the trade-off is a restricted runtime (no `setTimeout`, no `fetch`, no Node.js built-ins).

---

## Deployment

The GitHub Action (`.github/workflows/deploy.yml`) runs the tests, then updates and publishes the function with the AWS CLI on every push to `main`. The function must be associated with the **viewer request** event of the distribution. To deploy by hand instead (console editor, CLI), copy the body of `function.js`.

> **Important:** the `export { handler }` line must not be deployed — the JS 2.0 runtime does not support ES module `export`. The Action strips it (`grep -v 'export {'`); do the same by hand. It exists only so Vitest can import the function. The `import cf from 'cloudfront'` line stays: it is the runtime module that gives access to the KeyValueStore (Vitest replaces it with `test-support/cloudfront-stub.js`).

The function reads the ASN KeyValueStore, so the store must be associated with it. The GitHub Action does this on every deploy (`KeyValueStoreAssociations` in `update-function`) from the repository secret `CLOUDFRONT_KVS_ARN` (output `KeyValueStoreArn` of the `asn-kvs-sync` stack). Set that secret before the first push, and make sure the deploy IAM user may associate the store. The distribution also needs the `CloudFront-Viewer-ASN` header ([asn-header-setup](#asn-header-setup)).

---

## Tests

[Vitest](https://vitest.dev/) (native ESM, zero config, Jest-compatible API).

```bash
npm test           # run once
npm run test:watch # watch mode
```

`function.test.js` builds a minimal CloudFront event (`{ request: { uri, headers } }`) and asserts on the return value: the original `request` (pass-through) or a synthetic response with `statusCode`, `headers` and `body`. It stays small on purpose: one or a few representative cases per rule (cheap checks, asset rules, ASN whitelist / hosted software / blocklist / fail-open, KeyValueStore hit / miss / error, pass-through). The `cloudfront` module only exists in the CloudFront runtime, so Vitest aliases it to `test-support/cloudfront-stub.js`, whose `kvs.exists` each test can override.
