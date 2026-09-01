# CloudFront Function — fake-Chrome scraper filter (client-hint based)

Blocks scrapers that hide behind a plain desktop-Chrome User-Agent, without touching
legitimate crawlers (Bingbot, Qwantbot, Googlebot, …). Stateless — every signal is
carried by the individual request, no history needed.

Status: **reviewed 2026-09-01, not yet integrated into function.js**. See
[Review findings](#review-findings-2026-09-01) for what changed since the first draft.

## Investigation (logs.db, 7 days ending 2026-09-01)

Target UA: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36`

- 1,015 requests from **80 distinct IPs**, all datacenter (AWS SG/US 13.x/3.x/18.x/44.x,
  GCP 34.x, OVH FR/DE 141.94.x/57.129.x). Zero residential.
- 725 HTML hits vs **2 CSS hits**, 951 requests without referer → headless page scraper.
- Same UA also probes for secrets: `/credentials.json`, `/rclone.conf`, `/secrets.yml`,
  `/graphql`, `/webpack-stats.json` (397 of the hits are 404s).
- Real visitors are on Chrome **151/152** (current for Sept 2026). Chrome/148 is ~5 months
  stale and frozen across 80 IPs.
- Same pattern at larger scale under other stale majors: **Chrome/120 → 3,683 hits/week**,
  Chrome/116 → 928 (~5,600 req/week total).
- **Not in logs.db: request headers.** CloudFront standard logs do not record `sec-ch-ua`,
  so whether these scrapers send client hints is unknown until observed (see
  [Rollout](#rollout)).

## Does the function even see the headers? (verified)

Yes. Per the [event structure docs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/functions-event-structure.html),
the viewer-request `request` object "represents the actual request that CloudFront received
from the viewer"; `headers` holds one field per header (lowercased), and only `Cookie` is
split out into `cookies`. The header-stripping table (Accept, Referer, User-Agent → "Amazon
CloudFront", …) describes what CloudFront forwards to the **origin**, which happens *after*
the viewer-request function runs.

Distribution `E1Z5N5X273TPT1` (post-tenebras-lire.net) is `https-only` with
`Block_Intrusions` already attached on viewer-request. Plain HTTP never reaches the
function, so every real Chromium ≥ 89 request carries `sec-ch-ua` (low-entropy hints are
sent unconditionally over HTTPS) and `sec-fetch-*` (Chrome ≥ 76).

## Detection logic (stateless)

1. **Chrome UA without client hints = faked UA.** HTTP libraries (curl, python-requests,
   Go, aiohttp) faking a Chrome UA almost never send `sec-ch-ua` / `sec-fetch-mode`.
2. **`sec-ch-ua` must contain the UA's claimed major.** Headless Chrome that spoofed only
   the UA string leaks its real version in `sec-ch-ua`. Brand order is randomised and
   includes a GREASE brand (`"Not A(Brand";v="8"`, `v="99"`, `v="24"`), so the check must
   search the whole header for `v="<major>"`, never take the first `v=`.

### Dropped: clock-based stale-major floor

The first draft computed a minimum Chrome major from the date (Chrome 140 = Sep 2025,
13 majors/year, 4 majors grace → floor 149 today). Dropped because:

- It contradicts README [min-chrome-major](../README.md#min-chrome-major): logs.db shows
  genuine multi-country sessions at Chrome 106, 110, 116 and 131. Chrome users lag far more
  than Firefox users.
- It would block Samsung Internet (Chromium lags by months), end-of-life Android devices
  frozen on their last Chrome, and Electron-based clients.
- The formula drifts: it assumes 13 majors/year, but 140 (Sep 2025) → 152 (Sep 2026) is 12,
  so the grace shrinks by ~1 major per year.

The existing static `MIN_CHROME_MAJOR = 99` in function.js stays as the evidence-backed
floor. If a stale-major signal is ever wanted, combine it with the hint checks
("stale major AND no/mismatched hints"), never on its own.

### Crawler exemption (cross-checked against live logs)

Self-declared crawlers are exempted **before** the Chrome checks, because:

- **Bingbot would otherwise be blocked** (844 hits/week): its UA ends with
  `…compatible; bingbot/2.0; …) Chrome/116.0.1938.76 Safari/537.36` and it sends no client
  hints. Verified genuine: all traffic from Microsoft ranges (207.46.13.x, 40.77.167.x,
  52.167.144.x).
- **Qwantbot is unaffected either way**: `Mozilla/5.0 (compatible; Qwantbot/1.0…)` has no
  `Chrome/` token, so it never enters the checks. All traffic from Qwant's 194.187.171.x.
- The exemption regex (`compatible;`, `bot\b`, `bot/`) also covers Googlebot, DuckDuckBot,
  Applebot, archive.org, etc.

**The exemption must only skip the Chrome checks, not `isBlockedBot`.** Blocklist entries
such as `googlebot-image`, `petalbot`, `amazonbot/` match the exemption regex and must still
be blocked. In function.js the exemption therefore lives inside the Chrome check, not as an
early `return request` in `handler`.

Trade-off (deliberate): a scraper could evade by adding "bot" to its UA — but then it stops
hiding and becomes visible to UA-name analysis and robots.txt. Current logs show zero
fake-bingbot traffic. If that ever appears, embed Microsoft's published ranges
(https://www.bing.com/toolbox/bingbot.json) and validate `bingbot` UAs by IP.

## Function code (runtime cloudfront-js-2.0, viewer-request)

Standalone form for the console test tab. In function.js the UA is already lowercased and
`headers` is `request.headers`; add this as an `isFakeChromeUA(ua, headers)` term in
`isBadActor` (after `isSuspiciousChromeUA`) with a `// rationale: README.md#fake-chrome-ua`
pointer, and add the matching README section.

```js
function isFakeChromeUA(ua, headers) {
    // Self-declared crawlers (bingbot embeds a stale Chrome token and sends no hints).
    if (/compatible;|bot\b|bot\//.test(ua)) return false;
    var m = ua.match(/chrome\/(\d+)\./);
    if (!m) return false;
    var hints = headers['sec-ch-ua'] ? headers['sec-ch-ua'].value : '';
    // Real Chromium >= 89 always sends both over HTTPS; the distribution is https-only.
    if (!hints || !headers['sec-fetch-mode']) return true;
    // Brand order is randomised and includes a GREASE brand: search the whole header.
    return hints.indexOf('v="' + m[1] + '"') === -1;
}
```

Plain ES5 (`var`, `indexOf`, `match`), no `?.`/`??`, no `catch {}` — deployable on
cloudfront-js-2.0. Adds well under 1 kB to the 6.4 kB function (10 kB limit).

## Rollout

The core assumption — that the Chrome/148, /120, /116 scrapers omit or mismatch
`sec-ch-ua` — is **unverified**: logs.db has no headers. If they are real headless
Chromium, they send consistent hints and this filter catches nothing; only a stale-major
rule would, and that one is dropped (see above).

1. **Observe first.** Deploy with the block replaced by a log line, for Chrome UAs only:
   ```js
   console.log(m[1] + ' ' + (headers['sec-ch-ua'] ? headers['sec-ch-ua'].value : '-')
       + ' ' + (headers['sec-fetch-mode'] ? 1 : 0) + ' ' + event.viewer.ip);
   ```
   CloudFront Functions logs land in CloudWatch **us-east-1**, log group
   `/aws/cloudfront/function/Block_Intrusions`. Run for a day, then check:
   - Do the datacenter IPs from the investigation send `sec-ch-ua`? Does the major match?
   - Do any real-looking sessions (residential IPs, current Chrome) lack hints? If so,
     the filter has false positives and must not ship as a 404.
2. **Enforce** only if step 1 shows the scrapers fail the check and real users pass it.
   Use the existing `createNotFoundResponse()` (404), consistent with the rest of
   function.js, not 403.
3. Test cases for `function.test.js`:
   - Chrome/148 UA, no `sec-ch-ua` → 404
   - Chrome/152 UA with `sec-ch-ua` containing `v="152"` (GREASE brand first) → pass
   - Chrome/152 UA with `sec-ch-ua: "Chromium";v="120", …` → 404
   - Edge UA (`Chrome/152 … Edg/152`) with `"Chromium";v="152", "Microsoft Edge";v="152"` → pass
   - Bingbot UA (`compatible;` + Chrome/116, no hints) → pass
   - Qwantbot UA → pass
   - Firefox / Safari (no Chrome token) → pass

## Review findings (2026-09-01)

Summary of the review that turned the first draft into the version above:

- **Headers are available** in viewer-request functions; verified against the docs and the
  live distribution config (`https-only`, function on viewer-request).
- **Bug fixed:** the draft matched the *first* `v="…"` in `sec-ch-ua`. Chrome randomises
  brand order and includes a GREASE brand, so real Chrome would have been blocked whenever
  the GREASE brand came first.
- **Layer removed:** the clock-based stale-major floor contradicted the README evidence,
  would block Samsung Internet / EOL Android / Electron, and drifted over time.
- **Unverified premise flagged:** logs.db cannot show whether the scrapers send hints.
  Hence the observe-first rollout via `console.log`.
- **Integration constraint:** the crawler exemption must not bypass `isBlockedBot`.
- Runtime, size and ES5 compliance checked; response should be 404 to match function.js.

## Not covered (by design)

Honest bots you may still want to limit (robots.txt / the `blockedBotRegex` list), and
per-IP rate limiting (needs state → AWS WAF rate-based rules, or the WAF Anonymous IP
managed list — all 80 scraper IPs are AWS/GCP/OVH — ~$10+/month, probably unnecessary).
