function handler(event) {
    const request = event.request;

    // Block requests with no user agent (cheap check, done before any URI decoding)
    const userAgentHeader = request.headers['user-agent'];
    if (!userAgentHeader || !userAgentHeader.value || !userAgentHeader.value.trim()) {
        return createNotFoundResponse();
    }

    // Only ~3% of URIs contain a %-escape (per logs.db); skip the decode for the rest.
    let uri = request.uri || '';
    if (uri.indexOf('%') !== -1) {
        try {
            uri = decodeURIComponent(uri);
        } catch (_e) {
            return createNotFoundResponse();
        }
    }

    // Lowercased copy for case-insensitive pattern matching (UA, file extensions, etc.)
    const uriLower = uri.trim().toLowerCase();

    // Obvious security scans
    if (isSecurityScanUri(uriLower)) {
        return createNotFoundResponse();
    }

    const ua = userAgentHeader.value.toLowerCase();

    // Anchored full-UA templates first: a ^ regex is tested at position 0 only,
    // and these two templates alone cause ~63% of UA blocks (per logs.db), so
    // most bots exit here without paying for the big alternation below.
    if (spoofedChromeTemplateRegex.test(ua)) {
        return createNotFoundResponse();
    }

    // Outdated or malformed Firefox UA. Google Image Proxy (Gmail, etc. fetching
    // embedded email images) hardcodes an old Firefox/11.0 UA — legitimate, not a
    // scraper, so it is exempted; the exemption substring scan only runs when the
    // Firefox rule actually fires (~1% of traffic) instead of on every request.
    if (isSuspiciousFirefoxUA(ua) && !ua.includes('googleimageproxy')) {
        return createNotFoundResponse();
    }

    // Deny blocked bots
    if (isBlockedBot(ua)) {
        return createNotFoundResponse();
    }

    // Pass through
    return request;
}

// Combined into a single precompiled regex instead of separate .test()/.includes()
// calls: one pass over the URI covers extensions, folder prefixes, /.env and /.git.
const securityScanRegex = /\.(php\d?|sql|bak|phtml|phar)$|^\/(images?|img|wp-includes|static|wp|wordpress|old|new|blog|backup|cgi-bin|admin|administrator|wp-admin|phpmyadmin|pma)(\/|$)|\/\.env|^\/\.git/;

function isSecurityScanUri(uri) {
    return uri === '/ip' || securityScanRegex.test(uri);
}

// The two spoofed-Chrome full-UA templates, split out of blockedBotRegex and
// anchored (they always match from position 0, so ^ makes the failure case a
// single test instead of a scan at every character).
//   - intel mac os x 10_15_5/10_15_7 ... chrome/(144|148|110-139|any 2-digit
//     major).x.x.x: OS build and trailing Chrome version digits are generalized;
//     any 2-digit major (10-99) is inherently stale since Chrome passed version
//     100 in March 2022 and auto-updates; 110-139 covers Nov 2023-mid 2024
//     majors and is a wider, deliberately-accepted-risk range rather than
//     single-version log evidence like 144/148 — see CLAUDE.md: real Chrome
//     only ever reports its major version, so a general .0.0.0 rule alone would
//     false-positive; gating on this specific spoofed OS/UA template plus
//     known-impossible majors keeps this reasonably safe.
//   - windows nt 10.0; win64; x64 ... chrome/(142|116|104|107).0.0.0: same
//     verbatim-per-version rationale as the mac entry.
const spoofedChromeTemplateRegex = /^mozilla\/5\.0 \((?:macintosh; intel mac os x 10_15_[57]\) applewebkit\/537\.36 \(khtml, like gecko\) chrome\/(?:144|148|1[1-3]\d|\d{2})\.\d+\.\d+\.\d+|windows nt 10\.0; win64; x64\) applewebkit\/537\.36 \(khtml, like gecko\) chrome\/(?:142|116|104|107)\.0\.0\.0) safari\/537\.36/;

// Plain substrings matched against the (already lowercased) User-Agent header,
// as ONE regex literal. Written out literally rather than built at runtime from an
// array: a literal is compiled when the script is parsed, whereas
// `new RegExp(list.map(escape).join('|'))` re-does the escape calls, a map, a join
// and a pattern compile on every script evaluation — pure compute we were paying for.
//
// Alternatives, in the same order (most → least frequent, per logs.db analysis
// of the 3 months up to 2026-08; only match frequency of BLOCKED requests
// matters for this order, non-matching UAs try every alternative regardless):
//   linkupbot/, sleepbot, ms-office/msoffice 16, got (sindresorhus/got),
//   palo alto networks, petalbot, trident, amazonbot/, oai-searchbot/,
//   reyilbot/, ccbot/, aiohttp/, emacs (URL/Emacs scraper), meta-webindexer/,
//   twitterbot/1.0, presto, lanai, analyseseonet/, scrapy, crios,
//   headlesschrome, aranea web-crawled corpora project, pimeyes-downloader-api,
//   bytespider, python-httpx/, mach-o (PPC-era Mac UAs — no browser has emitted
//   this token since Firefox 1.x), intelx.io_bot, welley/1.0 bot,
//   webtrackrcrawler, searchenginebot, python-requests/,
//   databankmetasearch (prefix, covers Production and Experiment variants),
//   shapbot, cms-detector/, fxios, navcrawl/, shap-user, wellknownbot,
//   siteauditbot/, ptst/ (trailing slash required, else it false-positives),
//   wellesley/1.0, pathscan/, ev-crawler, builtwith, timpibot, xai-searchbot/,
//   semrushbot, greedyhand/, yasearchbrowser, livelapbot/, engagemiibot/,
//   sitescan/, stackyenrich/, testsearchspider, atlas-enrich/, fyndbot,
//   cmssurvey/, wpbot/, googlebot-image, rankpulsebot/, siteanalysisbot/,
//   webscraperbot, serankingbacklinksbot, seamus the search engine,
//   dataforseobot, yaapp_android, imagebot/, perplexitybot/, gptbot/
//
// To add a bot: append `|your-token` (escaping . ( ) and / as \. \( \) \/) and add a
// UA sample to the `blockedAgents` fixture in function.test.js. Full-UA templates
// belong in spoofedChromeTemplateRegex above instead.
const blockedBotRegex = /linkupbot\/|sleepbot|mozilla\/4\.0 \(compatible; ms-office; msoffice 16\)|got \(https:\/\/github\.com\/sindresorhus\/got|palo alto networks|petalbot|trident|amazonbot\/|oai-searchbot\/|reyilbot\/|ccbot\/|aiohttp\/|emacs\/|meta-webindexer\/|twitterbot\/1\.0|presto|lanai|analyseseonet\/|scrapy|crios|headlesschrome|aranea web-crawled corpora project|pimeyes-downloader-api|bytespider|python-httpx\/|mach-o|intelx\.io_bot|welley\/1\.0 bot|webtrackrcrawler|searchenginebot|python-requests\/|databankmetasearch|shapbot|cms-detector\/|fxios|navcrawl\/|shap-user|wellknownbot|siteauditbot\/|ptst\/|wellesley\/1\.0|pathscan\/|ev-crawler|builtwith|timpibot|xai-searchbot\/|semrushbot|greedyhand\/|yasearchbrowser|livelapbot\/|engagemiibot\/|sitescan\/|stackyenrich\/|testsearchspider|atlas-enrich\/|fyndbot|cmssurvey\/|wpbot\/|googlebot-image|rankpulsebot\/|siteanalysisbot\/|webscraperbot|serankingbacklinksbot|seamus the search engine|dataforseobot|yaapp_android|imagebot\/|perplexitybot\/|gptbot\//;

function isBlockedBot(normalizedUserAgent) {
    return blockedBotRegex.test(normalizedUserAgent);
}

// Firefox auto-updates, so a stale major version is a scraper with a hardcoded UA, not
// a real user. 100 shipped in May 2022 and every still-maintained ESR is far above it;
// Tor Browser also reports an ESR major (115+), so privacy users are unaffected.
const MIN_FIREFOX_MAJOR = 100;

function isSuspiciousFirefoxUA(ua) {
    const ff = ua.match(/firefox\/(\d+)\./);
    if (!ff) return false;
    if (parseInt(ff[1], 10) < MIN_FIREFOX_MAJOR) return true;
    // Malformed: the rv: version must mirror the firefox/ major version
    const rv = ua.match(/rv:(\d+)\./);
    return !!rv && rv[1] !== ff[1];
}

function createNotFoundResponse() {
    return {
        statusCode: 404,
        statusDescription: 'Not Found',
        headers: {"content-type": {value: "text/plain"}},
        body: 'Not Found'
    };
}

export {handler};