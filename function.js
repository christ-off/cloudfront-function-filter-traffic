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
    const ua = userAgentHeader.value.toLowerCase();

    // Deny bad actors and blocked bots alike. For /robots.txt, /sitemap.xml and
    // /feed.xml specifically, answer with a real disallow-all / empty sitemap /
    // empty feed instead of a 404 — a bad actor or blocked scraper asking for
    // any of these gets a correct, on-brand "you're not welcome here" rather
    // than a generic miss.
    if (isBadActor(uriLower, ua) || isBlockedBot(ua)) {
        if (uriLower === '/robots.txt') {
            return createDisallowAllRobotsResponse();
        }
        if (uriLower === '/sitemap.xml') {
            return createEmptySitemapResponse();
        }
        if (uriLower === '/feed.xml') {
            return createEmptyFeedResponse();
        }
        return createNotFoundResponse();
    }

    // Pass through
    return request;
}

// Security scans, truncated/malformed Chrome UAs and outdated Firefox UAs.
// Ordered most- to least-frequent (per logs.db) so common cases
// short-circuit before the rarer, costlier checks run.
function isBadActor(uri, ua) {
    return isSecurityScanUri(uri) ||
        isTruncatedChromeUA(ua) ||
        isMalformedChromeClaim(ua) ||
        isFullVersionChromeUA(ua) ||
        isSuspiciousChromeUA(ua) ||
        isSuspiciousFirefoxUA(ua) ||
        isKnownBadExactUA(ua);
}

// UAs structurally indistinguishable from real traffic but confirmed bad by
// request pattern (bursty /.php and / from a few IPs), not by structure —
// so unlike isSuspiciousChromeUA this does NOT generalize to a template.
const knownBadExactUAs = [
    'mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/120.0.0.0 safari/537.36'
];

function isKnownBadExactUA(ua) {
    return knownBadExactUAs.indexOf(ua) !== -1;
}

// Combined into a single precompiled regex: one pass over the URI covers
// extensions, folder prefixes, /.env, /.git, /.docker and known
// credisential-scan filenames. The trailing .json group is NOT a blanket
// `.json$` rule — /about/data/*.json and /pagefind/*.json are real,
// legitimately-served site data — so only known credential-scan filenames
// (secrets.json, config.json, service-account.json, etc.) are matched there.
const securityScanRegex = /\.(php\d*|sql|bak|phtml|config|ya?ml|toml|conf|key|pem|axd|boto|s3cfg|npmrc|htpasswd|tfstate)$|^\/(images?|img|wp-includes|wp-content|wp-json|static|wp|wordpress|old|new|blog|backup|cgi-bin|admin|administrator|wp-admin|phpmyadmin|pma|vendor|uploads|plugins|login|webmail|roundcube|mail|rc)(\/|$)|\/\.env|\/\.docker\/|^\/\.git|^\/(secrets?|config|credentials?|service[-_]account|firebase-(?:adminsdk|service-account|config)|serviceaccountkey|settings|env|auth|app-config|appsettings|openapi|swagger|amplifyconfiguration)\.json$/;

function isSecurityScanUri(uri) {
    return uri === '/ip' || securityScanRegex.test(uri);
}

// Shared literal fragments of the truncated-Chrome full-UA template below,
// factored out for readability. Composed into a RegExp object once, at parse
// time — not rebuilt per request.
const UA_OPEN = 'mozilla\\/5\\.0 \\(';
const CLOSE_APPLEWEBKIT = '\\) applewebkit\\/537\\.36';
const WINDOWS_PLATFORM = 'windows nt 10\\.0; win64; x64';

// Real Chrome freezes its UA to major.0.0.0 (see CLAUDE.md: never block on
// that alone) — see MIN_CHROME_MAJOR below for the evidence-backed floor.

// A real browser always continues past AppleWebKit/537.36 with
// "(KHTML, like Gecko) Chrome/... Safari/..."; a string that stops dead
// right here is a bot with a copy-pasted, incomplete UA.
const truncatedWindowsUaRegex = new RegExp('^' + UA_OPEN + WINDOWS_PLATFORM + CLOSE_APPLEWEBKIT + '$');

function isTruncatedChromeUA(ua) {
    return truncatedWindowsUaRegex.test(ua);
}

// Every real Chromium browser emits "AppleWebKit/537.36 (KHTML, like Gecko)"
// immediately before the "Chrome/" token, so a UA with "chrome/" but no
// "applewebkit" is a hand-built/incomplete UA, not a browser — catches
// malformed strings the exact-template regexes above don't cover (e.g.
// "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0").
function isMalformedChromeClaim(ua) {
    return ua.indexOf('chrome/') !== -1 && ua.indexOf('applewebkit') === -1;
}

// Below Chrome/99 (March 2022), logs.db shows no organic signal — no real
// multi-country sessions loading real assets. Chrome users lag updates far
// more than Firefox users, so this floor is much lower than MIN_FIREFOX_MAJOR.
// Chrome 113+ froze the Chrome token to "major.0.0.0" (User-Agent Reduction) —
// a full build/patch there (e.g. "Chrome/130.0.6723.70") is a scraper on a
// stale template. Excludes majors <113 (full versions were real pre-freeze,
// see Chrome/99.0.4844.51 below) and "compatible;" crawlers (e.g. Bingbot
// legitimately ships a full version as part of its documented template).
const CHROME_UA_FREEZE_MAJOR = 113;
const chromeVersionRegex = /chrome\/(\d+)\.(\d+\.\d+\.\d+)/;

function isFullVersionChromeUA(ua) {
    if (ua.indexOf('compatible;') !== -1) return false;
    const match = ua.match(chromeVersionRegex);
    if (!match) return false;
    if (parseInt(match[1], 10) < CHROME_UA_FREEZE_MAJOR) return false;
    return match[2] !== '0.0.0';
}

const MIN_CHROME_MAJOR = 99;

// Firefox auto-updates, so a stale major is a hardcoded scraper UA, not a real
// user. 100 (May 2022) is below every maintained ESR, Tor's included (115+).
const MIN_FIREFOX_MAJOR = 100;

function isBelowMinMajor(ua, versionRegex, minMajor) {
    const match = ua.match(versionRegex);
    if (!match) return false;
    return parseInt(match[1], 10) < minMajor;
}

function isSuspiciousChromeUA(ua) {
    return isBelowMinMajor(ua, /chrome\/(\d+)\./, MIN_CHROME_MAJOR);
}

function isSuspiciousFirefoxUA(ua) {
    return isBelowMinMajor(ua, /firefox\/(\d+)\./, MIN_FIREFOX_MAJOR);
}

// Plain substrings matched against the lowercased UA, as ONE precompiled regex
// literal (cheaper than building one from an array at runtime). Ordered most-
// to least-frequent per logs.db.
//
// To add a bot: append `|your-token` (escaping . ( ) / as \. \( \) \/) and add
// a UA sample to `blockedAgents` in function.test.js.
const blockedBotRegex = /linkupbot\/|sleepbot|mozilla\/4\.0 \(compatible; ms-office; msoffice 16\)|got \(https:\/\/github\.com\/sindresorhus\/got|palo alto networks|petalbot|trident|amazonbot\/|amzn-searchbot\/|oai-searchbot\/|reyilbot\/|ccbot\/|aiohttp\/|emacs\/|meta-webindexer\/|twitterbot\/1\.0|presto|lanai|analyseseonet\/|scrapy|crios|headlesschrome|aranea web-crawled corpora project|pimeyes-downloader-api|bytespider|python-httpx\/|mach-o|intelx\.io_bot|welley\/1\.0|webtrackrcrawler|searchenginebot|python-requests\/|databankmetasearch|shapbot|cms-detector\/|fxios|navcrawl\/|shap-user|wellknownbot|siteauditbot\/|ptst\/|wellesley\/1\.0|pathscan\/|ev-crawler|builtwith|timpibot|xai-searchbot\/|semrushbot|greedyhand\/|yasearchbrowser|livelapbot\/|engagemiibot\/|sitescan\/|stackyenrich\/|testsearchspider|atlas-enrich\/|fyndbot|cmssurvey\/|wpbot\/|googlebot-image|rankpulsebot\/|siteanalysisbot\/|webscraperbot|serankingbacklinksbot|seamus the search engine|dataforseobot|yaapp_android|imagebot\/|perplexitybot\/|gptbot\/|loadedbot\/|google-cloudvertexbot|googleother|koofie\.net\/|feedfetcher-google|domain-intel\/|screaming frog seo spider|openclaw/;

function isBlockedBot(normalizedUserAgent) {
    return blockedBotRegex.test(normalizedUserAgent);
}

function createNotFoundResponse() {
    return {
        statusCode: 404,
        statusDescription: 'Not Found',
        headers: {"content-type": {value: "text/plain"}},
        body: 'Not Found'
    };
}

function createDisallowAllRobotsResponse() {
    return {
        statusCode: 200,
        statusDescription: 'OK',
        headers: {
            "content-type": {value: "text/plain"},
            "cache-control": {value: "public, max-age=86400"}
        },
        body: 'User-agent: *\nDisallow: /\n'
    };
}

function createEmptySitemapResponse() {
    return {
        statusCode: 200,
        statusDescription: 'OK',
        headers: {
            "content-type": {value: "application/xml"},
            "cache-control": {value: "public, max-age=86400"}
        },
        body: '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>\n'
    };
}

function createEmptyFeedResponse() {
    return {
        statusCode: 200,
        statusDescription: 'OK',
        headers: {
            "content-type": {value: "application/atom+xml"},
            "cache-control": {value: "public, max-age=86400"}
        },
        body: '<?xml version="1.0" encoding="UTF-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom"></feed>\n'
    };
}

export {handler};
