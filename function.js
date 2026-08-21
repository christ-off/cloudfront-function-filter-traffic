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
    if (spoofedChromeMacRegex.test(ua) || spoofedChromeWindowsRegex.test(ua) || truncatedWindowsUaRegex.test(ua)) {
        return createNotFoundResponse();
    }

    // Malformed Chrome claim: every real Chromium browser emits "AppleWebKit/537.36
    // (KHTML, like Gecko)" immediately before the "Chrome/" token, so a UA with
    // "chrome/" but no "applewebkit" is a hand-built/incomplete UA, not a browser —
    // catches malformed strings the exact-template regexes above don't cover
    // (e.g. "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0").
    if (ua.indexOf('chrome/') !== -1 && ua.indexOf('applewebkit') === -1) {
        return createNotFoundResponse();
    }

    // Outdated or malformed Firefox UA. Google Image Proxy (Gmail, etc. fetching
    // embedded email images) hardcodes an old Firefox/11.0 UA — legitimate, not a
    // scraper, so it is exempted; the exemption substring scan only runs when the
    // Firefox rule actually fires (~1% of traffic) instead of on every request.
    if (isSuspiciousFirefoxUA(ua) && !ua.includes('googleimageproxy')) {
        return createNotFoundResponse();
    }

    // Deny blocked bots. For /robots.txt specifically, answer with a real
    // disallow-all instead of a 404 — a blocked scraper asking for robots.txt
    // gets a correct, on-brand "you're not welcome here" rather than a generic miss.
    if (isBlockedBot(ua)) {
        if (uriLower === '/robots.txt') {
            return createDisallowAllRobotsResponse();
        }
        return createNotFoundResponse();
    }

    // Pass through
    return request;
}

// Combined into a single precompiled regex: one pass over the URI covers
// extensions, folder prefixes, /.env, /.git, /.docker and known
// credential-scan filenames. The trailing .json group is NOT a blanket
// `.json$` rule — /about/data/*.json and /pagefind/*.json are real,
// legitimately-served site data — so only known credential-scan filenames
// (secrets.json, config.json, service-account.json, etc.) are matched there.
const securityScanRegex = /\.(php\d*|sql|bak|phtml|config|ya?ml|toml|conf|key|pem|axd|boto|s3cfg|npmrc|htpasswd|tfstate)$|^\/(images?|img|wp-includes|wp-content|wp-json|static|wp|wordpress|old|new|blog|backup|cgi-bin|admin|administrator|wp-admin|phpmyadmin|pma)(\/|$)|\/\.env|\/\.docker\/|^\/\.git|^\/(secrets?|config|credentials?|service[-_]account|firebase-(?:adminsdk|service-account|config)|serviceaccountkey|settings|env|auth|app-config|appsettings|openapi|swagger|amplifyconfiguration)\.json$/;

function isSecurityScanUri(uri) {
    return uri === '/ip' || securityScanRegex.test(uri);
}

// The two spoofed-Chrome full-UA templates, anchored (^ matches only at
// position 0, so the failure case is one test instead of a scan at every
// character) and split into their own regexes to keep each one's alternation
// count under the linter's complexity threshold. Chrome auto-updates and
// only ever reports its major version, so a bare .0.0.0 rule would
// false-positive on real Chrome (see CLAUDE.md) — these Chrome/major values
// and the impossible-major ranges are specific, observed-in-logs values
// gated behind their exact spoofed OS/UA template, not a general rule.
const spoofedChromeMacRegex = /^mozilla\/5\.0 \(macintosh; intel mac os x 10_15_[57]\) applewebkit\/537\.36 \(khtml, like gecko\) chrome\/(?:144|148|1[1-3]\d|\d{2})\.\d+\.\d+\.\d+ safari\/537\.36/;
const spoofedChromeWindowsRegex = /^mozilla\/5\.0 \(windows nt 10\.0; win64; x64\) applewebkit\/537\.36 \(khtml, like gecko\) chrome\/(?:142|\d{2}|1[0-2]\d)\.0\.0\.0 safari\/537\.36/;

// Truncated UA: a real browser always continues past AppleWebKit/537.36 with
// "(KHTML, like Gecko) Chrome/... Safari/...", so a string that stops dead
// right here is a bot with a copy-pasted, incomplete UA, not a real Chrome/Edge.
const truncatedWindowsUaRegex = /^mozilla\/5\.0 \(windows nt 10\.0; win64; x64\) applewebkit\/537\.36$/;

// Plain substrings matched against the (already lowercased) User-Agent header,
// as ONE regex literal. Written out literally rather than built at runtime from
// an array: a literal is compiled when the script is parsed, whereas
// `new RegExp(list.map(escape).join('|'))` re-does the escape calls, a map, a
// join and a pattern compile on every script evaluation — pure compute we were
// paying for. Alternatives are ordered most- to least-frequent per logs.db so
// common bots exit early (non-matching UAs still try every alternative).
//
// To add a bot: append `|your-token` (escaping . ( ) and / as \. \( \) \/) and add a
// UA sample to the `blockedAgents` fixture in function.test.js. Full-UA templates
// belong in spoofedChromeMacRegex / spoofedChromeWindowsRegex above instead.
const blockedBotRegex = /linkupbot\/|sleepbot|mozilla\/4\.0 \(compatible; ms-office; msoffice 16\)|got \(https:\/\/github\.com\/sindresorhus\/got|palo alto networks|petalbot|trident|amazonbot\/|oai-searchbot\/|reyilbot\/|ccbot\/|aiohttp\/|emacs\/|meta-webindexer\/|twitterbot\/1\.0|presto|lanai|analyseseonet\/|scrapy|crios|headlesschrome|aranea web-crawled corpora project|pimeyes-downloader-api|bytespider|python-httpx\/|mach-o|intelx\.io_bot|welley\/1\.0 bot|webtrackrcrawler|searchenginebot|python-requests\/|databankmetasearch|shapbot|cms-detector\/|fxios|navcrawl\/|shap-user|wellknownbot|siteauditbot\/|ptst\/|wellesley\/1\.0|pathscan\/|ev-crawler|builtwith|timpibot|xai-searchbot\/|semrushbot|greedyhand\/|yasearchbrowser|livelapbot\/|engagemiibot\/|sitescan\/|stackyenrich\/|testsearchspider|atlas-enrich\/|fyndbot|cmssurvey\/|wpbot\/|googlebot-image|rankpulsebot\/|siteanalysisbot\/|webscraperbot|serankingbacklinksbot|seamus the search engine|dataforseobot|yaapp_android|imagebot\/|perplexitybot\/|gptbot\/|loadedbot\//;

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

export {handler};