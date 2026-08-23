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

    // Bad actors (see isBadActor) get the EICAR test string instead of the usual 404.
    if (isBadActor(uriLower, ua)) {
        return createEicarTestResponse();
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

// Security scans, truncated/malformed Chrome UAs and outdated Firefox UAs.
// Ordered most- to least-frequent (per logs.db) so common cases
// short-circuit before the rarer, costlier checks run.
function isBadActor(uri, ua) {
    return isSecurityScanUri(uri) ||
        isTruncatedChromeUA(ua) ||
        isMalformedChromeClaim(ua) ||
        isSuspiciousFirefoxUA(ua);
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

// NOTE: an exact-template match on OS/engine string plus a Chrome major-version
// range used to be treated as "spoofed" here, but real Chrome (which freezes
// its UA to major.0.0.0, and whose major version varies widely across users who
// haven't updated yet) produces this exact template too — logs.db showed the
// two most common UAs in real traffic matching it. Structure alone can't tell
// real Chrome from spoofed Chrome; don't reintroduce a version-based rule here
// (see CLAUDE.md: never block Chrome solely on the .0.0.0 minor/patch version).

// Truncated UA: a real browser always continues past AppleWebKit/537.36 with
// "(KHTML, like Gecko) Chrome/... Safari/...", so a string that stops dead
// right here is a bot with a copy-pasted, incomplete UA, not a real Chrome/Edge.
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

// Firefox auto-updates, so a stale major version is a scraper with a hardcoded UA, not
// a real user. 100 shipped in May 2022 and every still-maintained ESR is far above it;
// Tor Browser also reports an ESR major (115+), so privacy users are unaffected.
const MIN_FIREFOX_MAJOR = 100;

function isSuspiciousFirefoxUA(ua) {
    const ff = ua.match(/firefox\/(\d+)\./);
    if (!ff) return false;
    return parseInt(ff[1], 10) < MIN_FIREFOX_MAJOR;
}

// Plain substrings matched against the (already lowercased) User-Agent header,
// as ONE regex literal. Written out literally rather than built at runtime from
// an array: a literal is compiled when the script is parsed, whereas
// `new RegExp(list.map(escape).join('|'))` re-does the escape calls, a map, a
// join and a pattern compile on every script evaluation — pure compute we were
// paying for. Alternatives are ordered most- to least-frequent per logs.db so
// common bots exit early (non-matching UAs still try every alternative).
//
// To add a bot: append `|your-token` (escaping . ( ) and / as \. \( \) \/) and add a
// UA sample to the `blockedAgents` fixture in function.test.js.
const blockedBotRegex = /linkupbot\/|sleepbot|mozilla\/4\.0 \(compatible; ms-office; msoffice 16\)|got \(https:\/\/github\.com\/sindresorhus\/got|palo alto networks|petalbot|trident|amazonbot\/|oai-searchbot\/|reyilbot\/|ccbot\/|aiohttp\/|emacs\/|meta-webindexer\/|twitterbot\/1\.0|presto|lanai|analyseseonet\/|scrapy|crios|headlesschrome|aranea web-crawled corpora project|pimeyes-downloader-api|bytespider|python-httpx\/|mach-o|intelx\.io_bot|welley\/1\.0|webtrackrcrawler|searchenginebot|python-requests\/|databankmetasearch|shapbot|cms-detector\/|fxios|navcrawl\/|shap-user|wellknownbot|siteauditbot\/|ptst\/|wellesley\/1\.0|pathscan\/|ev-crawler|builtwith|timpibot|xai-searchbot\/|semrushbot|greedyhand\/|yasearchbrowser|livelapbot\/|engagemiibot\/|sitescan\/|stackyenrich\/|testsearchspider|atlas-enrich\/|fyndbot|cmssurvey\/|wpbot\/|googlebot-image|rankpulsebot\/|siteanalysisbot\/|webscraperbot|serankingbacklinksbot|seamus the search engine|dataforseobot|yaapp_android|imagebot\/|perplexitybot\/|gptbot\/|loadedbot\//;

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

// Per the EICAR spec, the body must be ONLY the 68-byte test string (no markup,
// no wrapping) — some AV/gateway engines do an exact-length or exact-prefix
// match rather than a substring scan, so HTML around it risks a false negative.
function createEicarTestResponse() {
    return {
        statusCode: 200,
        statusDescription: 'OK',
        headers: {"content-type": {value: "text/plain"}},
        body: 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
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
