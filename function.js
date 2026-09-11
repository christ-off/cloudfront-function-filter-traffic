function handler(event) {
    const request = event.request;

    // Block requests with no user agent (cheap check, done before any URI decoding)
    const userAgentHeader = request.headers['user-agent'];
    if (!userAgentHeader || !userAgentHeader.value || !userAgentHeader.value.trim()) {
        return createNotFoundResponse();
    }

    // rationale: README.md#uri-decoding
    let uri = request.uri || '';
    if (uri.indexOf('%') !== -1) {
        try {
            for (let i = 0; i < 3 && uri.indexOf('%') !== -1; i++) {
                const decoded = decodeURIComponent(uri);
                if (decoded === uri) break;
                uri = decoded;
            }
        } catch (_e) {
            return createNotFoundResponse();
        }
    }

    // Lowercased copy for case-insensitive pattern matching (UA, file extensions, etc.)
    const uriLower = uri.trim().toLowerCase();
    const ua = userAgentHeader.value.toLowerCase();

    // rationale: README.md#bad-actor-response-mapping
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

    // rationale: README.md#trailing-slash-redirect
    if (needsTrailingSlashRedirect(request.uri)) {
        return createTrailingSlashRedirectResponse(request.uri);
    }

    // Pass through
    return request;
}

// rationale: README.md#bad-actor-check-order
function isBadActor(uri, ua) {
    return isPathTraversal(uri) ||
        isDotfilePath(uri) ||
        isSecurityScanUri(uri) ||
        isTruncatedChromeUA(ua) ||
        isMalformedChromeClaim(ua) ||
        isSuspiciousChromeUA(ua) ||
        isSuspiciousFirefoxUA(ua);
}

// rationale: README.md#dotfile-path
const dotfilePathRegex = /\/\./;

function isDotfilePath(uri) {
    return dotfilePathRegex.test(uri);
}

// rationale: README.md#security-scan-regex
const securityScanRegex = /\.(php\d*|sql|bak|swp|phtml|config|ya?ml|toml|conf|key|pem|axd|boto|s3cfg|htpasswd|tfstate)$|~$|^\/(images?|img|wp-includes|wp-content|wp-json|static|wp|wordpress|old|new|blog|backup|cgi-bin|admin|administrator|wp-admin|phpmyadmin|pma|vendor|uploads|plugins|login|webmail|roundcube|mail|rc|actuator|api|@fs|@vite|@id)(\/|$)|^\/(secrets?|config|credentials?|service[-_]account|firebase-(?:adminsdk|service-account|config)|serviceaccountkey|settings|env|auth|app-config|appsettings|openapi|swagger|amplifyconfiguration)\.json$/;

function isSecurityScanUri(uri) {
    return uri === '/ip' || securityScanRegex.test(uri);
}

// rationale: README.md#path-traversal
function isPathTraversal(uri) {
    return uri.indexOf('..') !== -1;
}

// rationale: README.md#truncated-chrome-ua
const UA_OPEN = 'mozilla\\/5\\.0 \\(';
const CLOSE_APPLEWEBKIT = '\\) applewebkit\\/537\\.36';
const WINDOWS_PLATFORM = 'windows nt 10\\.0; win64; x64';
const truncatedWindowsUaRegex = new RegExp('^' + UA_OPEN + WINDOWS_PLATFORM + CLOSE_APPLEWEBKIT + '$');

function isTruncatedChromeUA(ua) {
    return truncatedWindowsUaRegex.test(ua);
}

// rationale: README.md#malformed-chrome-claim
function isMalformedChromeClaim(ua) {
    return ua.indexOf('chrome/') !== -1 && ua.indexOf('applewebkit') === -1;
}

// rationale: README.md#min-chrome-major
const MIN_CHROME_MAJOR = 149;
// rationale: README.md#chrome-floor-exemptions
const chromeFloorExemptRegex = /compatible;|samsungbrowser\/|feeder\.co;|newsblur\.com|chrome-lighthouse/;

// rationale: README.md#min-firefox-major
const MIN_FIREFOX_MAJOR = 139;
// rationale: README.md#firefox-esr-115-exemption
const firefoxFloorExemptRegex = /firefox\/115\.|googleimageproxy/;

function isBelowMinMajor(ua, versionRegex, minMajor) {
    const match = ua.match(versionRegex);
    if (!match) return false;
    return parseInt(match[1], 10) < minMajor;
}

function isSuspiciousChromeUA(ua) {
    return isBelowMinMajor(ua, /chrome\/(\d+)\./, MIN_CHROME_MAJOR) && !chromeFloorExemptRegex.test(ua);
}

function isSuspiciousFirefoxUA(ua) {
    return isBelowMinMajor(ua, /firefox\/(\d+)\./, MIN_FIREFOX_MAJOR) && !firefoxFloorExemptRegex.test(ua);
}

// rationale: README.md#blocked-bot-regex
const blockedBotRegex = /linkupbot\/|sleepbot|mozilla\/4\.0 \(compatible; ms-office; msoffice 16\)|got \(https:\/\/github\.com\/sindresorhus\/got|palo alto networks|trident|amazonbot\/|amzn-searchbot\/|oai-searchbot\/|reyilbot\/|ccbot\/|aiohttp\/|emacs\/|meta-webindexer\/|twitterbot\/1\.0|presto|lanai|analyseseonet\/|scrapy|crios|headlesschrome|aranea web-crawled corpora project|pimeyes-downloader-api|bytespider|python-httpx\/|mach-o|intelx\.io_bot|welley\/1\.0|webtrackrcrawler|searchenginebot|python-requests\/|databankmetasearch|shapbot|cms-detector\/|fxios|navcrawl\/|shap-user|wellknownbot|siteauditbot\/|ptst\/|wellesley\/1\.0|pathscan\/|ev-crawler|builtwith|timpibot|xai-searchbot\/|semrushbot|greedyhand\/|yasearchbrowser|livelapbot\/|engagemiibot\/|sitescan\/|stackyenrich\/|testsearchspider|atlas-enrich\/|fyndbot|cmssurvey\/|wpbot\/|googlebot-image|rankpulsebot\/|siteanalysisbot\/|webscraperbot|serankingbacklinksbot|seamus the search engine|dataforseobot|yaapp_android|imagebot\/|perplexitybot\/|gptbot\/|loadedbot\/|google-cloudvertexbot|googleother|koofie\.net\/|feedfetcher-google|domain-intel\/|screaming frog seo spider|openclaw|discordbot\/|sharkey|reflectionbot\/|lightpanda\/|forestengine\/|seojuice-searchbot\/|coccocbot|hubspot crawler|yandex|domain-harvester\/|mapthenetbot\/|expansel-monitor\/|fogbot\/|newsletterformresearchbot\/|srchs-research-bot\/|aionbot\/|tiktokspider|opentheboxbot\/|veryhip\/|cms-security-auditor\/|censysinspect\/|publicwwwbot\//;

function isBlockedBot(normalizedUserAgent) {
    return blockedBotRegex.test(normalizedUserAgent);
}

// rationale: README.md#trailing-slash-redirect
function needsTrailingSlashRedirect(uri) {
    if (uri.charAt(uri.length - 1) === '/') return false;
    return uri.lastIndexOf('.') <= uri.lastIndexOf('/');
}

function createTrailingSlashRedirectResponse(uri) {
    return {
        statusCode: 301,
        statusDescription: 'Moved Permanently',
        headers: {location: {value: uri + '/'}}
    };
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
