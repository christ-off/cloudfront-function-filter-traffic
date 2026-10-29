function handler(event) {
    const request = event.request;
    const viewerIp = (event.viewer && event.viewer.ip) || '';

    // rationale: README.md#allowlisted-uris
    if (allowlistedUriRegex.test(request.uri || '')) {
        return request;
    }

    // Block requests with no user agent (cheap check, done before any URI decoding)
    const userAgentHeader = request.headers['user-agent'];
    if (!userAgentHeader || !userAgentHeader.value || !userAgentHeader.value.trim()) {
        return createGoneResponse(request.uri || '');
    }

    const uri = decodeUri(request.uri || '');
    if (uri === null) {
        return createNotFoundResponse();
    }

    // Lowercased copy for case-insensitive pattern matching (UA, file extensions, etc.)
    const uriLower = uri.trim().toLowerCase();
    const ua = userAgentHeader.value.toLowerCase();

    // rationale: README.md#bad-actor-response-mapping
    if (isBadActor(uriLower, ua) || isBlockedIpRange(viewerIp) ||
        isBlockedAsn(request.headers['cloudfront-viewer-asn'], ua) || isBlockedBot(ua, uriLower)) {
        return createGoneResponse(uriLower);
    }

    if (isDisallowedAsset(uriLower) || isCoverDenied(uriLower, request.headers.referer)) {
        return createNotFoundResponse();
    }

    return request;
}

// rationale: README.md#uri-decoding
function decodeUri(uri) {
    try {
        for (let i = 0; i < 3 && uri.indexOf('%') !== -1; i++) {
            const decoded = decodeURIComponent(uri);
            if (decoded === uri) break;
            uri = decoded;
        }
    } catch (_e) {
        return null;
    }
    return uri;
}

// rationale: README.md#json-allowlist
// rationale: README.md#js-allowlist
function isDisallowedAsset(uri) {
    return (uri.slice(-5) === '.json' && !allowedJsonRegex.test(uri)) ||
        (uri.slice(-3) === '.js' && !allowedJsRegex.test(uri));
}

// rationale: README.md#cover-referer
function isCoverDenied(uri, referer) {
    return coverUriRegex.test(uri) &&
        (!referer || !referer.value || referer.value.toLowerCase().indexOf(COVER_REFERER_PREFIX) !== 0);
}

// rationale: README.md#cover-referer
const coverUriRegex = /^\/assets\/posts(_640)?\/.+\.webp$/;
const COVER_REFERER_PREFIX = 'https://post-tenebras-lire.net/';

// rationale: README.md#json-allowlist
const allowedJsonRegex = /^\/(about\/data\/(blogs|pages|visitors)|human|pagefind\/pagefind-entry)\.json$/;

// rationale: README.md#allowlisted-uris
const allowlistedUriRegex = /^\/(backup\.zip|robots\.txt|ads\.txt)$/i;

// rationale: README.md#js-allowlist
const allowedJsRegex = /^\/(javascript\/(recommended-blogs|chart\.umd\.min|bootstrap\.bundle\.min)|pagefind\/pagefind(-worker|-ui)?)\.js$/;

// rationale: README.md#bad-actor-check-order
function isBadActor(uri, ua) {
    return isPathTraversal(uri) ||
        isDotfilePath(uri) ||
        isSecurityScanUri(uri) ||
        isTruncatedChromeUA(ua) ||
        isMalformedChromeClaim(ua);
}

// rationale: README.md#dotfile-path
const dotfilePathRegex = /\/\./;

function isDotfilePath(uri) {
    return dotfilePathRegex.test(uri);
}

// rationale: README.md#security-scan-regex
const securityScanRegex = /\.(php\d*|sql|bak|swp|phtml|config|ya?ml|toml|conf|key|pem|axd|boto|s3cfg|htpasswd|tfstate|old|env|map|webmanifest)$|~$|^\/(images?|img|wp-includes|wp-content|wp-json|static|wp|wordpress|old|new|blog|backup|cgi-bin|admin|administrator|wp-admin|phpmyadmin|vendor|uploads|plugins|login|webmail|roundcube|mail|rc|actuator|api|@fs|@vite|userfiles|telescope|horizon|storage|debug|console|server-status|server-info|manage|graphql|v1|health|proc|var|dockerfile)(\/|$)|^\/(secrets?|config|credentials?|service[-_]account|firebase-(?:adminsdk|service-account|config)|serviceaccountkey|settings|env|auth|app-config|appsettings|openapi|swagger|amplifyconfiguration)\.json$|^\/(_|id_)/;

function isSecurityScanUri(uri) {
    return uri === '/ip' || securityScanRegex.test(uri);
}

// rationale: README.md#path-traversal
function isPathTraversal(uri) {
    return uri.indexOf('..') !== -1;
}

// rationale: README.md#truncated-chrome-ua
function isTruncatedChromeUA(ua) {
    return ua === 'mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36';
}

// rationale: README.md#malformed-chrome-claim
function isMalformedChromeClaim(ua) {
    return ua.indexOf('chrome/') !== -1 && ua.indexOf('applewebkit') === -1;
}

// rationale: README.md#blocked-bot-regex
const blockedBotRegex = /linkupbot\/|sleepbot|got \(https:\/\/github\.com\/sindresorhus\/got|palo alto networks|trident|amzn-searchbot\/|ccbot\/|aiohttp\/|emacs\/|meta-webindexer\/|twitterbot\/1\.0|presto|analyseseonet\/|scrapy|headlesschrome|aranea web-crawled corpora project|pimeyes-downloader-api|bytespider|python-httpx\/|mach-o|intelx\.io_bot|welley\/|searchenginebot|python-requests\/|databankmetasearch|shapbot|cms-detector\/|navcrawl\/|wellknownbot|siteauditbot\/|ev-crawler|builtwith|timpibot|xai-searchbot\/|semrushbot|livelapbot\/|engagemiibot\/|sitescan\/|stackyenrich\/|testsearchspider|atlas-enrich\/|fyndbot|wpbot\/|googlebot-image|dataforseobot|imagebot\/|loadedbot\/|google-cloudvertexbot|googleother|koofie\.net\/|domain-intel\/|screaming frog seo spider|openclaw|discordbot\/|sharkey \(like|reflectionbot\/|lightpanda\/|forestengine\/|seojuice-searchbot\/|coccocbot|hubspot crawler|domain-harvester\/|mapthenetbot\/|expansel-monitor\/|fogbot\/|newsletterformresearchbot\/|srchs-research-bot\/|aionbot\/|tiktokspider|opentheboxbot\/|veryhip\/|cms-security-auditor\/|censysinspect\/|publicwwwbot\/|wp2shell|webatlabot|ssi-nutch\/|variableratio-publicassetresearch\/|halobot\/|flowb0t-contentengine\/|claritybot\/|undici|serpex-index\/|compatible; crawler\)|webapp-mapper\/|ironfountain-leads\/|what10bot\/|konqueror\/|brightbot|rust-scrape\/|crawl-engine\/|keenablebot\/|wordpress\/|curl\/|tphotobot\/|websiteresearch\/|surdotlybot\/|aonsightmetabot\/|baiduspider|httpx - open-source project/;

function isBlockedBot(normalizedUserAgent, uri) {
    // rationale: README.md#feedfetcher-google
    if (normalizedUserAgent.indexOf('feedfetcher-google') !== -1) {
        return uri !== '/feed.xml';
    }
    return blockedBotRegex.test(normalizedUserAgent);
}

// rationale: README.md#ip-range-blocking
const blockedIpRangeRegex = /^(45\.148\.10\.|93\.123\.109\.|195\.178\.110\.|213\.209\.159\.|213\.177\.179\.|62\.60\.131\.|45\.138\.12\.|185\.218\.86\.)/;

function isBlockedIpRange(ip) {
    return blockedIpRangeRegex.test(ip);
}

// rationale: README.md#asn-blocking
const blockedAsnRegex = /^(16509|14618|215125|29222|396982|1299|48090|8075)$/;

const allowedAsnBotRegex = /birchfeed\/|claude-searchbot\//;

function isBlockedAsn(asnHeader, ua) {
    return !!asnHeader && blockedAsnRegex.test(asnHeader.value) && !allowedAsnBotRegex.test(ua);
}

function createNotFoundResponse() {
    return {
        statusCode: 404,
        statusDescription: 'Not Found',
        headers: {"content-type": {value: "text/plain"}},
        body: 'Not Found'
    };
}

// rationale: README.md#bad-actor-response-mapping
function createGoneResponse(uri) {
    // rationale: README.md#feed-redirect
    if (uri.toLowerCase() === '/feed.xml') {
        return {
            statusCode: 301,
            statusDescription: 'Moved Permanently',
            headers: {location: {value: '/backup.zip'}}
        };
    }
    return {
        statusCode: 410,
        statusDescription: 'Gone',
        headers: {"content-type": {value: "text/plain"}},
        body: 'Gone'
    };
}

export {handler};
