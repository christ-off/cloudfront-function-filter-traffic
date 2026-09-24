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
    if (isBadActor(uriLower, ua) || isBlockedBot(ua) || isBlockedIpRange(viewerIp)) {
        return createNotFoundResponse();
    }

    // rationale: README.md#json-allowlist
    if (uriLower.slice(-5) === '.json' && !allowedJsonRegex.test(uriLower)) {
        return createNotFoundResponse();
    }

    // rationale: README.md#js-allowlist
    if (uriLower.slice(-3) === '.js' && !allowedJsRegex.test(uriLower)) {
        return createNotFoundResponse();
    }

    // Pass through
    return request;
}

// rationale: README.md#json-allowlist
const allowedJsonRegex = /^\/(about\/data\/(blogs|pages|visitors)|human|pagefind\/pagefind-entry)\.json$/;

// rationale: README.md#allowlisted-uris
const allowlistedUriRegex = /^\/backup\.zip$/i;

// rationale: README.md#js-allowlist
const allowedJsRegex = /^\/(javascript\/(recommended-blogs|chart\.umd\.min|bootstrap\.bundle\.min)|pagefind\/pagefind(-worker|-ui)?)\.js$/;

// rationale: README.md#bad-actor-check-order
function isBadActor(uri, ua) {
    return isPathTraversal(uri) ||
        isDotfilePath(uri) ||
        isSecurityScanUri(uri) ||
        isTruncatedChromeUA(ua) ||
        isMalformedChromeClaim(ua) ||
        isSuspiciousChromeUA(ua) ||
        isSuspiciousEdgeUA(ua) ||
        isSuspiciousFirefoxUA(ua) ||
        isSuspiciousSafariUA(ua);
}

// rationale: README.md#dotfile-path
const dotfilePathRegex = /\/\./;

function isDotfilePath(uri) {
    return dotfilePathRegex.test(uri);
}

// rationale: README.md#security-scan-regex
const securityScanRegex = /\.(php\d*|sql|bak|swp|phtml|config|ya?ml|toml|conf|key|pem|axd|boto|s3cfg|htpasswd|tfstate|old|env|map|webmanifest)$|~$|^\/(images?|img|wp-includes|wp-content|wp-json|static|wp|wordpress|old|new|blog|backup|cgi-bin|admin|administrator|wp-admin|phpmyadmin|pma|vendor|uploads|plugins|login|webmail|roundcube|mail|rc|actuator|api|read-document|@fs|@vite|@id|userfiles|telescope|horizon|storage|debug|console|server-status|server-info|manage|graphql|v1|health|proc|var|dockerfile)(\/|$)|^\/(secrets?|config|credentials?|service[-_]account|firebase-(?:adminsdk|service-account|config)|serviceaccountkey|settings|env|auth|app-config|appsettings|openapi|swagger|amplifyconfiguration)\.json$|^\/(_|id_)/;

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

// rationale: README.md#min-edge-major
const MIN_EDGE_MAJOR = 150;

// rationale: README.md#min-firefox-major
const MIN_FIREFOX_MAJOR = 139;
// rationale: README.md#firefox-esr-115-exemption
const firefoxFloorExemptRegex = /firefox\/115\.|googleimageproxy/;

// rationale: README.md#min-safari-major
const MIN_SAFARI_MAJOR = 17;
// rationale: README.md#safari-floor-exemptions
const safariFloorExemptRegex = /compatible;|crios\/|fxios\/|edgios\/|opios\/|duckduckgo|ucbrowser\//;

function isBelowMinMajor(ua, versionRegex, minMajor) {
    const match = ua.match(versionRegex);
    if (!match) return false;
    return parseInt(match[1], 10) < minMajor;
}

function isSuspiciousChromeUA(ua) {
    return isBelowMinMajor(ua, /chrome\/(\d+)\./, MIN_CHROME_MAJOR) && !chromeFloorExemptRegex.test(ua);
}

function isSuspiciousEdgeUA(ua) {
    return isBelowMinMajor(ua, /edg\/(\d+)\./, MIN_EDGE_MAJOR) && !chromeFloorExemptRegex.test(ua);
}

function isSuspiciousFirefoxUA(ua) {
    return isBelowMinMajor(ua, /firefox\/(\d+)\./, MIN_FIREFOX_MAJOR) && !firefoxFloorExemptRegex.test(ua);
}

function isSuspiciousSafariUA(ua) {
    return ua.indexOf('safari/') !== -1 &&
        isBelowMinMajor(ua, /version\/(\d+)\./, MIN_SAFARI_MAJOR) &&
        !safariFloorExemptRegex.test(ua);
}

// rationale: README.md#blocked-bot-regex
const blockedBotRegex = /linkupbot\/|sleepbot|mozilla\/4\.0 \(compatible; ms-office; msoffice 16\)|got \(https:\/\/github\.com\/sindresorhus\/got|palo alto networks|trident|amazonbot\/|amzn-searchbot\/|reyilbot\/|ccbot\/|aiohttp\/|emacs\/|meta-webindexer\/|twitterbot\/1\.0|presto|lanai|analyseseonet\/|scrapy|crios|headlesschrome|aranea web-crawled corpora project|pimeyes-downloader-api|bytespider|python-httpx\/|mach-o|intelx\.io_bot|welley\/1\.0|webtrackrcrawler|searchenginebot|python-requests\/|databankmetasearch|shapbot|cms-detector\/|fxios|navcrawl\/|shap-user|wellknownbot|siteauditbot\/|ptst\/|wellesley\/1\.0|pathscan\/|ev-crawler|builtwith|timpibot|xai-searchbot\/|semrushbot|greedyhand\/|yasearchbrowser|livelapbot\/|engagemiibot\/|sitescan\/|stackyenrich\/|testsearchspider|atlas-enrich\/|fyndbot|cmssurvey\/|wpbot\/|googlebot-image|rankpulsebot\/|siteanalysisbot\/|webscraperbot|seamus the search engine|dataforseobot|yaapp_android|imagebot\/|perplexitybot\/|gptbot\/|loadedbot\/|google-cloudvertexbot|googleother|koofie\.net\/|feedfetcher-google|domain-intel\/|screaming frog seo spider|openclaw|discordbot\/|sharkey \(like|reflectionbot\/|lightpanda\/|forestengine\/|seojuice-searchbot\/|coccocbot|hubspot crawler|domain-harvester\/|mapthenetbot\/|expansel-monitor\/|fogbot\/|newsletterformresearchbot\/|srchs-research-bot\/|aionbot\/|tiktokspider|opentheboxbot\/|veryhip\/|cms-security-auditor\/|censysinspect\/|publicwwwbot\/|wp2shell|webatlabot|ssi-nutch\/|variableratio-publicassetresearch\/|baiduspider|halobot\/|flowb0t-contentengine\/|claritybot\/|undici|jscrawler\/|exasearchbot\/|serpex-index\/|compatible; crawler\)|webapp-mapper\/|ironfountain-leads\/|colly/;

function isBlockedBot(normalizedUserAgent) {
    return blockedBotRegex.test(normalizedUserAgent);
}

// rationale: README.md#ip-range-blocking
const blockedIpRangeRegex = /^(45\.148\.10\.|93\.123\.109\.|195\.178\.110\.|213\.177\.179\.|62\.60\.131\.|213\.209\.159\.)/;

function isBlockedIpRange(ip) {
    return blockedIpRangeRegex.test(ip);
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
