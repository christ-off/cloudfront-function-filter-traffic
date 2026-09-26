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

    // rationale: README.md#gone-pages
    if (gonePageRegex.test(uriLower)) {
        return createGoneResponse();
    }

    // rationale: README.md#bad-actor-response-mapping
    if (isBadActor(uriLower, ua) || isBlockedBot(ua) || isBlockedIpRange(viewerIp)) {
        // rationale: README.md#bad-actor-response-mapping
        if (uriLower === '/feed.xml') {
            return createFakeFeedResponse();
        }
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
const allowlistedUriRegex = /^\/(backup\.zip|robots\.txt|ads\.txt)$/i;

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
const securityScanRegex = /\.(php\d*|sql|bak|swp|phtml|config|ya?ml|toml|conf|key|pem|axd|boto|s3cfg|htpasswd|tfstate|old|env|map|webmanifest)$|~$|^\/(images?|img|wp-includes|wp-content|wp-json|static|wp|wordpress|old|new|blog|backup|cgi-bin|admin|administrator|wp-admin|phpmyadmin|vendor|uploads|plugins|login|webmail|roundcube|mail|rc|actuator|api|@fs|@vite|userfiles|telescope|horizon|storage|debug|console|server-status|server-info|manage|graphql|v1|health|proc|var|dockerfile)(\/|$)|^\/(secrets?|config|credentials?|service[-_]account|firebase-(?:adminsdk|service-account|config)|serviceaccountkey|settings|env|auth|app-config|appsettings|openapi|swagger|amplifyconfiguration)\.json$|^\/(_|id_)/;

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
const safariFloorExemptRegex = /compatible;|crios\/|fxios\/|edgios\/|duckduckgo|ucbrowser\//;

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
const blockedBotRegex = /linkupbot\/|sleepbot|mozilla\/4\.0 \(compatible; ms-office; msoffice 16\)|got \(https:\/\/github\.com\/sindresorhus\/got|palo alto networks|trident|amazonbot\/|amzn-searchbot\/|reyilbot\/|ccbot\/|aiohttp\/|emacs\/|meta-webindexer\/|twitterbot\/1\.0|presto|analyseseonet\/|scrapy|crios|headlesschrome|aranea web-crawled corpora project|pimeyes-downloader-api|bytespider|python-httpx\/|mach-o|intelx\.io_bot|welley\/1\.0|searchenginebot|python-requests\/|databankmetasearch|shapbot|cms-detector\/|fxios|navcrawl\/|shap-user|wellknownbot|siteauditbot\/|wellesley\/1\.0|ev-crawler|builtwith|timpibot|xai-searchbot\/|semrushbot|livelapbot\/|engagemiibot\/|sitescan\/|stackyenrich\/|testsearchspider|atlas-enrich\/|fyndbot|wpbot\/|googlebot-image|dataforseobot|imagebot\/|perplexitybot\/|gptbot\/|loadedbot\/|google-cloudvertexbot|googleother|koofie\.net\/|feedfetcher-google|domain-intel\/|screaming frog seo spider|openclaw|discordbot\/|sharkey \(like|reflectionbot\/|lightpanda\/|forestengine\/|seojuice-searchbot\/|coccocbot|hubspot crawler|domain-harvester\/|mapthenetbot\/|expansel-monitor\/|fogbot\/|newsletterformresearchbot\/|srchs-research-bot\/|aionbot\/|tiktokspider|opentheboxbot\/|veryhip\/|cms-security-auditor\/|censysinspect\/|publicwwwbot\/|wp2shell|webatlabot|ssi-nutch\/|variableratio-publicassetresearch\/|baiduspider|halobot\/|flowb0t-contentengine\/|claritybot\/|undici|exasearchbot\/|serpex-index\/|compatible; crawler\)|webapp-mapper\/|ironfountain-leads\/|what10bot\/|konqueror\//;

function isBlockedBot(normalizedUserAgent) {
    return blockedBotRegex.test(normalizedUserAgent);
}

// rationale: README.md#gone-pages
const gonePageRegex = /^\/(les-annales-du-disque-monde-le-régiment-monstrueux|les_remèdes_du_docteur_irabu_hideo_okuda|nos_premières_fois_nicolas_teyssandier|les-machines-fantômes-olivier-paquet|le-maître-et-marguerite_mikhaïl-boulgakov|les_mémoires_d_un_chat_hiro_arikawa|la-cité-du-futur-robert-charles-wilson|dans-l-oeil-du-démon_junichirô-tanizaki|le_grand_roman_des-maths_mickaël_launay|dernières-nouvelles-de-sapiens-silvana-condemi|andromède_voyager_tome_3_stephanne_desienne|le-jugement-de-jéhovah-james-morrow|mais_qui_a_attrapé_le_bison_de_higgs_david_louapre|le_japon_moderne_et_l_éthique_samouraï|carnaval_ray-celestin|l_univers_à_portée_de_main_christophe_galfard|2012-08-28-review-le-japon-vu-de-l|2013-04-12-les-chronolithes-robert-charles-wilson|2014-01-18-histoire-suisse-jean-jacques-bouquet)\/?$/;

// rationale: README.md#ip-range-blocking
const blockedIpRangeRegex = /^(45\.148\.10\.|93\.123\.109\.|195\.178\.110\.|213\.209\.159\.|45\.138\.12\.|185\.218\.86\.)/;

function isBlockedIpRange(ip) {
    return blockedIpRangeRegex.test(ip);
}

// rationale: README.md#bad-actor-response-mapping
function createNotFoundResponse() {
    return {
        statusCode: 404,
        statusDescription: 'Not Found',
        headers: {"content-type": {value: "text/plain"}},
        body: 'Not Found'
    };
}

function createGoneResponse() {
    return {
        statusCode: 410,
        statusDescription: 'Gone',
        headers: {"content-type": {value: "text/plain"}},
        body: 'Gone'
    };
}

function createFakeFeedResponse() {
    return {
        statusCode: 200,
        statusDescription: 'OK',
        headers: {
            "content-type": {value: "application/atom+xml"},
            "cache-control": {value: "public, max-age=604800"}
        },
        body: '<?xml version="1.0" encoding="UTF-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom">' +
            '<title>Feed</title><id>tag:feed,2026-01-01:feed</id><updated>2026-01-01T00:00:00Z</updated></feed>\n'
    };
}

export {handler};
