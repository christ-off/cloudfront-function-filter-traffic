import cf from 'cloudfront';

// rationale: README.md#asn-kvs
const kvsHandle = cf.kvs();

// rationale: README.md#filtering-sequence
async function handler(event) {
    const request = event.request;

    // Block requests with no user agent (cheap check, done before any URI decoding)
    const userAgentHeader = request.headers['user-agent'];
    if (!userAgentHeader || !userAgentHeader.value || !userAgentHeader.value.trim()) {
        return createNotFoundResponse();
    }

    const uri = decodeUri(request.uri || '');
    if (uri === null) {
        return createNotFoundResponse();
    }

    // Lowercased copy for case-insensitive pattern matching (UA, file extensions, etc.)
    const uriLower = uri.trim().toLowerCase();
    const ua = userAgentHeader.value.toLowerCase();

    if (isBadActor(uriLower, ua) || blockedBotRegex.test(ua) ||
        isDisallowedAsset(uriLower) || isCoverDenied(uriLower, request.headers.referer)) {
        return createNotFoundResponse();
    }

    // The ASN decision comes last: it may cost a KeyValueStore read
    const asnHeader = request.headers['cloudfront-viewer-asn'];
    if (!await isAsnAllowed(asnHeader && asnHeader.value ? asnHeader.value : '', ua)) {
        return createNotFoundResponse();
    }

    return request;
}

// rationale: README.md#filtering-sequence
async function isAsnAllowed(asn, ua) {
    if (asnWhitelistRegex.test(asn) || allowedHostedSoftwareRegex.test(ua)) {
        return true;
    }
    if (blockedAsnRegex.test(asn)) {
        return false;
    }
    // Fail open: no (or unusable) ASN header, or the KeyValueStore read fails
    if (!/^\d+$/.test(asn)) {
        return true;
    }
    try {
        return await kvsHandle.exists(asn);
    } catch (_e) {
        return true;
    }
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
const allowedJsonRegex = /^\/(about\/data\/(blogs|pages|visitors)|pagefind\/pagefind-entry)\.json$/;

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
const blockedBotRegex = /linkupbot\/|sleepbot|got \(https:\/\/github\.com\/sindresorhus\/got|palo alto networks|trident|amzn-searchbot\/|ccbot\/|aiohttp\/|emacs\/|meta-webindexer\/|twitterbot\/1\.0|presto|analyseseonet\/|scrapy|headlesschrome|aranea web-crawled corpora project|pimeyes-downloader-api|bytespider|python-httpx\/|mach-o|intelx\.io_bot|welley\/|searchenginebot|python-requests\/|databankmetasearch|shapbot|cms-detector\/|navcrawl\/|wellknownbot|siteauditbot\/|ev-crawler|builtwith|timpibot|xai-searchbot\/|semrushbot|livelapbot\/|engagemiibot\/|sitescan\/|stackyenrich\/|testsearchspider|atlas-enrich\/|fyndbot|wpbot\/|googlebot|dataforseobot|imagebot\/|loadedbot\/|google-cloudvertexbot|googleother|koofie\.net\/|domain-intel\/|screaming frog seo spider|openclaw|discordbot\/|sharkey \(like|reflectionbot\/|lightpanda\/|forestengine\/|seojuice-searchbot\/|coccocbot|hubspot crawler|domain-harvester\/|mapthenetbot\/|expansel-monitor\/|fogbot\/|newsletterformresearchbot\/|srchs-research-bot\/|aionbot\/|tiktokspider|opentheboxbot\/|veryhip\/|cms-security-auditor\/|censysinspect\/|publicwwwbot\/|wp2shell|webatlabot|ssi-nutch\/|variableratio-publicassetresearch\/|halobot\/|flowb0t-contentengine\/|claritybot\/|undici|serpex-index\/|compatible; crawler\)|webapp-mapper\/|ironfountain-leads\/|what10bot\/|konqueror\/|brightbot|rust-scrape\/|crawl-engine\/|keenablebot\/|wordpress\/|curl\/|tphotobot\/|websiteresearch\/|surdotlybot\/|aonsightmetabot\/|giantcrawler\/|baiduspider|sqlspider\/|goscan-mini\/|storebot-google\/|feedfetcher-google|googleimageproxy|app::jupiter\/|httpx - open-source project/;

// rationale: README.md#asn-blocking
const blockedAsnRegex = /^(16509|14618|215125|29222|396982|1299|48090|8075|4134|23724|271315|209334|41608|213230|212238|20326|51167|53667|218785|213438|132203|201738|45102|9534|24940|197540|211619|56655|14593|18779|57043|60404|7979|62874|200651|213790|62044|136907|9009|213954|35830|43444|26548|210906|46475|12876|212286|216014|59651|19148|3257|64249|136258|30900|62387|138915|60729|201341|15169|4837)$/;

// rationale: README.md#asn-whitelist
const asnWhitelistRegex = /^(60653|199064|714)$/;

// rationale: README.md#asn-allowed-hosted-software
const allowedHostedSoftwareRegex = /bingbot\/|mastodon\/|friendica|iceshrimp|duckduckbot\/|summalybot\/|misskey\/|feedbin|birchfeed|feeder\.co|newsblur|freshrss|flus\/|kriss feed agent|miniflux/;

function createNotFoundResponse() {
    return {
        statusCode: 404,
        statusDescription: 'Not Found',
        headers: {"content-type": {value: 'text/plain'}},
        body: 'Not Found'
    };
}

export {handler};
