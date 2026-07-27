function handler(event) {
    const request = event.request;

    // Block requests with no user agent (cheap check, done before any URI decoding)
    const userAgentHeader = request.headers['user-agent'];
    if (!userAgentHeader || !userAgentHeader.value || !userAgentHeader.value.trim()) {
        return createNotFoundResponse();
    }

    let uri;
    try {
        uri = request.uri ? decodeURIComponent(request.uri).trim() : '';
    } catch (_e) {
        return createNotFoundResponse();
    }

    // Lowercased copy for case-insensitive pattern matching (UA, file extensions, etc.)
    const uriLower = uri.toLowerCase();

    // Always allow ads.txt, robots.txt and llms.txt
    if (uriLower === '/ads.txt' || uriLower === '/robots.txt' || uriLower === '/llms.txt') {
        return request;
    }

    // Obvious security scans
    if (isSecurityScanUri(uriLower)) {
        return createNotFoundResponse();
    }

    const ua = userAgentHeader.value.toLowerCase();

    // Malformed Firefox UA (rv: version != firefox/ version)
    if (isMalformedFirefoxUA(ua)) {
        return createNotFoundResponse();
    }

    // Deny blocked bots
    if (isBlockedBot(ua)) {
        return createNotFoundResponse();
    }

    // Pass through
    return request;
}

// Combined into a single precompiled regex instead of two separate .test() calls.
const securityScanRegex = /\.(php\d?|sql|bak|phtml|phar)$|^\/(images?|img|wp-includes|static|wp|wordpress|old|new|blog|backup|cgi-bin|admin|administrator|wp-admin|phpmyadmin|pma)(\/|$)/;

function isSecurityScanUri(uri) {
    return (
        uri === '/ip' ||
        uri.includes('/.env') ||
        uri.startsWith('/.git') ||
        securityScanRegex.test(uri)
    );
}

// Plain substrings matched against the (already lowercased) User-Agent header,
// as ONE regex literal. Written out literally rather than built at runtime from an
// array: a literal is compiled when the script is parsed, whereas
// `new RegExp(list.map(escape).join('|'))` re-does 53 escape calls, a map, a join
// and a pattern compile on every script evaluation — pure compute we were paying for.
//
// Alternatives, in the same order (most → least frequent, per logs.db analysis):
//   sleepbot, petalbot, got (sindresorhus/got), palo alto networks, semrushbot,
//   headlesschrome, trident, presto, serankingbacklinksbot, seamus the search engine,
//   crios, lanai, webtrackrcrawler, fxios, dataforseobot, bytespider,
//   pimeyes-downloader-api, shapbot, shap-user, wellknownbot, ev-crawler, builtwith,
//   timpibot, fyndbot, greedyhand/, scrapy, yasearchbrowser, yaapp_android,
//   webscraperbot, python-httpx/, python-requests/, ms-office/msoffice 16, wpbot/,
//   siteanalysisbot/, cmssurvey/, reyilbot/, wellesley/1.0, rankpulsebot/, linkupbot/,
//   googlebot-image, ccbot/, aranea web-crawled corpora project, intelx.io_bot,
//   oai-searchbot/, analyseseonet/, siteauditbot/, engagemiibot/, amazonbot/,
//   pathscan/, stackyenrich/, welley/1.0 bot, twitterbot/1.0, meta-webindexer/
//
// To add a bot: append `|your-token` (escaping . ( ) and / as \. \( \) \/) and add a
// UA sample to the `blockedAgents` fixture in function.test.js.
const blockedBotRegex = /sleepbot|petalbot|got \(https:\/\/github\.com\/sindresorhus\/got|palo alto networks|semrushbot|headlesschrome|trident|presto|serankingbacklinksbot|seamus the search engine|crios|lanai|webtrackrcrawler|fxios|dataforseobot|bytespider|pimeyes-downloader-api|shapbot|shap-user|wellknownbot|ev-crawler|builtwith|timpibot|fyndbot|greedyhand\/|scrapy|yasearchbrowser|yaapp_android|webscraperbot|python-httpx\/|python-requests\/|mozilla\/4\.0 \(compatible; ms-office; msoffice 16\)|wpbot\/|siteanalysisbot\/|cmssurvey\/|reyilbot\/|wellesley\/1\.0|rankpulsebot\/|linkupbot\/|googlebot-image|ccbot\/|aranea web-crawled corpora project|intelx\.io_bot|oai-searchbot\/|analyseseonet\/|siteauditbot\/|engagemiibot\/|amazonbot\/|pathscan\/|stackyenrich\/|welley\/1\.0 bot|twitterbot\/1\.0|meta-webindexer\//;

// ptst/ isn't a plain substring match (needs the trailing slash to avoid false positives).
const ptstRegex = /ptst\//;

function isBlockedBot(normalizedUserAgent) {
    return blockedBotRegex.test(normalizedUserAgent) || ptstRegex.test(normalizedUserAgent);
}

function isMalformedFirefoxUA(ua) {
    const rv = ua.match(/rv:(\d+)\./);
    const ff = ua.match(/firefox\/(\d+)\./);
    if (rv && ff) return rv[1] !== ff[1];
    return false;
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
