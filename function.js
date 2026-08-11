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

    // Outdated or malformed Firefox UA
    if (isSuspiciousFirefoxUA(ua)) {
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
// `new RegExp(list.map(escape).join('|'))` re-does 56 escape calls, a map, a join
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
//   pathscan/, stackyenrich/, welley/1.0 bot, twitterbot/1.0, meta-webindexer/,
//   mach-o (PPC-era Mac UAs — no browser has emitted this token since Firefox 1.x),
//   testsearchspider, ptst/ (trailing slash required, else it false-positives),
//   xai-searchbot/, navcrawl/, cms-detector/, atlas-enrich/, sitescan/,
//   the intel mac os x 10_15_5/10_15_7 ... chrome/(144|148|120|any 2-digit
//   major).x.x.x scraper UAs below (OS build and trailing Chrome version
//   digits are generalized; any 2-digit major, i.e. 10-99, is inherently
//   stale since Chrome passed version 100 in March 2022 and auto-updates —
//   see CLAUDE.md: real Chrome only ever reports its major version, so a
//   general .0.0.0 rule alone would false-positive; gating on this specific
//   spoofed OS/UA template plus known-impossible majors keeps this safe),
//   livelapbot/,
//   databankmetasearch (prefix, covers Production and Experiment variants),
//   the exact windows nt 10.0; win64; x64 ... chrome/142.0.0.0,
//   chrome/116.0.0.0, chrome/104.0.0.0, and chrome/107.0.0.0 scraper UAs
//   below (same verbatim-per-version rationale as the mac entry above),
//   searchenginebot/
//
// To add a bot: append `|your-token` (escaping . ( ) and / as \. \( \) \/) and add a
// UA sample to the `blockedAgents` fixture in function.test.js.
const blockedBotRegex = /sleepbot|petalbot|got \(https:\/\/github\.com\/sindresorhus\/got|palo alto networks|semrushbot|headlesschrome|trident|presto|serankingbacklinksbot|seamus the search engine|crios|lanai|webtrackrcrawler|fxios|dataforseobot|bytespider|pimeyes-downloader-api|shapbot|shap-user|wellknownbot|ev-crawler|builtwith|timpibot|fyndbot|greedyhand\/|scrapy|yasearchbrowser|yaapp_android|webscraperbot|python-httpx\/|python-requests\/|mozilla\/4\.0 \(compatible; ms-office; msoffice 16\)|wpbot\/|siteanalysisbot\/|cmssurvey\/|reyilbot\/|wellesley\/1\.0|rankpulsebot\/|linkupbot\/|googlebot-image|ccbot\/|aranea web-crawled corpora project|intelx\.io_bot|oai-searchbot\/|analyseseonet\/|siteauditbot\/|engagemiibot\/|amazonbot\/|pathscan\/|stackyenrich\/|welley\/1\.0 bot|twitterbot\/1\.0|meta-webindexer\/|mach-o|testsearchspider|ptst\/|xai-searchbot\/|navcrawl\/|cms-detector\/|atlas-enrich\/|sitescan\/|mozilla\/5\.0 \(macintosh; intel mac os x 10_15_[57]\) applewebkit\/537\.36 \(khtml, like gecko\) chrome\/(?:144|148|120|\d{2})\.\d+\.\d+\.\d+ safari\/537\.36|livelapbot\/|databankmetasearch|mozilla\/5\.0 \(windows nt 10\.0; win64; x64\) applewebkit\/537\.36 \(khtml, like gecko\) chrome\/(?:142|116|104|107)\.0\.0\.0 safari\/537\.36|searchenginebot\//;

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
