function handler(event) {
    const request = event.request;
    let uri;
    try {
        uri = request.uri ? decodeURIComponent(request.uri).trim().toLowerCase() : '';
    } catch (_e) {
        return createNotFoundResponse();
    }

    // ====================================================
    // Block requests with no user agent
    // ====================================================
    const userAgentHeader = request.headers['user-agent'];
    if (!userAgentHeader || !userAgentHeader.value || !userAgentHeader.value.trim()) {
        return createNotFoundResponse();
    }

    // =====================================================
    // Always Allow robots.txt, ads.txt
    // =====================================================
    if (/^\/(robots\.txt|ads\.txt)$/.test(uri)) {
        return request;
    }

    // ====================================================
    // Obvious security scans
    // ====================================================
    if (isSecurityScanUri(uri)) {
        return createNotFoundResponse();
    }

    const ua = userAgentHeader.value.toLowerCase();

    // ====================================================
    // DENIES blocked bots
    // ====================================================
    if (isBlockedBot(ua)) {
        return createNotFoundResponse();
    }

    // Pass through
    return request;
}

function isSecurityScanUri(uri) {
    return (
        uri === '/ip' ||
        uri.includes('/.env') ||
        uri.startsWith('/.git') ||
        /\.(php\d?|sql|bak|phtml|phar)$/.test(uri) ||
        /^\/(images?|img|wp-includes|static|wp|wordpress|old|new|blog|backup|cgi-bin|admin|administrator|wp-admin|phpmyadmin|pma)(\/|$)/.test(uri)
    );
}

const blockedBotPatterns = [
    // Most frequent → least frequent (based on logs.db analysis)
    'petalbot',
    'sleepbot',
    'got (https://github.com/sindresorhus/got',
    'presto', 'trident',
    /ptst\//,
    'seamus the search engine',
    'crios',
    'webtrackrcrawler',
    'dataforseobot',
    'fxios',
    'pimeyes-downloader-api',
    'shapbot',
    'ev-crawler',
    'builtwith',
    'yasearchbrowser', 'scrapy',
    'yaapp_android',
    'webscraperbot',
    'spiderling',
    'timpibot',
    'semrushbot',
    'greedyhand/',
    'palo alto networks',
    'baiduspider',
    /chrome\/[1-9]?\d\.\d+(?!\d)/, // Chrome < 100 (1–99), all stale
    /iphone os [1-9]_/,   // iOS 1–9, all end-of-life
];

function isBlockedBot(normalizedUserAgent) {
    return blockedBotPatterns.some(
        (pattern) => typeof pattern === 'string'
            ? normalizedUserAgent.includes(pattern)
            : pattern.test(normalizedUserAgent)
    );
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