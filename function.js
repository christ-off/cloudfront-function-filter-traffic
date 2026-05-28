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
    // Chrome Private Prefetch Proxy — traffic-advice
    // ====================================================
    if (uri === '/.well-known/traffic-advice') {
        return createTrafficAdviceResponse();
    }

    // ====================================================
    // Obvious security scans
    // ====================================================
    if (isSecurityScanUri(uri)) {
        return createNotFoundResponse();
    }

    const ua = userAgentHeader.value.toLowerCase();

    // ====================================================
    // DENIES scrapper bots
    // ====================================================
    if (isScrapperBot(ua)) {
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

const scrapperBotPatterns = [
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
];

function isScrapperBot(normalizedUserAgent) {
    return scrapperBotPatterns.some(
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

function createTrafficAdviceResponse() {
    return {
        statusCode: 200,
        headers: {
            'content-type': {value: 'application/trafficadvice+json'},
            'permissions-policy': {value: 'browsing-topics=(), prefetch=()'},
            'cache-control': {value: 'max-age=63072000'},
            'traffic-advice': {value: '1.0'}
        },
        body: '[{ "user_agent": "prefetch-proxy", "google_prefetch_proxy_eap": { "fraction": 1.0 } },{ "user_agent": "*", "accept": { "purpose": { "prefetch": true, "prerender": true },"sec-purpose": { "prefetch": true, "prerender": true }} }]'
    };
}

export {handler};