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
    // DENIES scrapper bots
    // ====================================================
    if (isScrapperBot(ua)) {
        return createNotFoundResponse();
    }

    // ====================================================
    // DENIES too old Chrome versions (<= 123)
    // ====================================================
    if (isTooOldChrome(ua)) {
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

function isScrapperBot(normalizedUserAgent) {
    return /presto|trident|crios|fxios|yaapp_android|yasearchbrowser|ev-crawler|seamus the search engine|dataforseobot|\bptst\//.test(normalizedUserAgent);
}

function isTooOldChrome(normalizedUserAgent) {
    if (/bingbot\//.test(normalizedUserAgent)) return false;
    const match = normalizedUserAgent.match(/(?:headless)?chrome\/(\d+)/);
    if (!match) return false;
    return Number.parseInt(match[1], 10) <= 123;
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