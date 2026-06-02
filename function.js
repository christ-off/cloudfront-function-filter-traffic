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
    // Always allow robots.txt and ads.txt
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

    // ====================================================
    // Google referrer → warning page (before bot blocking)
    // ====================================================
    if (isGoogleReferrer(request.headers)) {
        const referer = request.headers['referer'].value;
        const originalUrl = extractGoogleUrl(uri, referer);
        return createGoogleWarningResponse(originalUrl);
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
    'feedfetcher-google',
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

function isGoogleReferrer(headers) {
    const referer = headers['referer'];
    if (!referer || !referer.value) return false;
    return /^https?:\/\/[^/]*\.google\./.test(referer.value.toLowerCase());
}

function extractGoogleUrl(currentUri, referer) {
    // Try to extract the original URL from Google's redirect ?url= parameter
    const idx = referer.indexOf('?');
    if (idx === -1) return currentUri;
    const params = new URLSearchParams(referer.slice(idx + 1));
    const raw = params.get('url');
    if (!raw) return currentUri;
    try {
        const parsed = new URL(raw);
        return parsed.pathname.toLowerCase();
    } catch (_e) {
        return decodeURIComponent(raw).trim().toLowerCase();
    }
}

function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function createGoogleWarningResponse(originalUrl) {
    const body =
        '<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">' +
        '<meta name="viewport" content="width=device-width,initial-scale=1">' +
        '<title>Avertissement — Accès depuis Google</title>' +
        '<style>body{font-family:system-ui,sans-serif;text-align:center;' +
        'padding:2rem;margin:0;min-height:100vh;display:flex;flex-direction:column;' +
        'justify-content:center;align-items:center;background:#f5f5f5;color:#212121}' +
        'h1{font-size:1.25rem;margin:0 0 .5rem}.msg{max-width:480px;line-height:1.5;margin:0 0 1.5rem}' +
        'a{color:#1a73e8;text-decoration:none;font-weight:500}' +
        'a:hover{text-decoration:underline}.logo{font-size:2rem;margin-bottom:1rem}</style>' +
        '</head><body><div class="logo">Google</div>' +
        '<h1>Ce site apparaît dans vos résultats Google</h1>' +
        '<p class="msg">En raison de la politique prédatrice de Google, ce site ne sera bientôt plus référencé dans ses résultats. Nous vous invitons à utiliser un autre moteur de recherche pour le retrouver. ' +
        'Pour accéder à la page originale, cliquez ci-dessous :</p>' +
        '<a href="' + escapeHtml(originalUrl) + '">Accéder à la page originale</a>' +
        '</body></html>';
    return {
        statusCode: 200,
        statusDescription: 'OK',
        headers: {
            'content-type': { value: 'text/html; charset=UTF-8' },
            'cache-control': { value: 'no-cache, no-store' },
        },
        body: body,
    };
}

export {handler};