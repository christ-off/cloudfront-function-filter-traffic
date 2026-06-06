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
    // DENIES blocked bots — except /feed.xml (empty Atom feed, 200 OK)
    // ====================================================
    if (isBlockedBot(ua)) {
        if (/^\/feed\.xml$/.test(uri)) {
            return createEmptyFeedResponse();
        }
        return createNotFoundResponse();
    }
    // ====================================================
    // Redirect pages missing trailing slash
    // ====================================================
    if (needsTrailingSlash(uri)) {
        const correctUrl = uri + '/';
        if (isWhitelistedBot(ua)) {
            return createPermanentRedirectResponse(correctUrl);
        }
        return createTrailingSlashResponse(correctUrl);
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
    'fyndbot',
    'got (https://github.com/sindresorhus/got',
    'presto', 'trident',
    /ptst\//,
    'seamus the search engine',
    'crios',
    'webtrackrcrawler',
    'dataforseobot',
    'fxios',
    'bytespider',
    'pimeyes-downloader-api',
    'shapbot',
    'ev-crawler',
    'builtwith',
    'lanai',
    'yasearchbrowser', 'scrapy',
    'yaapp_android',
    'webscraperbot',
    'spiderling',
    'timpibot',
    'semrushbot', 'serankingbacklinksbot',
    'feedfetcher-google',
    'greedyhand/',
    'palo alto networks',
    'baiduspider',
    (ua) => isStaleChrome(ua),
    /iphone os [1-9]_/,   // iOS 1–9, all end-of-life
    'applewebkit/605.1.15 (khtml, like gecko) chrome/',
    'mozilla/5.0 (x11; ubuntu; linux x86_64; rv:147.0) gecko/20100101 firefox/147.0',
    'applewebkit/605.1.15',
    'wellknownbot',
];

function isBlockedBot(normalizedUserAgent) {
    return blockedBotPatterns.some(
        (pattern) => typeof pattern === 'string'
            ? normalizedUserAgent.includes(pattern)
            : pattern instanceof RegExp
                ? pattern.test(normalizedUserAgent)
                : pattern(normalizedUserAgent)
    );
}

const whitelistedBotPatterns = [
    'qwantbot/',
];

function isWhitelistedBot(normalizedUserAgent) {
    return whitelistedBotPatterns.some((pattern) => normalizedUserAgent.includes(pattern));
}

function needsTrailingSlash(uri) {
    if (uri.endsWith('/')) return false;
    const lastSegment = uri.split('/').pop();
    return !lastSegment.includes('.');
}

const KNOWN_CRAWLERS = ['bingbot/', 'googlebot/', 'applebot/'];

function isStaleChrome(ua) {
    if (KNOWN_CRAWLERS.some((c) => ua.includes(c))) return false;
    const m = ua.match(/chrome\/(\d+)\./);
    if (!m) return false;
    const version = parseInt(m[1], 10);
    // Chrome 120 = Oct 2024. Pre-121 in 2026 = bot indicator.
    return version <= 120;
}

function createPermanentRedirectResponse(correctUrl) {
    return {
        statusCode: 301,
        statusDescription: 'Moved Permanently',
        headers: { 'location': { value: correctUrl } },
        body: '',
    };
}

function createTrailingSlashResponse(correctUrl) {
    const safeUrl = escapeHtml(correctUrl);
    const body =
        '<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">' +
        '<meta http-equiv="refresh" content="0;url=' + safeUrl + '">' +
        '<meta name="viewport" content="width=device-width,initial-scale=1">' +
        '<title>Redirection</title>' +
        '<style>body{font-family:system-ui,sans-serif;text-align:center;' +
        'padding:2rem;margin:0;min-height:100vh;display:flex;flex-direction:column;' +
        'justify-content:center;align-items:center;background:#f5f5f5;color:#212121}' +
        'h1{font-size:1.25rem;margin:0 0 .5rem}.msg{max-width:480px;line-height:1.5;margin:0 0 1.5rem}' +
        'a{color:#1a73e8;text-decoration:none;font-weight:500}' +
        'a:hover{text-decoration:underline}</style>' +
        '</head><body>' +
        '<h1>L\'adresse n\'est pas correcte</h1>' +
        '<p class="msg">Cette page existe à une adresse légèrement différente. ' +
        'Vous allez être redirigé automatiquement.</p>' +
        '<a href="' + safeUrl + '">Accéder à la bonne adresse</a>' +
        '</body></html>';
    return {
        statusCode: 200,
        statusDescription: 'OK',
        headers: { 'content-type': { value: 'text/html; charset=UTF-8' } },
        body: body,
    };
}

function createNotFoundResponse() {
    return {
        statusCode: 404,
        statusDescription: 'Not Found',
        headers: {"content-type": {value: "text/plain"}},
        body: 'Not Found'
    };
}

function createEmptyFeedResponse() {
    return {
        statusCode: 200,
        statusDescription: 'OK',
        headers: {'content-type': {value: 'application/atom+xml'}},
        body: '<feed xmlns="http://www.w3.org/2005/Atom"></feed>'
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