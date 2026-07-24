// Harmless static responses served to blocked bots on well-known paths
const BOT_DECOYS = {
    '/robots.txt': {
        etag: '"deny-all-robots-v1"',
        contentType: 'text/plain',
        body: 'User-agent: *\nDisallow: /\n',
    },
    '/feed.xml': {
        etag: '"empty-feed-v1"',
        contentType: 'application/atom+xml',
        body: '<feed xmlns="http://www.w3.org/2005/Atom"></feed>',
    },
    '/sitemap.xml': {
        etag: '"empty-sitemap-v1"',
        contentType: 'application/xml',
        body: '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>',
    },
};

function handler(event) {
    const request = event.request;
    let uri;
    try {
        uri = request.uri ? decodeURIComponent(request.uri).trim() : '';
    } catch (_e) {
        return createNotFoundResponse();
    }

    // Lowercased copy for case-insensitive pattern matching (UA, file extensions, etc.)
    const uriLower = uri.toLowerCase();

    // Block requests with no user agent
    const userAgentHeader = request.headers['user-agent'];
    if (!userAgentHeader || !userAgentHeader.value || !userAgentHeader.value.trim()) {
        return createNotFoundResponse();
    }

    // Always allow ads.txt
    if (uriLower === '/ads.txt') {
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

    // DENIES blocked bots — except decoy paths (robots.txt,
    // feed.xml, sitemap.xml) which get harmless cached 200s
    if (isBlockedBot(ua)) {
        const decoy = BOT_DECOYS[uriLower];
        if (decoy) {
            return createDecoyResponse(request.headers, decoy);
        }
        return createNotFoundResponse();
    }

    // Always allow robots.txt for non-blocked traffic
    if (uriLower === '/robots.txt') {
        return request;
    }

    // Redirect pages missing trailing slash
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

// Plain substrings matched case-insensitively against the User-Agent header.
// Combined below into a single precompiled regex instead of N .includes() calls.
const blockedBotSubstrings = [
    // Most frequent → least frequent (based on logs.db analysis)
    'feedfetcher-google',
    'sleepbot',
    'petalbot',
    'got (https://github.com/sindresorhus/got',
    'palo alto networks',
    'semrushbot',
    'headlesschrome',
    'trident', 'presto',
    'serankingbacklinksbot',
    'seamus the search engine',
    'crios',
    'lanai',
    'webtrackrcrawler',
    'fxios',
    'dataforseobot',
    'bytespider',
    'pimeyes-downloader-api',
    'shapbot',
    'shap-user',
    'wellknownbot',
    'ev-crawler',
    'builtwith', 'timpibot',
    'fyndbot', 'greedyhand/',
    'scrapy',
    'yasearchbrowser',
    'yaapp_android',
    'webscraperbot',
    'python-httpx/',
    'python-requests/',
    'mozilla/4.0 (compatible; ms-office; msoffice 16)',
    'wpbot/',
    'siteanalysisbot/',
    'cmssurvey/',
    'reyilbot/',
    'wellesley/1.0',
    'rankpulsebot/',
    'linkupbot/',
    'gemini-deep-research',
    'googlebot-image',
    'google-cloudvertexbot',
    'google-extended',
    'google-inspectiontool',
    'ccbot/',
    'aranea web-crawled corpora project',
    'intelx.io_bot',
    'perplexitybot/',
    'oai-searchbot/',
    'analyseseonet/',
    'chatgpt-user/',
    'siteauditbot/',
    'engagemiibot/',
    'amazonbot/',
    'pathscan/',
    'googleother',
    'applebot',
    'gptbot/',
    'stackyenrich/',
    'welley/1.0 bot',
    'twitterbot/1.0',
    'facebookexternalhit/',
    'meta-webindexer/',
];

function escapeRegExp(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const blockedBotRegex = new RegExp(blockedBotSubstrings.map(escapeRegExp).join('|'));

// Patterns that aren't plain substrings: dynamic checks and structured regexes.
const blockedBotExtraPatterns = [
    (ua) => isStaleChrome(ua),
    (ua) => isStaleSafari(ua),
    /ptst\//,
];

function isBlockedBot(normalizedUserAgent) {
    if (blockedBotRegex.test(normalizedUserAgent)) return true;
    return blockedBotExtraPatterns.some((pattern) => {
        if (pattern instanceof RegExp) return pattern.test(normalizedUserAgent);
        return pattern(normalizedUserAgent);
    });
}

function isMalformedFirefoxUA(ua) {
    const rv = ua.match(/rv:(\d+)\./);
    const ff = ua.match(/firefox\/(\d+)\./);
    if (rv && ff) return rv[1] !== ff[1];
    return false;
}

const whitelistedBotPatterns = [
    'qwantbot/',
    'duckduckbot/',
];

function isWhitelistedBot(normalizedUserAgent) {
    return whitelistedBotPatterns.some((pattern) => normalizedUserAgent.includes(pattern));
}

function needsTrailingSlash(uri) {
    if (uri.endsWith('/')) return false;
    const lastSegment = uri.split('/').pop();
    return !lastSegment.includes('.');
}

const KNOWN_CRAWLERS = ['bingbot/', 'applebot/'];

function isStaleChrome(ua) {
    if (KNOWN_CRAWLERS.some((c) => ua.includes(c))) return false;
    const m = ua.match(/chrome\/(\d+)\./);
    if (!m) return false;
    const version = Number.parseInt(m[1], 10);
    // Chrome 124 = Apr 2024. Pre-125 in 2026 = bot indicator.
    return version <= 124;
}

function isStaleSafari(ua) {
    if (KNOWN_CRAWLERS.some((c) => ua.includes(c))) return false;
    const m = ua.match(/version\/(\d+)\./);
    if (!m) return false;
    const version = Number.parseInt(m[1], 10);
    // Safari 17 = macOS Sonoma (Jun 2023). Pre-17 in 2026 = bot indicator.
    if (ua.includes('iphone') || ua.includes('ipad')) {
        return version < 15;
    }
    return version < 17;
}

function createPermanentRedirectResponse(correctUrl) {
    return {
        statusCode: 301,
        statusDescription: 'Moved Permanently',
        headers: { 'location': { value: correctUrl } },
        body: '',
    };
}

const HTML_HEAD_START = '<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">';
const VIEWPORT_META = '<meta name="viewport" content="width=device-width,initial-scale=1">';
const PAGE_STYLE_BASE =
    'body{font-family:system-ui,sans-serif;text-align:center;' +
    'padding:2rem;margin:0;min-height:100vh;display:flex;flex-direction:column;' +
    'justify-content:center;align-items:center;background:#f5f5f5;color:#212121}' +
    'h1{font-size:1.25rem;margin:0 0 .5rem}.msg{max-width:480px;line-height:1.5;margin:0 0 1.5rem}' +
    'a{color:#1a73e8;text-decoration:none;font-weight:500}' +
    'a:hover{text-decoration:underline}';

function createTrailingSlashResponse(correctUrl) {
    const safeUrl = escapeHtml(correctUrl);
    const body =
        HTML_HEAD_START +
        '<meta http-equiv="refresh" content="0;url=' + safeUrl + '">' +
        VIEWPORT_META +
        '<title>Redirection</title>' +
        '<style>' + PAGE_STYLE_BASE + '</style>' +
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

const DECOY_LAST_MODIFIED = 'Mon, 01 Jan 2024 00:00:00 GMT';
const DECOY_CACHE_CONTROL = 'public, max-age=31536000';

function createDecoyResponse(headers, decoy) {
    const inm = headers && headers['if-none-match'] && headers['if-none-match'].value;
    const ims = headers && headers['if-modified-since'] && headers['if-modified-since'].value;
    if (inm === decoy.etag || ims) {
        return {
            statusCode: 304,
            statusDescription: 'Not Modified',
            headers: {
                'etag': {value: decoy.etag},
                'cache-control': {value: DECOY_CACHE_CONTROL},
            }
        };
    }
    return {
        statusCode: 200,
        statusDescription: 'OK',
        headers: {
            'content-type': {value: decoy.contentType},
            'etag': {value: decoy.etag},
            'last-modified': {value: DECOY_LAST_MODIFIED},
            'cache-control': {value: DECOY_CACHE_CONTROL},
        },
        body: decoy.body
    };
}

const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' };

function escapeHtml(str) {
    return str.replace(/[&<>"]/g, (c) => HTML_ESCAPES[c]);
}

export {handler};
