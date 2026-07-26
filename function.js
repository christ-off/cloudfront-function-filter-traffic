// Harmless static responses served to blocked bots on well-known paths.
// Purpose: a 404 on these paths would itself signal to a bot that the path
// is worth retrying/enumerating further, so we mask blocked bots with a
// believable empty payload instead — starving them of real page discovery.
const BOT_DECOYS = {
    '/feed.xml': {
        etag: '"empty-feed-v1"',
        contentType: 'application/atom+xml',
        body: '<feed xmlns="http://www.w3.org/2005/Atom"></feed>',
    },
    '/rss.xml': {
        etag: '"empty-rss-v1"',
        contentType: 'application/rss+xml',
        body: '<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel></channel></rss>',
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

    // DENIES blocked bots — except decoy paths (feed.xml,
    // rss.xml, sitemap.xml) which get harmless cached 200s
    if (isBlockedBot(ua)) {
        const decoy = BOT_DECOYS[uriLower];
        if (decoy) {
            return createDecoyResponse(request.headers, decoy);
        }
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

// Plain substrings matched case-insensitively against the User-Agent header.
// Combined below into a single precompiled regex instead of N .includes() calls.
const blockedBotSubstrings = [
    // Most frequent → least frequent (based on logs.db analysis)
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
    'googlebot-image',
    'ccbot/',
    'aranea web-crawled corpora project',
    'intelx.io_bot',
    'oai-searchbot/',
    'analyseseonet/',
    'siteauditbot/',
    'engagemiibot/',
    'amazonbot/',
    'pathscan/',
    'stackyenrich/',
    'welley/1.0 bot',
    'twitterbot/1.0',
    'meta-webindexer/',
];

function escapeRegExp(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const blockedBotRegex = new RegExp(blockedBotSubstrings.map(escapeRegExp).join('|'));

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

export {handler};
