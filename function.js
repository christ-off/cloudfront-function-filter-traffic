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
    // Always Allow robots.txt and ads.txt
    // =====================================================
    if (uri === "/robots.txt" || uri === "/ads.txt") {
        return request;
    }

    // ====================================================
    // Allow traffic-advice ( Chrome cache )
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
    // DENIES IA bots
    // ====================================================
    if (isAiBot(ua)) {
        return createNotFoundResponse();
    }

    // ====================================================
    // DENIES scrapper bots
    // ====================================================
    if (isScrapperBot(ua)) {
        return createNotFoundResponse();
    }

    // ====================================================
    // DENIES Fake user agents
    // ====================================================
    if (isFakeUserAgent(ua) || isStaleBrowserUA(ua)) {
        return createNotFoundResponse();
    }

    // Pass through
    return request;
}

function isSecurityScanUri(uri) {
    return (
        /\.(php\d?|sql|bak|phtml|phar)$/.test(uri) ||
        uri.includes('/.env') ||
        uri.startsWith('/.git') ||
        uri === '/ip' ||
        /^\/(images?|img|wp-includes|static|wp|wordpress|old|new|blog|backup|cgi-bin|admin|administrator|wp-admin|phpmyadmin|pma)(\/|$)/.test(uri)
    );
}

function isAiBot(normalizedUserAgent) {
    return (
        /addsearchbot|ai2bot|aihitbot|amazon-kendra|amazonbot|amazonbuyforme|amzn-searchbot|amzn-user|andibot|anomura|anthropic-ai|apifybot|apifywebsitecontentcrawler|applebot|atlassian-bot|awario|azureai-searchbot|bedrockbot|bigsur\.ai/.test(normalizedUserAgent) ||
        /bravebot|brightbot|buddybot|bytespider|ccbot|channel3bot|chatglm-spider|chatgpt|cloudflare-autorag|cloudvertexbot|cohere-|cotoyogi|crawl4ai|crawlspace|datenbank crawler|deepseekbot|devin|diffbot/.test(normalizedUserAgent) ||
        /duckassistbot|echobot|echoboxbot|exabot|facebookbot|factset_spyderbot|firecrawlagent|friendlycrawler|gemini-deep-research|google-cloudvertexbot|google-extended|google-firebase|google-notebooklm/.test(normalizedUserAgent) ||
        /googleagent-mariner|googleother|gptbot|henkbot|iaskbot|iaskspider|iboubot|icc-crawler|imagesiftbot|imagespider|img2dataset|isscyberriskcrawler|kangaroo bot|klaviyoaibot|kunatocrawler|laion-huggingface-processor|laiondownloader/.test(normalizedUserAgent) ||
        /linerbot|linguee bot|linkupbot|manus-user|meta-externalagent|meta-externalfetcher|meta-webindexer|mistralai-user|mycentralaiscraperbot|netestate imprint crawler|notebooklm|novaact|oai-searchbot|omgili|omgilibot/.test(normalizedUserAgent) ||
        /openai|operator|pangubot|panscient|perplexity-user|perplexitybot|petalbot|phindbot|poggio-citations|poseidon research crawler|qualifiedbot|quillbot|sbintuitionsbot|scrapy|semrushbot-ocob|semrushbot-swa/.test(normalizedUserAgent) ||
        /shapbot|sidetrade indexer bot|spider|summalybot|tavilybot|terracotta|thinkbot|tiktokspider|timpibot|twinagent|velenpublicwebcrawler|wardbot|webzio-extended|wpbot|wrtnbot|yandexadditional|youbot|zanistabot/.test(normalizedUserAgent)
    );
}

function isScrapperBot(normalizedUserAgent) {
    return (
        /yaapp_android|yasearchbrowser|ev-crawler/.test(normalizedUserAgent) ||
        /seamus the search engine/.test(normalizedUserAgent) ||
        /dataforseobot|yaapp_android|yasearchbrowser/.test(normalizedUserAgent)
    );
}

function isFakeUserAgent(normalizedUserAgent) {
    // Truncated Chrome UA — missing AppleWebKit/Safari tokens
    // Real Chrome always includes AppleWebKit/537.36 and Safari/537.36
    return (
        /mozilla.*windows nt.*chrome\/\d/.test(normalizedUserAgent) &&
        !normalizedUserAgent.includes('applewebkit') &&
        !normalizedUserAgent.includes('safari')
    );
}

function isStaleBrowserUA(ua) {
    // Allow Google PageSpeed Insights / Lighthouse regardless of Chrome version
    if (ua.includes('chrome-lighthouse')) return false;

    // Block Chrome versions below 110 (released Feb 2023)
    const match = ua.match(/chrome\/(\d+)\./);
    if (match) {
        const version = parseInt(match[1], 10);
        if (version <= 140) return true;
    }
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

function createTrafficAdviceResponse() {
    return {
        statusCode: 200,
        headers: {
            'content-type': {value: 'application/trafficadvice+json'},
            'permissions-policy': {value: 'browsing-topics=(), prefetch=()'},
            'cache-control': {value: 'max-age=63072000'}
        },
        body: '[{ "user_agent": "prefetch-proxy", "google_prefetch_proxy_eap": { "fraction": 1.0 } },{ "user_agent": "*", "accept": { "purpose": { "prefetch": true, "prerender": true },"sec-purpose": { "prefetch": true, "prerender": true }} }]'
    };
}

export {handler};