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

function isAiBot(normalizedUserAgent) {
    return /addsearchbot|aihitbot|amazon-kendra|amazonbuyforme|amzn-searchbot|amzn-user|andibot|anomura|awario|azureai-searchbot|bedrockbot|bigsur\.ai|brightbot|buddybot|bytespider|ccbot|channel3bot|chatglm-spider|chatgpt|cloudflare-autorag|cohere-|cotoyogi|crawlspace|datenbank crawler|devin|echobot|echoboxbot|facebookbot|factset_spyderbot|friendlycrawler|gemini-deep-research|google-extended|google-notebooklm|henkbot|iaskbot|iaskspider|iboubot|icc-crawler|imagesiftbot|imagespider|img2dataset|isscyberriskcrawler|kangaroo bot|klaviyoaibot|kunatocrawler|laion-huggingface-processor|laiondownloader|linerbot|linguee bot|linkupbot|manus-user|meta-externalagent|meta-externalfetcher|meta-webindexer|mycentralaiscraperbot|netestate imprint crawler|notebooklm|novaact|oai-searchbot|omgili|omgilibot|openai|operator|pangubot|panscient|perplexity-user|perplexitybot|poggio-citations|poseidon research crawler|qualifiedbot|quillbot|sbintuitionsbot|scrapy|shapbot|sidetrade indexer bot|spider|tavilybot|terracotta|thinkbot|tiktokspider|timpibot|twinagent|velenpublicwebcrawler|wardbot|webzio-extended|wpbot|wrtnbot|youbot|zanistabot/.test(normalizedUserAgent);
}

function isScrapperBot(normalizedUserAgent) {
    return /crios|fxios|yaapp_android|yasearchbrowser|ev-crawler|seamus the search engine|dataforseobot|\bptst\//.test(normalizedUserAgent);
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