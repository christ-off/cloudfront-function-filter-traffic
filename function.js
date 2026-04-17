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
    if (isScrapperBot(ua) || isHeadlessBrowser(ua)) {
        return createNotFoundResponse();
    }

    // ====================================================
    // DENIES Fake user agents
    // ====================================================
    if (isFakeUserAgent(ua) || isStaleBrowserUA(ua) || isFakeOldIE(ua)) {
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
    return /addsearchbot|aihitbot|amazon-kendra|amazonbuyforme|amzn-searchbot|amzn-user|andibot|anomura|awario|azureai-searchbot|bedrockbot|bigsur\.ai|brightbot|buddybot|bytespider|ccbot|channel3bot|chatglm-spider|chatgpt|cloudflare-autorag|cohere-|cotoyogi|crawlspace|datenbank crawler|devin|echobot|echoboxbot|facebookbot|factset_spyderbot|friendlycrawler|gemini-deep-research|google-extended|google-notebooklm|henkbot|iaskbot|iaskspider|iboubot|icc-crawler|imagesiftbot|imagespider|img2dataset|isscyberriskcrawler|kangaroo bot|klaviyoaibot|kunatocrawler|laion-huggingface-processor|laiondownloader|linerbot|linguee bot|linkupbot|manus-user|meta-externalagent|meta-externalfetcher|meta-webindexer|mycentralaiscraperbot|netestate imprint crawler|notebooklm|novaact|oai-searchbot|omgili|omgilibot|openai|operator|pangubot|panscient|perplexity-user|perplexitybot|poggio-citations|poseidon research crawler|qualifiedbot|quillbot|sbintuitionsbot|scrapy|shapbot|sidetrade indexer bot|spider|summalybot|tavilybot|terracotta|thinkbot|tiktokspider|timpibot|twinagent|velenpublicwebcrawler|wardbot|webzio-extended|wpbot|wrtnbot|youbot|zanistabot/.test(normalizedUserAgent);
}

function isScrapperBot(normalizedUserAgent) {
    return /yaapp_android|yasearchbrowser|ev-crawler|seamus the search engine|dataforseobot/.test(normalizedUserAgent);
}

function isHeadlessBrowser(normalizedUserAgent) {
    return (
        /headlesschrome|phantomjs|slimerjs|htmlunit/.test(normalizedUserAgent) ||
        /python-requests|python-httpx|python-urllib/.test(normalizedUserAgent) ||
        /go-http-client|java\/|libwww-perl/.test(normalizedUserAgent) ||
        /^curl\/|^wget\//.test(normalizedUserAgent)
    );
}

function isFakeUserAgent(normalizedUserAgent) {
    // Truncated Chrome UA — missing AppleWebKit/Safari tokens
    // Real Chrome always includes AppleWebKit/537.36 and Safari/537.36
    return (
        normalizedUserAgent.includes('presto/') ||
        (
            /mozilla.*windows nt.*chrome\/\d/.test(normalizedUserAgent) &&
            !normalizedUserAgent.includes('applewebkit') &&
            !normalizedUserAgent.includes('safari')
        ) ||
        (
            /\(i(?:phone|pad).*os 1[5-9]/.test(normalizedUserAgent) &&
            /applewebkit\/[1-5]\d{2}\./.test(normalizedUserAgent)
        )
    );
}

function isFakeOldIE(normalizedUserAgent) {
    // MSIE is dead - all IE user agents on a modern blog are bots/scanners
    return /msie\s[5-9]\.|trident\/[3-9]\.\d/.test(normalizedUserAgent);
}

function isStaleBrowserUA(ua) {
    // Allow known apps that embed old Chrome/Electron (Lighthouse, Obsidian)
    if (/chrome-lighthouse|obsidian\//.test(ua)) return false;

    // Block Chrome versions <= 140
    const match = ua.match(/chrome\/(\d+)\./);
    return match !== null && parseInt(match[1], 10) <= 140;
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