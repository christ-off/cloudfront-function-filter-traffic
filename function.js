function handler(event) {

  const request = event.request;
  let uri = '';
  try {
    uri = request.uri ? decodeURIComponent(request.uri).trim().toLowerCase() : '';
  } catch (e) {
    return createNotFoundResponse();
  }

  // ====================================================
  // Block requests with no user agent
  // ====================================================
  const headers = request.headers;
  const userAgentHeader = headers['user-agent'];
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

  // file extension probes
  if (/\.(php|sql|bak)$/.test(uri) || uri.includes('/.env') || uri.startsWith('/.git')) {
    return createNotFoundResponse();
  }

  // bad folders
  if (/^\/(images?|img|wp-includes|static|wp|wordpress|old|new|blog|backup|cgi-bin|admin|administrator|wp-admin|phpmyadmin|pma)(\/|$)/.test(uri)) {
    return createNotFoundResponse();
  }

  // ====================================================
  // DENIES IA By 403
  // ====================================================
  const normalizedUserAgent = userAgentHeader.value.toLowerCase();
  if (
      /addsearchbot|ai2bot|aihitbot|amazon-kendra|amazonbot|amazonbuyforme|amzn-searchbot|amzn-user|andibot|anomura|anthropic-ai|apifybot|apifywebsitecontentcrawler|applebot|atlassian-bot|awario|azureai-searchbot|bedrockbot|bigsur\.ai/.test(normalizedUserAgent) ||
      /bravebot|brightbot|buddybot|bytespider|ccbot|channel3bot|chatglm-spider|chatgpt|cloudflare-autorag|cloudvertexbot|cohere-|cotoyogi|crawl4ai|crawlspace|datenbank crawler|deepseekbot|devin|diffbot/.test(normalizedUserAgent) ||
      /duckassistbot|echobot|echoboxbot|exabot|facebookbot|factset_spyderbot|firecrawlagent|friendlycrawler|gemini-deep-research|google-cloudvertexbot|google-extended|google-firebase|google-notebooklm/.test(normalizedUserAgent) ||
      /googleagent-mariner|googleother|gptbot|iaskbot|iaskspider|iboubot|icc-crawler|imagesiftbot|imagespider|img2dataset|isscyberriskcrawler|kangaroo bot|klaviyoaibot|kunatocrawler|laion-huggingface-processor|laiondownloader/.test(normalizedUserAgent) ||
      /linerbot|linguee bot|linkupbot|manus-user|meta-externalagent|meta-externalfetcher|meta-webindexer|mistralai-user|mycentralaiscraperbot|netestate imprint crawler|notebooklm|novaact|oai-searchbot|omgili|omgilibot/.test(normalizedUserAgent) ||
      /openai|operator|pangubot|panscient|perplexity-user|perplexitybot|petalbot|phindbot|poggio-citations|poseidon research crawler|qualifiedbot|quillbot|sbintuitionsbot|scrapy|semrushbot-ocob|semrushbot-swa/.test(normalizedUserAgent) ||
      /shapbot|sidetrade indexer bot|spider|summalybot|tavilybot|terracotta|thinkbot|tiktokspider|timpibot|twinagent|velenpublicwebcrawler|wardbot|webzio-extended|wpbot|wrtnbot|yandexadditional|youbot|zanistabot/.test(normalizedUserAgent)
  ) {
    return createNotFoundResponse();
  }

  // Pass through
  return request;
}

function createNotFoundResponse() {
  return {
    statusCode: 404,
    statusDescription: 'Not Found',
    headers: { "content-type": { value: "text/plain" } },
    body: 'Not Found'
  };
}

function createTrafficAdviceResponse() {
  return {
    statusCode: 200,
    headers: {
      'content-type': {value: 'application/trafficadvice+json'},
      'permissions-policy': {value: 'browsing-topics=(), prefetch=()'},
      'cache-control' : {value: 'max-age=63072000'}
    },
    body: '[{ "user_agent": "prefetch-proxy", "google_prefetch_proxy_eap": { "fraction": 1.0 } },{ "user_agent": "*", "accept": { "purpose": { "prefetch": true, "prerender": true },"sec-purpose": { "prefetch": true, "prerender": true }} }]'
  };
}

export { handler };
