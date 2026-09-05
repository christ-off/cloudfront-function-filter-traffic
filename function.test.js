import { describe, it, expect } from "vitest";
import { handler } from "./function.js";

function makeEvent({ uri = "/", userAgent = "Mozilla/5.0", extraHeaders = {} } = {}) {
  const headers = {};
  if (userAgent !== null) {
    headers["user-agent"] = { value: userAgent };
  }
  Object.assign(headers, extraHeaders);
  return { request: { uri, headers } };
}

function expectNotFound(result) {
  expect(result.statusCode).toBe(404);
  expect(result.body).toBe("Not Found");
}

function expectNotBlocked(result) {
  expect(result.statusCode).not.toBe(404);
}

// =====================================================
// /.well-known/traffic-advice — Chrome Private Prefetch Proxy
// =====================================================
// =====================================================
// Security scan blocking — PHP files → 404
// =====================================================
describe("PHP file blocking", () => {
  it("returns 404 for a .php file at the root", () => {
    expectNotFound(handler(makeEvent({ uri: "/wp-login.php" })));
  });

  it("returns 404 for a .php file in a sub-directory", () => {
    expectNotFound(handler(makeEvent({ uri: "/path/to/script.php" })));
  });

  it("PHP block is case-insensitive due to URI normalisation", () => {
    expectNotFound(handler(makeEvent({ uri: "/Shell.PHP" })));
  });

    it("does not block a path that merely contains 'php' as a substring", () => {
      expectNotBlocked(handler(makeEvent({ uri: "/php-info" })));
    });

  it("returns 404 for a .php5 file", () => {
    expectNotFound(handler(makeEvent({ uri: "/shell.php5" })));
  });

  it("returns 404 for a .php7 file", () => {
    expectNotFound(handler(makeEvent({ uri: "/shell.php7" })));
  });

  it("returns 404 for a .phtml file", () => {
    expectNotFound(handler(makeEvent({ uri: "/page.phtml" })));
  });

  it("returns 404 for a multi-digit .phpNN suffix", () => {
    expectNotFound(handler(makeEvent({ uri: "/zup.php73" })));
    expectNotFound(handler(makeEvent({ uri: "/about.php525" })));
  });
});

// =====================================================
// Bad actors (security-scan URIs, truncated/malformed Chrome UAs, stale
// Firefox UAs) get a 404 like everything else.
// =====================================================
describe("404 response for bad actors", () => {
  it("returns 404 for a security scan URI", () => {
    const result = handler(makeEvent({ uri: "/wp-login.php" }));
    expectNotFound(result);
    expect(result.headers["content-type"].value).toBe("text/plain");
  });

  it("does not affect non-security-scan URIs", () => {
    const event = makeEvent({ uri: "/" });
    expect(handler(event)).toEqual(event.request);
  });

  const badActorAgents = [
    ["Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0", "outdated Firefox 72"],
    ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0", "outdated Firefox 99"],
    ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0", "outdated Firefox 138 (below MIN_FIREFOX_MAJOR)"],
    ["Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko Firefox/11.0 (via ggpht.com GoogleImageProxy)", "Google Image Proxy's stale Firefox/11.0 UA"],
    [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "truncated Windows UA missing KHTML/Chrome/Safari tail",
    ],
    [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
      "malformed Chrome claim missing AppleWebKit/KHTML entirely",
    ],
    [
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36",
      "Chrome/83 (below MIN_CHROME_MAJOR, no organic signal in logs.db)",
    ],
    [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.0.0 Safari/537.36",
      "Chrome/80 (below MIN_CHROME_MAJOR, no organic signal in logs.db)",
    ],
    [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
      "Chrome/148 (just below MIN_CHROME_MAJOR — rotating-UA cloud fleet in logs.db, no real audience)",
    ],
    [
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Chrome/120 (below MIN_CHROME_MAJOR — the largest bot fleet in logs.db)",
    ],
    [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36",
      "Chrome/98 (pre-UA-reduction full version, far below the floor)",
    ],
    [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36",
      "full build/patch version — post-UA-reduction Chrome never reports this",
    ],
  ];

  it.each(badActorAgents)("returns 404 for '%s' (%s)", (userAgent) => {
    expectNotFound(handler(makeEvent({ userAgent })));
  });

  // A Chrome major-version range is NOT a reliable spoof signal by structure
  // alone: real Chrome freezes its UA to major.0.0.0, and logs.db showed
  // exactly this template as the two most common real UAs in production
  // traffic (see CLAUDE.md: never block Chrome solely on the .0.0.0
  // minor/patch version). MIN_CHROME_MAJOR is a separate, evidence-backed
  // floor on the version number (see README.md#min-chrome-major).
  const realChromeAgents = [
    ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36", "Chrome/152 macOS"],
    ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36", "Chrome/150 Windows"],
    ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36", "Chrome/149, exactly at the floor"],
    ["Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36", "Chrome/151 Linux aarch64"],
    ["Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/30.0 Chrome/143.0.0.0 Mobile Safari/537.36", "Samsung Internet 30 (lagging Chromium, exempted from the floor)"],
    ["Mozilla/5.0 (Linux; Android 13; SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/125.0.0.0 Mobile Safari/537.36", "Samsung Internet 27 (lagging Chromium, exempted from the floor)"],
  ];

  it.each(realChromeAgents)("passes through '%s' (%s)", (userAgent) => {
    const event = makeEvent({ uri: "/", userAgent });
    expect(handler(event)).toEqual(event.request);
  });
});

// =====================================================
// Security scan blocking — bad folder prefixes → 404
// =====================================================
describe("bad folder blocking", () => {
  const cases = [
    ["/images/logo.png", "images"],
    ["/image/logo.png", "image (singular)"],
    ["/img/logo.png", "img"],
    ["/wp-includes/js/jquery.js", "wp-includes"],
    ["/static/app.js", "static"],
    ["/wp/xmlrpc.php", "wp"],
    ["/wordpress/index.php", "wordpress"],
    ["/old/site/index.html", "old"],
    ["/new/site/index.html", "new"],
    ["/blog/post/1", "blog"],
    ["/backup/db.sql", "backup"],
    ["/cgi-bin/test.cgi", "cgi-bin"],
    ["/vendor/autoload.php", "vendor"],
    ["/uploads/shell.php", "uploads"],
    ["/plugins/malicious.php", "plugins"],
    ["/login", "login (bare)"],
    ["/login/", "login (trailing slash)"],
    ["/webmail/", "webmail"],
    ["/roundcube/", "roundcube"],
    ["/mail/", "mail"],
    ["/rc/", "rc"],
  ];

  it.each(cases)("returns 404 for %s (%s)", (uri) => {
    expectNotFound(handler(makeEvent({ uri })));
  });

  it("returns 404 for a bad folder path with no trailing content (bare folder)", () => {
    expectNotFound(handler(makeEvent({ uri: "/cgi-bin" })));
  });

  it("does not block a path that shares a prefix but is a different folder", () => {
    // /images2 or /blog-post should NOT be caught — regex anchors with (\/|$)
    const event = makeEvent({ uri: "/images2/logo.png" });
    expect(handler(event)).toEqual(event.request);
  });

  it("does not block a path that merely shares a prefix with 'login' or 'uploads'", () => {
    expectNotBlocked(handler(makeEvent({ uri: "/loginpage" })));
    expectNotBlocked(handler(makeEvent({ uri: "/uploads2/x" })));
  });

  it("does not block a path that merely shares a prefix with 'mail' or 'rc'", () => {
    expectNotBlocked(handler(makeEvent({ uri: "/mailing-list" })));
    expectNotBlocked(handler(makeEvent({ uri: "/rcfiles/x" })));
  });

  it("does not block or redirect an ACME HTTP-01 domain-validation challenge under /.well-known/", () => {
    const event = makeEvent({ uri: "/.well-known/acme-challenge/some-token" });
    expect(handler(event)).toEqual(event.request);
  });

  it("blocking is case-insensitive due to URI normalisation", () => {
    expectNotFound(handler(makeEvent({ uri: "/WP-INCLUDES/load.php" })));
  });

  it("returns 404 for /ip (server IP disclosure probe)", () => {
    expectNotFound(handler(makeEvent({ uri: "/ip" })));
  });
});


// =====================================================
// Scrapper bot user-agent blocking → 404
// =====================================================
describe("scrapper bot blocking by user-agent", () => {
  const blockedAgents = [
    ["Mozilla/5.0 (compatible; Amzn-SearchBot/1.0; https://developer.amazon.com/support/amazonbot)", "Amzn-SearchBot"],
    [
      "Mozilla/5.0 (Linux; Android 7.1.1; MI MAX 2 Build/NMF26F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Mobile Safari/537.36 YaApp_Android/10.61 YaSearchBrowser/10.61",
      "YaApp_Android full UA",
    ],
    ["Mozilla/5.0 (compatible; LoadedBot/1.0; https://loaded.ai/bot)", "LoadedBot (ignores robots.txt)"],
    ["YaApp_Android/10.61", "YaApp_Android token"],
    ["YaSearchBrowser/10.61", "YaSearchBrowser token"],
    ["Seamus The Search Engine/1.0", "Seamus the search engine"],
    ["DataForSEOBot/1.0", "DataForSEO bot"],
    ["ev-crawler/1.0", "ev-crawler"],
    ["Mozilla/5.0 ptst/1.0", "ptst scraper token"],
    ["Mozilla/5.0 (compatible; xAI-SearchBot/1.0; https://x.ai)", "xAI-SearchBot token"],
    ["Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1", "Chrome for iOS (CriOS)"],
    ["Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/120.0 Mobile/15E148 Safari/604.1", "Firefox for iOS (FxiOS)"],
    ["Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko", "Internet Explorer (Trident)"],
    ["Opera/9.80 (Windows NT 6.1; WOW64) Presto/2.12.388 Version/12.18", "Opera legacy (Presto)"],
    ["WebScraperBot/0.1 (domain-check)", "WebScraperBot domain-check"],
    ["pimeyes-downloader-api/0.1", "PiMeyes downloader API"],
    ["SleepBot/1.0 (http://sleepbot.com/)", "SleepBot scraper"],
    ["Mozilla/5.0 (compatible; WebTrackrCrawler/1.0; https://affsignal.com/bot)", "WebTrackrCrawler (affsignal)"],
    ["got (https://github.com/sindresorhus/got)", "got HTTP client"],
    ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko; compatible; BuiltWith/1.4; rb.gy/xprgqj) Chrome/124.0.0.0 Safari/537.36", "BuiltWith scraper"],
    ["Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ShapBot/0.1.0", "ShapBot scraper"],
    ["Scrapy/2.16.0 ( https://scrapy.org)", "Scrapy scraper"],
    ["Mozilla/5.0 (Linux; Android 7.0;) AppleWebKit/537.36 (HTML, like Gecko) Mobile Safari/537.36 (compatible; PetalBot; https://webmaster.petalsearch.com/site/petalbot)", "PetalBot full UA"],
    ["Mozilla/5.0 (compatible;PetalBot; https://webmaster.petalsearch.com/site/petalbot)", "PetalBot compact UA"],
    ["Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; https://zhanzhang.toutiao.com/)", "Bytespider"],
    ["Timpibot/1.0 ( http://timpi.io/crawler)", "Timpibot/1.0 scraper"],
    ["Mozilla/5.0 (compatible; Timpibot/0.8; http://www.timpi.io)", "Timpibot/0.8 scraper"],
    ["greedyhand/0.1", "GreedyHand scraper"],
    ["greedyhand/1.0", "GreedyHand scraper (any version)"],
    ["Mozilla/5.0 (compatible; StackyEnrich/1.0)", "StackyEnrich"],
    ["fyndbot (robots; https://fynd.bot)", "FyndBot (robots)"],
    ["fyndbot (recrawler; https://fynd.bot)", "FyndBot (recrawler)"],
    ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/600.2.5 (KHTML, like Gecko) Version/8.0.2 Safari/600.2.5 (Lanai)", "Lanai bot"],
    ["Mozilla/5.0 (compatible; WellKnownBot/0.1;  https://well-known.dev/about/#bot)", "WellKnownBot"],
    ["Mozilla/5.0 (compatible; wpbot/1.4; https://forms.gle/ajBaxygz9jSR8p8G9)", "wpbot"],
    ["python-httpx/0.28.1", "Python httpx"],
    ["python-requests/2.32.5", "Python requests"],
    ["Python/3.14 aiohttp/3.14.1", "Python aiohttp"],
    ["Mozilla/4.0 (compatible; ms-office; MSOffice 16)", "MS Office SaaS"],
    ["CMSSurvey/1.0; https://addedlovely.com/crawler", "CMSSurvey"],
    ["Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ReyilBot/0.1", "ReyilBot"],
    ["Wellesley/1.0 bot", "Wellesley"],
    ["Welley/1.0 bot", "Welley/1.0 bot"],
    ["Welley/1.0", "Welley/1.0 (no bot suffix)"],
    ["RankPulseBot/0.1 ( https://github.com/rankpulse/rankpulse)", "RankPulseBot"],
    ["LinkupBot/1.0 (LinkupBot for web indexing; https://linkup.so/bot; bot@linkup.so)", "LinkupBot"],
    ["Googlebot-Image/1.0", "Googlebot-Image"],
    ["CCBot/2.0 (https://commoncrawl.org/faq/)", "CCBot"],
    ["Mozilla/5.0 (compatible; pathscan/1.0)", "pathscan"],
    ["Aranea Web-Crawled Corpora Project ( http://aranea.juls.savba.sk/guest (Frenchch 2026 Summer Crawl))", "Aranea"],
    ["Mozilla/5.0 (compatible; intelx.io_bot https://intelx.io)", "intelx.io_bot"],
    ["Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.4a) Gecko/20030401", "PPC Mach-O"],
    ["TestSearchSpider/0.1", "TestSearchSpider"],
    ["TestSearchSpider/2.0", "TestSearchSpider (any version)"],
    ["NavCrawl/0.4 ( https://example.com/bot)", "NavCrawl"],
    ["Mozilla/5.0 CMS-Detector/1.0", "CMS-Detector"],
    ["atlas-enrich/1.0", "atlas-enrich"],
    ["Mozilla/5.0 (compatible; SiteScan/1.0; free-tier enrichment; respects robots)", "SiteScan"],
    ["LivelapBot/0.2 (http://site.livelap.com/crawler)", "LivelapBot"],
    ["DatabankMetasearchProduction/0.2", "DatabankMetasearchProduction"],
    ["DatabankMetasearchExperiment/0.2", "DatabankMetasearchExperiment"],
    ["SearchEngineBot/0.1", "SearchEngineBot"],
    ["URL/Emacs Emacs/30.1 (X11; x86_64-pc-linux-gnu)", "Emacs URL/Emacs scraper"],
    [
      "ImageBot/1.0 (compatible; research crawler; https://github.com/rom1504/img2dataset; opt-out: abuse.notification.dcomp12b@gmail.com;",
      "ImageBot/img2dataset scraper",
    ],
    ["Mozilla/5.0 (compatible; PerplexityBot/1.0; https://perplexity.ai/perplexitybot)", "PerplexityBot"],
    ["Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.3; https://openai.com/gptbot)", "GPTBot"],
    ["Mozilla/5.0 (compatible; Google-CloudVertexBot; https://cloud.google.com/vertex-ai-bot)", "Google-CloudVertexBot"],
    ["Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GoogleOther)", "GoogleOther"],
    ["koofie.net/1.0 ( https://koofie.net/bot)", "koofie.net bot"],
    ["FeedFetcher-Google; (+http://www.google.com/feedfetcher.html)", "FeedFetcher-Google"],
    ["domain-intel/0.1", "domain-intel bot"],
    ["Screaming Frog SEO Spider/19.2", "Screaming Frog SEO Spider"],
    ["Mozilla/5.0 (compatible; OpenClaw-CN-Reach/1.0)", "OpenClaw-CN-Reach"],
    ["SummalyBot/1.0", "SummalyBot"],
    ["Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com/bots)", "Discordbot"],
    ["Sharkey (like Discordbot)", "Sharkey"],
    ["Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)", "Baiduspider"],
    ["Mozilla/5.0 (compatible; Reflectionbot/1.0; https://reflection.ai/bot)", "Reflectionbot"],
    ["Lightpanda/1.0 internal-testing-crawler", "Lightpanda"],
    ["Mozilla/5.0 (compatible; ForestEngine/1.0; +https://forestengine.net/)", "ForestEngine"],
    ["Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; SEOJuice-SearchBot/1.0; https://seojuice.io/bot", "SEOJuice-SearchBot"],
    ["Mozilla/5.0 (compatible; coccocbot-web/1.0; http://help.coccoc.com/searchengine)", "coccocbot-web"],
  ];

  it.each(blockedAgents)("blocks '%s' (%s)", (userAgent) => {
    const result = handler(makeEvent({ userAgent }));
    expect(result.statusCode).toBe(404);
  });

  it("scrapper bot matching is case-insensitive (YaApp)", () => {
    const result = handler(makeEvent({ userAgent: "YAAPP_ANDROID/10.61" }));
    expect(result.statusCode).toBe(404);
  });

  it("scrapper bot matching is case-insensitive (BuiltWith)", () => {
    const result = handler(makeEvent({ userAgent: "BuiltWith/1.4" }));
    expect(result.statusCode).toBe(404);
  });

  // /rss.xml gets no special treatment: blocked bots are simply denied there
  // like anywhere else (the decoy responses were removed). /sitemap.xml and
  // /feed.xml are the exceptions — see their dedicated describe blocks below.
  const feedPaths = ["/rss.xml"];

  it.each(feedPaths)("blocks a blocked bot on %s with a plain 404", (uri) => {
    const result = handler(makeEvent({ uri, userAgent: "Scrapy/2.16.0" }));
    expect(result.statusCode).toBe(404);
    expect(result.body).toBe("Not Found");
  });

  it.each(feedPaths)("ignores conditional request headers on %s", (uri) => {
    const result = handler(makeEvent({
      uri,
      userAgent: "Scrapy/2.16.0",
      extraHeaders: {
        "if-none-match": { value: '"empty-feed-v1"' },
        "if-modified-since": { value: "Mon, 01 Jan 2024 00:00:00 GMT" },
      }
    }));
    expect(result.statusCode).toBe(404);
  });

  it.each(feedPaths)("still lets a normal browser through on %s", (uri) => {
    const event = makeEvent({ uri, userAgent: "Mozilla/5.0 (Macintosh) Safari/604.1" });
    expect(handler(event)).toEqual(event.request);
  });
});

// =====================================================
// /robots.txt for a blocked bot → real disallow-all, not a 404
// =====================================================
describe("robots.txt disallow-all for blocked bots", () => {
  it("answers a blocked bot's /robots.txt with a 200 disallow-all", () => {
    const result = handler(makeEvent({ uri: "/robots.txt", userAgent: "Scrapy/2.16.0" }));
    expect(result.statusCode).toBe(200);
    expect(result.headers["content-type"].value).toBe("text/plain");
    expect(result.headers["cache-control"].value).toBe("public, max-age=86400");
    expect(result.body).toBe("User-agent: *\nDisallow: /\n");
  });

  it("also answers a bad-actor UA's (not just a blocked bot's) /robots.txt with a 200 disallow-all", () => {
    const result = handler(makeEvent({
      uri: "/robots.txt",
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.0.0 Safari/537.36",
    }));
    expect(result.statusCode).toBe(200);
    expect(result.body).toBe("User-agent: *\nDisallow: /\n");
  });

  it("is case-insensitive on the URI", () => {
    const result = handler(makeEvent({ uri: "/ROBOTS.TXT", userAgent: "Scrapy/2.16.0" }));
    expect(result.statusCode).toBe(200);
  });

  it("does not affect other bad-actor rules (e.g. security-scan URIs)", () => {
    const result = handler(makeEvent({ uri: "/wp-login.php", userAgent: "Scrapy/2.16.0" }));
    expectNotFound(result);
  });

  it("still lets a normal browser's /robots.txt through untouched", () => {
    const event = makeEvent({ uri: "/robots.txt", userAgent: "Mozilla/5.0 (Macintosh) Safari/604.1" });
    expect(handler(event)).toEqual(event.request);
  });
});

// =====================================================
// Empty sitemap.xml for blocked bots
// =====================================================
describe("sitemap.xml empty urlset for blocked bots", () => {
  it("answers a blocked bot's /sitemap.xml with a 200 empty urlset", () => {
    const result = handler(makeEvent({ uri: "/sitemap.xml", userAgent: "Scrapy/2.16.0" }));
    expect(result.statusCode).toBe(200);
    expect(result.headers["content-type"].value).toBe("application/xml");
    expect(result.headers["cache-control"].value).toBe("public, max-age=86400");
    expect(result.body).toBe(
      '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>\n'
    );
  });

  it("also answers a bad-actor UA's (not just a blocked bot's) /sitemap.xml with a 200 empty urlset", () => {
    const result = handler(makeEvent({
      uri: "/sitemap.xml",
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.0.0 Safari/537.36",
    }));
    expect(result.statusCode).toBe(200);
    expect(result.body).toBe(
      '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>\n'
    );
  });

  it("is case-insensitive on the URI", () => {
    const result = handler(makeEvent({ uri: "/SITEMAP.XML", userAgent: "Scrapy/2.16.0" }));
    expect(result.statusCode).toBe(200);
  });

  it("does not affect other bad-actor rules (e.g. security-scan URIs)", () => {
    const result = handler(makeEvent({ uri: "/wp-login.php", userAgent: "Scrapy/2.16.0" }));
    expectNotFound(result);
  });

  it("still lets a normal browser's /sitemap.xml through untouched", () => {
    const event = makeEvent({ uri: "/sitemap.xml", userAgent: "Mozilla/5.0 (Macintosh) Safari/604.1" });
    expect(handler(event)).toEqual(event.request);
  });
});

// =====================================================
// Empty feed.xml for blocked bots
// =====================================================
describe("feed.xml empty atom feed for blocked bots", () => {
  it("answers a blocked bot's /feed.xml with a 200 empty atom feed", () => {
    const result = handler(makeEvent({ uri: "/feed.xml", userAgent: "Scrapy/2.16.0" }));
    expect(result.statusCode).toBe(200);
    expect(result.headers["content-type"].value).toBe("application/atom+xml");
    expect(result.headers["cache-control"].value).toBe("public, max-age=86400");
    expect(result.body).toBe(
      '<?xml version="1.0" encoding="UTF-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom"></feed>\n'
    );
  });

  it("also answers a bad-actor UA's (not just a blocked bot's) /feed.xml with a 200 empty atom feed", () => {
    const result = handler(makeEvent({
      uri: "/feed.xml",
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.0.0 Safari/537.36",
    }));
    expect(result.statusCode).toBe(200);
    expect(result.body).toBe(
      '<?xml version="1.0" encoding="UTF-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom"></feed>\n'
    );
  });

  it("is case-insensitive on the URI", () => {
    const result = handler(makeEvent({ uri: "/FEED.XML", userAgent: "Scrapy/2.16.0" }));
    expect(result.statusCode).toBe(200);
  });

  it("does not affect other bad-actor rules (e.g. security-scan URIs)", () => {
    const result = handler(makeEvent({ uri: "/wp-login.php", userAgent: "Scrapy/2.16.0" }));
    expectNotFound(result);
  });

  it("still lets a normal browser's /feed.xml through untouched", () => {
    const event = makeEvent({ uri: "/feed.xml", userAgent: "Mozilla/5.0 (Macintosh) Safari/604.1" });
    expect(handler(event)).toEqual(event.request);
  });
});

// =====================================================
// Null or empty user-agent → 404
// =====================================================
describe("null or empty user-agent blocking", () => {
  it("blocks a request with no user-agent header", () => {
    const result = handler(makeEvent({ uri: "/about", userAgent: null }));
    expect(result.statusCode).toBe(404);
  });

  it("blocks a request with an empty user-agent value", () => {
    const result = handler(makeEvent({ uri: "/about", userAgent: "" }));
    expect(result.statusCode).toBe(404);
  });

  it("blocks a request with a whitespace-only user-agent value", () => {
    const result = handler(makeEvent({ uri: "/about", userAgent: "   " }));
    expect(result.statusCode).toBe(404);
  });

});

// =====================================================
// Percent-encoded URI bypass prevention
// =====================================================
describe("percent-encoded URI handling", () => {
  it("returns 404 for a .php file with an encoded dot (%2E)", () => {
    expectNotFound(handler(makeEvent({ uri: "/wp-login%2Ephp" })));
  });

  it("returns 404 for a bad folder with an encoded character (%77p-includes)", () => {
    expectNotFound(handler(makeEvent({ uri: "/%77p-includes/load.php" })));
  });

  it("returns 404 for cgi-bin with an encoded hyphen (%2D)", () => {
    expectNotFound(handler(makeEvent({ uri: "/cgi%2Dbin/test" })));
  });

  it("returns 404 for a malformed percent-encoded URI", () => {
    const result = handler(makeEvent({ uri: "/%zz/path" }));
    expect(result.statusCode).toBe(404);
  });
});


// =====================================================
// Security scan blocking — .env and .git URIs → 404
// =====================================================
describe(".env and .git URI blocking", () => {
  it("returns 404 for /.env", () => {
    expectNotFound(handler(makeEvent({ uri: "/.env" })));
  });

  it("returns 404 for /.env.local", () => {
    expectNotFound(handler(makeEvent({ uri: "/.env.local" })));
  });

  it("returns 404 for /config/.env inside a subdirectory", () => {
    expectNotFound(handler(makeEvent({ uri: "/config/.env" })));
  });

  it("returns 404 for /.git/config", () => {
    expectNotFound(handler(makeEvent({ uri: "/.git/config" })));
  });

  it("returns 404 for /.git (bare)", () => {
    expectNotFound(handler(makeEvent({ uri: "/.git" })));
  });
});

// =====================================================
// Security scan blocking — .sql and .bak extensions → 404
// =====================================================
describe(".sql and .bak file blocking", () => {
  it("returns 404 for a .sql file", () => {
    expectNotFound(handler(makeEvent({ uri: "/dump.sql" })));
  });

  it("returns 404 for a .bak file", () => {
    expectNotFound(handler(makeEvent({ uri: "/config.bak" })));
  });
});

// =====================================================
// Security scan blocking — WordPress content/API probing → 404
// =====================================================
describe("wp-content and wp-json blocking", () => {
  it("returns 404 for /wp-content/ paths", () => {
    expectNotFound(handler(makeEvent({ uri: "/wp-content/uploads/" })));
    expectNotFound(handler(makeEvent({ uri: "/wp-content/plugins/WordPressCore/" })));
  });

  it("returns 404 for /wp-json/ paths", () => {
    expectNotFound(handler(makeEvent({ uri: "/wp-json/" })));
  });
});

// =====================================================
// Security scan blocking — credential/config file scanning → 404
// =====================================================
describe("credential and config file scanning", () => {
  const extensionCases = [
    "/web.config",
    "/docker-compose.yaml",
    "/.gitlab-ci.yml",
    "/.aider.conf.yml",
    "/rclone.conf",
    "/server.key",
    "/key.pem",
    "/trace.axd",
    "/.boto",
    "/.s3cfg",
    "/.npmrc",
    "/.htpasswd",
    "/terraform.tfstate",
  ];

  it.each(extensionCases)("returns 404 for %s", (uri) => {
    expectNotFound(handler(makeEvent({ uri })));
  });

  it("returns 404 for /.docker/config.json", () => {
    expectNotFound(handler(makeEvent({ uri: "/.docker/config.json" })));
  });

  const secretJsonCases = [
    "/secrets.json",
    "/config.json",
    "/credentials.json",
    "/service-account.json",
    "/service_account.json",
    "/firebase-adminsdk.json",
    "/serviceAccountKey.json",
    "/settings.json",
    "/env.json",
    "/auth.json",
    "/app-config.json",
    "/appsettings.json",
    "/openapi.json",
    "/swagger.json",
    "/amplifyconfiguration.json",
  ];

  it.each(secretJsonCases)("returns 404 for root-level %s", (uri) => {
    expectNotFound(handler(makeEvent({ uri })));
  });

  it("does not block legitimate nested .json data files", () => {
    const event = makeEvent({ uri: "/about/data/blogs.json" });
    expect(handler(event)).toEqual(event.request);
  });

  it("does not block /manifest.json", () => {
    const event = makeEvent({ uri: "/manifest.json" });
    expect(handler(event)).toEqual(event.request);
  });
});

// =====================================================
// Security scan blocking — admin folder variants → 404
// =====================================================
describe("admin folder blocking", () => {
  const cases = [
    ["/admin/login", "admin"],
    ["/administrator/index.php", "administrator"],
    ["/wp-admin/admin-ajax.php", "wp-admin"],
    ["/phpmyadmin/index.php", "phpmyadmin"],
    ["/pma/index.php", "pma"],
  ];

  it.each(cases)("returns 404 for %s (%s)", (uri) => {
    expectNotFound(handler(makeEvent({ uri })));
  });
});

// =====================================================
// ads.txt / llms.txt with blocked user-agents
// =====================================================
describe("ads.txt and llms.txt follow normal UA blocking", () => {
  it("blocks /ads.txt for a blocked user-agent", () => {
    const result = handler(makeEvent({ uri: "/ads.txt", userAgent: "CCBot/2.0" }));
    expect(result.statusCode).toBe(404);
  });

  it("blocks /llms.txt for a blocked user-agent", () => {
    const result = handler(makeEvent({ uri: "/llms.txt", userAgent: "CCBot/2.0" }));
    expect(result.statusCode).toBe(404);
  });
});

// =====================================================
// Trailing-slash redirect (301) for directory-style URIs
// =====================================================
describe("trailing-slash redirect", () => {
  it("redirects a directory-style path with no trailing slash", () => {
    const result = handler(makeEvent({ uri: "/about" }));
    expect(result.statusCode).toBe(301);
    expect(result.statusDescription).toBe("Moved Permanently");
    expect(result.headers.location.value).toBe("/about/");
  });

  it("redirects a nested directory-style path with no trailing slash", () => {
    const result = handler(makeEvent({ uri: "/articles/my-post" }));
    expect(result.headers.location.value).toBe("/articles/my-post/");
  });

  it("does not redirect a path that already has a trailing slash", () => {
    const event = makeEvent({ uri: "/about/" });
    expect(handler(event)).toEqual(event.request);
  });

  it("does not redirect the root path", () => {
    const event = makeEvent({ uri: "/" });
    expect(handler(event)).toEqual(event.request);
  });

  it.each([
    "/logo.png",
    "/photos/vacation.jpg",
    "/styles/main.css",
    "/scripts/app.js",
    "/fonts/icon.woff2",
    "/data/report.pdf",
  ])("does not redirect an asset path %s", (uri) => {
    const event = makeEvent({ uri });
    expect(handler(event)).toEqual(event.request);
  });

  it("does not redirect a path with a dot in an earlier segment but not the final one", () => {
    const result = handler(makeEvent({ uri: "/v1.2/about" }));
    expect(result.statusCode).toBe(301);
    expect(result.headers.location.value).toBe("/v1.2/about/");
  });

  it("blocks a bad actor before ever considering the trailing-slash redirect", () => {
    const result = handler(makeEvent({ uri: "/wp-admin", userAgent: "Mozilla/5.0" }));
    expect(result.statusCode).toBe(404);
  });

  it("blocks a bad user-agent before ever considering the trailing-slash redirect", () => {
    const result = handler(makeEvent({ uri: "/about", userAgent: "Scrapy/2.0" }));
    expect(result.statusCode).toBe(404);
  });
});

// =====================================================
// Pass-through for normal traffic
// =====================================================
describe("pass-through", () => {
  it("returns the request object unchanged for a normal path", () => {
    const event = makeEvent({ uri: "/about/", userAgent: "Mozilla/5.0" });
    expect(handler(event)).toEqual(event.request);
  });

  it("returns the request object unchanged for the root path", () => {
    const event = makeEvent({ uri: "/" });
    expect(handler(event)).toEqual(event.request);
  });

  it("returns the request object unchanged for a file path with no trailing slash", () => {
    const event = makeEvent({ uri: "/about.html" });
    expect(handler(event)).toEqual(event.request);
  });

  it("allows real Googlebot through", () => {
    const event = makeEvent({
      userAgent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    });
    expect(handler(event)).toEqual(event.request);
  });

  it("passes through iPhone Safari iOS 18.6 / Safari 26 on Mobile", () => {
    const event = makeEvent({
      uri: "/",
      userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
    });
    expect(handler(event)).toEqual(event.request);
  });

  it("passes through current Firefox on Linux", () => {
    const event = makeEvent({
      uri: "/",
      userAgent: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0",
    });
    expect(handler(event)).toEqual(event.request);
  });

  it("passes through Tor Browser (Firefox ESR 140)", () => {
    const event = makeEvent({
      uri: "/",
      userAgent: "Mozilla/5.0 (Windows NT 10.0; rv:140.0) Gecko/20100101 Firefox/140.0",
    });
    expect(handler(event)).toEqual(event.request);
  });

  it("passes through real Firefox 140 with its frozen rv:109.0 (Mozilla's IE11-workaround UA freeze)", () => {
    const event = makeEvent({
      uri: "/",
      userAgent: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/140.0",
    });
    expect(handler(event)).toEqual(event.request);
  });

  it("passes through Firefox ESR 115 (Mozilla's extended-support train for legacy OSes)", () => {
    const event = makeEvent({
      uri: "/",
      userAgent: "Mozilla/5.0 (Windows NT 6.1; rv:115.0) Gecko/20100101 Firefox/115.0",
    });
    expect(handler(event)).toEqual(event.request);
  });

  it("allows Gemini-Deep-Research through", () => {
    const event = makeEvent({
      userAgent: "Mozilla/5.0 (compatible; Gemini-Deep-Research; https://google.com/bot.html)",
    });
    expect(handler(event)).toEqual(event.request);
  });

  it("passes through Chrome/150 on macOS", () => {
    const event = makeEvent({
      uri: "/",
      userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
    });
    expect(handler(event)).toEqual(event.request);
  });

  it("passes through Feeder (feeder.co) with its embedded UA token", () => {
    const event = makeEvent({
      uri: "/",
      userAgent: "Mozilla/5.0 (feeder.co; Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
    });
    expect(handler(event)).toEqual(event.request);
  });

  it("allows real Bingbot through", () => {
    const event = makeEvent({
      uri: "/",
      userAgent: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36",
    });
    expect(handler(event)).toEqual(event.request);
  });

  it("passes through Chrome/150 on Windows", () => {
    const event = makeEvent({
      uri: "/",
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
    });
    expect(handler(event)).toEqual(event.request);
  });

  it("passes through a real current Chrome on Linux x86_64 (aarch64 desktop Chrome would be unusual but is no longer specially blocked)", () => {
    const event = makeEvent({
      uri: "/",
      userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
    });
    expect(handler(event)).toEqual(event.request);
  });

  it("allows Google-InspectionTool through", () => {
    const event = makeEvent({
      userAgent: "Mozilla/5.0 (compatible; Google-InspectionTool/1.0)",
    });
    expect(handler(event)).toEqual(event.request);
  });
});

