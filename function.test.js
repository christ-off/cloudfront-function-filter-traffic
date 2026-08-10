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

// =====================================================
// Always-allow paths
// =====================================================
describe("always-allow paths", () => {
  it("allows /robots.txt", () => {
    const event = makeEvent({ uri: "/robots.txt" });
    expect(handler(event)).toEqual(event.request);
  });

  it("allows /ads.txt", () => {
    const event = makeEvent({ uri: "/ads.txt" });
    expect(handler(event)).toEqual(event.request);
  });

  it("allows /llms.txt", () => {
    const event = makeEvent({ uri: "/llms.txt" });
    expect(handler(event)).toEqual(event.request);
  });


  it("normalises URI whitespace before checking (trim)", () => {
    const event = makeEvent({ uri: "  /robots.txt  " });
    expect(handler(event)).toEqual(event.request);
  });

  it("normalises URI case before checking (lowercase)", () => {
    const event = makeEvent({ uri: "/ROBOTS.TXT" });
    expect(handler(event)).toEqual(event.request);
  });
});

// =====================================================
// /.well-known/traffic-advice — Chrome Private Prefetch Proxy
// =====================================================
// =====================================================
// Security scan blocking — PHP files → 404
// =====================================================
describe("PHP file blocking", () => {
  it("blocks a .php file at the root", () => {
    const result = handler(makeEvent({ uri: "/wp-login.php" }));
    expect(result.statusCode).toBe(404);
  });

  it("blocks a .php file in a sub-directory", () => {
    const result = handler(makeEvent({ uri: "/path/to/script.php" }));
    expect(result.statusCode).toBe(404);
  });

  it("PHP block is case-insensitive due to URI normalisation", () => {
    const result = handler(makeEvent({ uri: "/Shell.PHP" }));
    expect(result.statusCode).toBe(404);
  });

  it("does not block a path that merely contains 'php' as a substring", () => {
    const event = makeEvent({ uri: "/php-info" });
    expect(handler(event)).toEqual(event.request);
  });

  it("blocks a .php5 file", () => {
    expect(handler(makeEvent({ uri: "/shell.php5" })).statusCode).toBe(404);
  });

  it("blocks a .php7 file", () => {
    expect(handler(makeEvent({ uri: "/shell.php7" })).statusCode).toBe(404);
  });

  it("blocks a .phtml file", () => {
    expect(handler(makeEvent({ uri: "/page.phtml" })).statusCode).toBe(404);
  });

  it("blocks a .phar file", () => {
    expect(handler(makeEvent({ uri: "/app.phar" })).statusCode).toBe(404);
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
  ];

  it.each(cases)("blocks %s (%s)", (uri) => {
    expect(handler(makeEvent({ uri })).statusCode).toBe(404);
  });

  it("blocks a bad folder path with no trailing content (bare folder)", () => {
    expect(handler(makeEvent({ uri: "/cgi-bin" })).statusCode).toBe(404);
  });

  it("does not block a path that shares a prefix but is a different folder", () => {
    // /images2 or /blog-post should NOT be caught — regex anchors with (\/|$)
    const event = makeEvent({ uri: "/images2/logo.png" });
    expect(handler(event)).toEqual(event.request);
  });

  it("blocking is case-insensitive due to URI normalisation", () => {
    const result = handler(makeEvent({ uri: "/WP-INCLUDES/load.php" }));
    expect(result.statusCode).toBe(404);
  });

  it("blocks /ip (server IP disclosure probe)", () => {
    expect(handler(makeEvent({ uri: "/ip" })).statusCode).toBe(404);
  });
});


// =====================================================
// Scrapper bot user-agent blocking → 404
// =====================================================
describe("scrapper bot blocking by user-agent", () => {
  const blockedAgents = [
    [
      "Mozilla/5.0 (Linux; Android 7.1.1; MI MAX 2 Build/NMF26F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Mobile Safari/537.36 YaApp_Android/10.61 YaSearchBrowser/10.61",
      "YaApp_Android full UA",
    ],
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
    ["Mozilla/4.0 (compatible; ms-office; MSOffice 16)", "MS Office SaaS"],
    ["CMSSurvey/1.0; https://addedlovely.com/crawler", "CMSSurvey"],
    ["Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ReyilBot/0.1", "ReyilBot"],
    ["Wellesley/1.0 bot", "Wellesley"],
    ["RankPulseBot/0.1 ( https://github.com/rankpulse/rankpulse)", "RankPulseBot"],
    ["LinkupBot/1.0 (LinkupBot for web indexing; https://linkup.so/bot; bot@linkup.so)", "LinkupBot"],
    ["Googlebot-Image/1.0", "Googlebot-Image"],
    ["CCBot/2.0 (https://commoncrawl.org/faq/)", "CCBot"],
    ["Mozilla/5.0 (compatible; pathscan/1.0)", "pathscan"],
    ["Aranea Web-Crawled Corpora Project ( http://aranea.juls.savba.sk/guest (Frenchch 2026 Summer Crawl))", "Aranea"],
    ["Mozilla/5.0 (compatible; intelx.io_bot https://intelx.io)", "intelx.io_bot"],
    ["Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.4a) Gecko/20030401", "PPC Mach-O"],
    ["Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0", "outdated Firefox 72"],
    ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0", "outdated Firefox 99"],
    ["TestSearchSpider/0.1", "TestSearchSpider"],
    ["TestSearchSpider/2.0", "TestSearchSpider (any version)"],
    ["NavCrawl/0.4 ( https://example.com/bot)", "NavCrawl"],
    ["Mozilla/5.0 CMS-Detector/1.0", "CMS-Detector"],
    ["atlas-enrich/1.0", "atlas-enrich"],
    ["Mozilla/5.0 (compatible; SiteScan/1.0; free-tier enrichment; respects robots)", "SiteScan"],
    [
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
      "known scraper spoofing Chrome/148 desktop UA",
    ],
    [
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
      "known scraper spoofing Chrome/144 desktop UA",
    ],
    [
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "known scraper spoofing Chrome/120 desktop UA",
    ],
    ["LivelapBot/0.2 (http://site.livelap.com/crawler)", "LivelapBot"],
    ["DatabankMetasearchProduction/0.2", "DatabankMetasearchProduction"],
    ["DatabankMetasearchExperiment/0.2", "DatabankMetasearchExperiment"],
    [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
      "known scraper spoofing Chrome/142 Windows UA",
    ],
    [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
      "known scraper spoofing Chrome/116 Windows UA",
    ],
    [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36",
      "known scraper spoofing Chrome/104 Windows UA",
    ],
    [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
      "known scraper spoofing Chrome/107 Windows UA",
    ],
    ["SearchEngineBot/0.1", "SearchEngineBot"],
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

  // Feed/sitemap paths get no special treatment: blocked bots are simply
  // denied there like anywhere else (the decoy responses were removed).
  const feedPaths = ["/feed.xml", "/rss.xml", "/sitemap.xml"];

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

  it("blocks even for robots.txt when user-agent is absent", () => {
    const result = handler(makeEvent({ uri: "/robots.txt", userAgent: null }));
    expect(result.statusCode).toBe(404);
  });
});

// =====================================================
// Percent-encoded URI bypass prevention
// =====================================================
describe("percent-encoded URI handling", () => {
  it("blocks a .php file with an encoded dot (%2E)", () => {
    const result = handler(makeEvent({ uri: "/wp-login%2Ephp" }));
    expect(result.statusCode).toBe(404);
  });

  it("blocks a bad folder with an encoded character (%77p-includes)", () => {
    const result = handler(makeEvent({ uri: "/%77p-includes/load.php" }));
    expect(result.statusCode).toBe(404);
  });

  it("blocks cgi-bin with an encoded hyphen (%2D)", () => {
    const result = handler(makeEvent({ uri: "/cgi%2Dbin/test" }));
    expect(result.statusCode).toBe(404);
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
  it("blocks /.env", () => {
    expect(handler(makeEvent({ uri: "/.env" })).statusCode).toBe(404);
  });

  it("blocks /.env.local", () => {
    expect(handler(makeEvent({ uri: "/.env.local" })).statusCode).toBe(404);
  });

  it("blocks /config/.env inside a subdirectory", () => {
    expect(handler(makeEvent({ uri: "/config/.env" })).statusCode).toBe(404);
  });

  it("blocks /.git/config", () => {
    expect(handler(makeEvent({ uri: "/.git/config" })).statusCode).toBe(404);
  });

  it("blocks /.git (bare)", () => {
    expect(handler(makeEvent({ uri: "/.git" })).statusCode).toBe(404);
  });
});

// =====================================================
// Security scan blocking — .sql and .bak extensions → 404
// =====================================================
describe(".sql and .bak file blocking", () => {
  it("blocks a .sql file", () => {
    expect(handler(makeEvent({ uri: "/dump.sql" })).statusCode).toBe(404);
  });

  it("blocks a .bak file", () => {
    expect(handler(makeEvent({ uri: "/config.bak" })).statusCode).toBe(404);
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

  it.each(cases)("blocks %s (%s)", (uri) => {
    expect(handler(makeEvent({ uri })).statusCode).toBe(404);
  });
});

// =====================================================
// Always-allow paths with blocked user-agents
// =====================================================
describe("always-allow paths bypass UA checks", () => {
  it("allows /ads.txt even with a blocked user-agent", () => {
    const event = makeEvent({ uri: "/ads.txt", userAgent: "CCBot/2.0" });
    expect(handler(event)).toEqual(event.request);
  });

  it("allows /llms.txt even with a blocked user-agent", () => {
    const event = makeEvent({ uri: "/llms.txt", userAgent: "CCBot/2.0" });
    expect(handler(event)).toEqual(event.request);
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

  it("returns the request object unchanged for a path with no trailing slash", () => {
    const event = makeEvent({ uri: "/about" });
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

  it("passes through Tor Browser (Firefox ESR 128)", () => {
    const event = makeEvent({
      uri: "/",
      userAgent: "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
    });
    expect(handler(event)).toEqual(event.request);
  });

  it("allows Google-CloudVertexBot through", () => {
    const event = makeEvent({
      userAgent: "Mozilla/5.0 (compatible; Google-CloudVertexBot; https://cloud.google.com/vertex-ai-bot)",
    });
    expect(handler(event)).toEqual(event.request);
  });

  it("allows Gemini-Deep-Research through", () => {
    const event = makeEvent({
      userAgent: "Mozilla/5.0 (compatible; Gemini-Deep-Research; https://google.com/bot.html)",
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

