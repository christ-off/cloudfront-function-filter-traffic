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
    // /php-info has no dot and no trailing slash → trailing-slash redirect (not a 404 security block)
    const result = handler(makeEvent({ uri: "/php-info" }));
    expect(result.statusCode).toBe(200);
    expect(result.body).toContain("L'adresse n'est pas correcte");
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
    ["Feedfetcher-Google; (+http://www.google.com/feedfetcher.html)", "Feedfetcher-Google"],
    ["Mozilla/5.0 (compatible; StackyEnrich/1.0)", "StackyEnrich"],
    ["fyndbot (robots; https://fynd.bot)", "FyndBot (robots)"],
    ["fyndbot (recrawler; https://fynd.bot)", "FyndBot (recrawler)"],
    ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/600.2.5 (KHTML, like Gecko) Version/8.0.2 Safari/600.2.5 (Lanai)", "Lanai bot"],
    [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
      "Peg Tech Inc. / RakSmart",
    ],
    [
      "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0",
      "Firefox 147 (Ubuntu) suspected scraper",
    ],
    ["Mozilla/5.0 (compatible; WellKnownBot/0.1;  https://well-known.dev/about/#bot)", "WellKnownBot"],
    ["Mozilla/5.0 (compatible; wpbot/1.4; https://forms.gle/ajBaxygz9jSR8p8G9)", "wpbot"],
    ["Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Googlebot"],
    ["python-httpx/0.28.1", "Python httpx"],
    ["python-requests/2.32.5", "Python requests"],
    ["Mozilla/4.0 (compatible; ms-office; MSOffice 16)", "MS Office SaaS"],
    ["CMSSurvey/1.0; https://addedlovely.com/crawler", "CMSSurvey"],
    ["Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ReyilBot/0.1", "ReyilBot"],
    ["Wellesley/1.0 bot", "Wellesley"],
    ["RankPulseBot/0.1 ( https://github.com/rankpulse/rankpulse)", "RankPulseBot"],
    ["LinkupBot/1.0 (LinkupBot for web indexing; https://linkup.so/bot; bot@linkup.so)", "LinkupBot"],
    ["Mozilla/5.0 (compatible; Google-CloudVertexBot; https://cloud.google.com/vertex-ai-bot)", "Google-CloudVertexBot"],
    ["CCBot/2.0 (https://commoncrawl.org/faq/)", "CCBot"],
    ["Aranea Web-Crawled Corpora Project ( http://aranea.juls.savba.sk/guest (Frenchch 2026 Summer Crawl))", "Aranea"],
    ["Mozilla/5.0 (compatible; intelx.io_bot https://intelx.io)", "intelx.io_bot"],
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

  // Parametrized tests for decoy responses (robots.txt, feed.xml, rss.xml, sitemap.xml)
  const decoyTests = [
    ["/robots.txt", "text/plain", "User-agent", "robots.txt"],
    ["/feed.xml", "application/atom+xml", "<feed", "feed.xml"],
    ["/rss.xml", "application/rss+xml", "<rss", "rss.xml"],
    ["/sitemap.xml", "application/xml", "<urlset", "sitemap.xml"],
  ];

  describe.each(decoyTests)("decoy response for blocked bot on %s", (uri, contentType, bodyMarker) => {
    it("returns 200 OK with cache headers", () => {
      const result = handler(makeEvent({ uri, userAgent: "Scrapy/2.16.0" }));
      expect(result.statusCode).toBe(200);
      expect(result.headers["content-type"].value).toBe(contentType);
      expect(result.body).toContain(bodyMarker);
      expect(result.headers["etag"]).toBeDefined();
      expect(result.headers["last-modified"]).toBeDefined();
      expect(result.headers["cache-control"].value).toContain("max-age=31536000");
    });

    it("returns 304 on matching ETag", () => {
      const first = handler(makeEvent({ uri, userAgent: "Scrapy/2.16.0" }));
      const etag = first.headers["etag"].value;
      const result = handler(makeEvent({
        uri,
        userAgent: "Scrapy/2.16.0",
        extraHeaders: { "if-none-match": { value: etag } }
      }));
      expect(result.statusCode).toBe(304);
      expect(result.headers["etag"].value).toBe(etag);
    });

    it("returns 304 on If-Modified-Since", () => {
      const result = handler(makeEvent({
        uri,
        userAgent: "Scrapy/2.16.0",
        extraHeaders: { "if-modified-since": { value: "Mon, 01 Jan 2024 00:00:00 GMT" } }
      }));
      expect(result.statusCode).toBe(304);
    });
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
});

// =====================================================
// Chrome ≤ 124, all stale → 404
// =====================================================
describe("stale Chrome ≤ 124 blocking by user-agent", () => {
  const staleChromeVersions = [
    [89, "below 120"],
    [94, "below 120"],
    [99, "below 120"],
    [110, "below 120"],
    [120, "below 124"],
    [124, "boundary, <= 124"],
  ];

  it.each(staleChromeVersions)("blocks Chrome %i (%s)", (version) => {
    const ua = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`;
    expect(handler(makeEvent({ userAgent: ua })).statusCode).toBe(404);
  });

  it("does not block Chrome 125 (minimum version)", () => {
    const event = makeEvent({ userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.5790.170 Safari/537.36" });
    expect(handler(event)).toEqual(event.request);
  });

  it("does not block Chrome 130 (modern)", () => {
    const event = makeEvent({ userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.117 Safari/537.36" });
    expect(handler(event)).toEqual(event.request);
  });

  it("does not block bingbot with stale Chrome version", () => {
    const event = makeEvent({ userAgent: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36" });
    expect(handler(event)).toEqual(event.request);
  });
});

// =====================================================
// iOS 1–9, all end-of-life → 404
// =====================================================
describe("end-of-life iOS 1–9 blocking by user-agent", () => {
  it("blocks iOS 9 (real stale bot UA)", () => {
    expect(handler(makeEvent({ userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 9_3_5 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13G36 Safari/601.1" })).statusCode).toBe(404);
  });

  it("does not block iOS 10 (above range)", () => {
    const event = makeEvent({ userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_4 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.0 Mobile/14G61 Safari/602.1" });
    expect(handler(event)).toEqual(event.request);
  });
});

// =====================================================
// Trailing slash redirect
// =====================================================
describe("trailing slash redirect", () => {
  // --- needsTrailingSlash: triggers redirect ---
  it("returns 200 redirect page for /about (no trailing slash)", () => {
    const result = handler(makeEvent({ uri: "/about" }));
    expect(result.statusCode).toBe(200);
  });

  it("returns 200 redirect page for /contact/team (nested, no trailing slash)", () => {
    const result = handler(makeEvent({ uri: "/contact/team" }));
    expect(result.statusCode).toBe(200);
  });

  it("returns 200 redirect page for /php-info (no dot, not a security scan)", () => {
    const result = handler(makeEvent({ uri: "/php-info" }));
    expect(result.statusCode).toBe(200);
  });

  // --- needsTrailingSlash: pass-through ---
  it("passes through / (root already has trailing slash)", () => {
    const event = makeEvent({ uri: "/" });
    expect(handler(event)).toEqual(event.request);
  });

  it("passes through /about/ (already has trailing slash)", () => {
    const event = makeEvent({ uri: "/about/" });
    expect(handler(event)).toEqual(event.request);
  });

  it("passes through /style.css (has dot — static resource)", () => {
    const event = makeEvent({ uri: "/style.css" });
    expect(handler(event)).toEqual(event.request);
  });

  it("passes through /image.avif (has dot — static resource)", () => {
    const event = makeEvent({ uri: "/image.avif" });
    expect(handler(event)).toEqual(event.request);
  });

  it("passes through /feed.xml (has dot)", () => {
    const event = makeEvent({ uri: "/feed.xml" });
    expect(handler(event)).toEqual(event.request);
  });

  // --- 200 response content ---
  it("body contains 'L'adresse n'est pas correcte'", () => {
    const result = handler(makeEvent({ uri: "/about" }));
    expect(result.body).toContain("L'adresse n'est pas correcte");
  });

  it("body contains meta http-equiv refresh pointing to /about/", () => {
    const result = handler(makeEvent({ uri: "/about" }));
    expect(result.body).toContain('<meta http-equiv="refresh"');
    expect(result.body).toContain("0;url=/about/");
  });

  it("body contains link to correct relative URL /about/", () => {
    const result = handler(makeEvent({ uri: "/about" }));
    expect(result.body).toContain('href="/about/"');
  });

  it("response has content-type text/html; charset=UTF-8", () => {
    const result = handler(makeEvent({ uri: "/about" }));
    expect(result.headers["content-type"].value).toBe("text/html; charset=UTF-8");
  });

  // --- whitelisted bots → 301 ---
  it("returns 301 for Qwant bot on /about", () => {
    const result = handler(makeEvent({
      uri: "/about",
      userAgent: "Mozilla/5.0 (compatible; Qwantbot/1.0_4600311;  https://help.qwant.com/bot/)",
    }));
    expect(result.statusCode).toBe(301);
    expect(result.headers["location"].value).toBe("/about/");
  });

  it("returns 301 for Qwant bot on /page (second UA variant)", () => {
    const result = handler(makeEvent({
      uri: "/page",
      userAgent: "Mozilla/5.0 (compatible; Qwantbot/1.0_4600311;  https://help.qwant.com/bot/)",
    }));
    expect(result.statusCode).toBe(301);
    expect(result.headers["location"].value).toBe("/page/");
  });

  it("Qwant on /about/ (already correct) passes through, no redirect", () => {
    const event = makeEvent({
      uri: "/about/",
      userAgent: "Mozilla/5.0 (compatible; Qwantbot/1.0_4600311;  https://help.qwant.com/bot/)",
    });
    expect(handler(event)).toEqual(event.request);
  });

  // --- blocked bot hits bot-block before trailing-slash gate ---
  it("blocked bot on /about still gets 404 (bot block runs first)", () => {
    const result = handler(makeEvent({ uri: "/about", userAgent: "Scrapy/2.16.0" }));
    expect(result.statusCode).toBe(404);
  });

  // --- case preservation in redirect URLs ---
  it("preserves original case in redirect URL for /About", () => {
    const result = handler(makeEvent({ uri: "/About" }));
    expect(result.statusCode).toBe(200);
    expect(result.body).toContain("href=\"/About/\"");
    expect(result.body).toContain('0;url=/About/');
  });

  it("preserves original case and special chars in redirect URL", () => {
    const result = handler(makeEvent({ uri: "/Le_grand_roman_des-maths_Mickaël_Launay" }));
    expect(result.statusCode).toBe(200);
    expect(result.body).toContain("/Le_grand_roman_des-maths_Mickaël_Launay/");
  });

  it("301 redirect preserves original case for whitelisted bot", () => {
    const result = handler(makeEvent({
      uri: "/Le_grand_roman_des-maths_Mickaël_Launay",
      userAgent: "Mozilla/5.0 (compatible; Qwantbot/1.0_4600311;  https://help.qwant.com/bot/)",
    }));
    expect(result.statusCode).toBe(301);
    expect(result.headers["location"].value).toBe("/Le_grand_roman_des-maths_Mickaël_Launay/");
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
});

