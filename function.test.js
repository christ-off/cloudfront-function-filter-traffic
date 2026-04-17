import { describe, it, expect } from "vitest";
import { handler } from "./function.js";

function makeEvent({ uri = "/", userAgent = "Mozilla/5.0" } = {}) {
  const headers = {};
  if (userAgent !== null) {
    headers["user-agent"] = { value: userAgent };
  }
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

  it("allows /robots.txt even with a blocked user-agent (always-allow wins)", () => {
    const event = makeEvent({ uri: "/robots.txt", userAgent: "CCBot/2.0" });
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
// Traffic-advice path
// =====================================================
describe("/.well-known/traffic-advice", () => {
  it("returns 200", () => {
    const result = handler(makeEvent({ uri: "/.well-known/traffic-advice" }));
    expect(result.statusCode).toBe(200);
  });

  it("returns application/trafficadvice+json content-type", () => {
    const result = handler(makeEvent({ uri: "/.well-known/traffic-advice" }));
    expect(result.headers["content-type"].value).toBe("application/trafficadvice+json");
  });

  it("response body is valid JSON containing prefetch-proxy entry", () => {
    const result = handler(makeEvent({ uri: "/.well-known/traffic-advice" }));
    const parsed = JSON.parse(result.body);
    expect(parsed.some((e) => e.user_agent === "prefetch-proxy")).toBe(true);
  });

  it("sets a long cache-control header", () => {
    const result = handler(makeEvent({ uri: "/.well-known/traffic-advice" }));
    expect(result.headers["cache-control"].value).toContain("max-age=");
  });
});

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
// AI / bot user-agent blocking → 404
// =====================================================
describe("AI bot blocking by user-agent", () => {
  // One representative bot from each regex line in the function
  const blockedAgents = [
    ["CCBot/2.0", "ccbot"],
    ["ByteSpider", "bytespider"],
    ["FacebookBot/1.0", "facebookbot"],
    ["Google-Extended", "google-extended"],
    ["PerplexityBot/1.0", "perplexitybot"],
    ["Scrapy/2.6", "scrapy"],
    ["meta-externalagent/1.0", "meta-externalagent"],
    ["OAI-SearchBot/1.0", "oai-searchbot"],
    ["SummalyBot/5.2.5", "SummalyBot"],
  ];

  it.each(blockedAgents)("blocks '%s' (%s)", (userAgent) => {
    const result = handler(makeEvent({ userAgent }));
    expect(result.statusCode).toBe(404);
  });

  it("bot matching is case-insensitive (UA header not lowercased by sender)", () => {
    const result = handler(makeEvent({ userAgent: "CCBOT/2.0" }));
    expect(result.statusCode).toBe(404);
  });



  it("allows a normal browser user-agent", () => {
    const event = makeEvent({
      uri: "/about",
      userAgent:
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
    });
    expect(handler(event)).toEqual(event.request);
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
  ];

  it.each(blockedAgents)("blocks '%s' (%s)", (userAgent) => {
    const result = handler(makeEvent({ userAgent }));
    expect(result.statusCode).toBe(404);
  });

  it("scrapper bot matching is case-insensitive", () => {
    const result = handler(makeEvent({ userAgent: "YAAPP_ANDROID/10.61" }));
    expect(result.statusCode).toBe(404);
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
// Fake Chrome user agent blocking
// =====================================================
describe("fake Chrome UA blocking", () => {
  it("blocks a truncated Chrome UA missing AppleWebKit and Safari", () => {
    const result = handler(makeEvent({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
    }));
    expect(result.statusCode).toBe(404);
  });

  it("blocks Chrome/120.0.0.0 UA (stale version <= 140)", () => {
    const result = handler(makeEvent({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }));
    expect(result.statusCode).toBe(404);
  });

  it("allows a real Chrome UA with a non-fake version", () => {
    const event = makeEvent({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.6367.82 Safari/537.36"
    });
    expect(handler(event)).toEqual(event.request);
  });

  it("does not block a non-Chrome UA without AppleWebKit", () => {
    const event = makeEvent({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0"
    });
    expect(handler(event)).toEqual(event.request);
  });
});

// =====================================================
// Stale browser UA blocking (old Chrome versions)
// =====================================================
describe("stale Chrome UA blocking", () => {
  it("blocks Chrome/109 (below minimum version 110)", () => {
    const result = handler(makeEvent({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36"
    }));
    expect(result.statusCode).toBe(404);
  });

  it("blocks Chrome/85 (very old version)", () => {
    const result = handler(makeEvent({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36"
    }));
    expect(result.statusCode).toBe(404);
  });

  it("blocks Chrome/110 (below minimum allowed version 141)", () => {
    const result = handler(makeEvent({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
    }));
    expect(result.statusCode).toBe(404);
  });

  it("allows Chrome/141 (minimum allowed version)", () => {
    const event = makeEvent({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.6167.85 Safari/537.36"
    });
    expect(handler(event)).toEqual(event.request);
  });

  it("allows Chrome/150 (recent version)", () => {
    const event = makeEvent({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.6367.82 Safari/537.36"
    });
    expect(handler(event)).toEqual(event.request);
  });
});

// =====================================================
// Fake old IE user-agent blocking → 404
// =====================================================
describe("fake old IE UA blocking", () => {
  it("blocks IE 5 (MSIE 5.5)", () => {
    const result = handler(makeEvent({
      userAgent: "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)"
    }));
    expect(result.statusCode).toBe(404);
  });

  it("blocks IE 6 (MSIE 6.0)", () => {
    const result = handler(makeEvent({
      userAgent: "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
    }));
    expect(result.statusCode).toBe(404);
  });

  it("blocks IE 9 (MSIE 9.0 + Trident/5.0)", () => {
    const result = handler(makeEvent({
      userAgent: "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"
    }));
    expect(result.statusCode).toBe(404);
  });

  it("blocks IE 10 via Trident/6.0 (MSIE 10 is outside [5-9] range)", () => {
    const result = handler(makeEvent({
      userAgent: "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)"
    }));
    expect(result.statusCode).toBe(404);
  });

  it("blocks IE 11 via Trident/7.0", () => {
    const result = handler(makeEvent({
      userAgent: "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko"
    }));
    expect(result.statusCode).toBe(404);
  });

  it("matching is case-insensitive due to UA normalisation", () => {
    const result = handler(makeEvent({
      userAgent: "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)"
    }));
    expect(result.statusCode).toBe(404);
  });

  it("does not block a modern Firefox UA", () => {
    const event = makeEvent({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0"
    });
    expect(handler(event)).toEqual(event.request);
  });
});

// =====================================================
// Headless browser and CLI tool blocking → 404
// =====================================================
describe("headless browser and CLI tool blocking", () => {
  const blockedAgents = [
    ["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/112.0.0.0 Safari/537.36", "HeadlessChrome"],
    ["Mozilla/5.0 (unknown; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) PhantomJS/1.9.8 Safari/534.34", "PhantomJS"],
    ["SlimerJS/0.9", "SlimerJS"],
    ["Mozilla/5.0 (HtmlUnit)", "HtmlUnit"],
    ["python-requests/2.28.2", "python-requests"],
    ["python-httpx/0.24.0", "python-httpx"],
    ["Python-urllib/3.11", "python-urllib"],
    ["Go-http-client/2.0", "go-http-client"],
    ["Java/17.0.3", "java/"],
    ["libwww-perl/6.67", "libwww-perl"],
    ["curl/7.88.1", "curl"],
    ["Wget/1.21.4", "wget"],
  ];

  it.each(blockedAgents)("blocks '%s' (%s)", (userAgent) => {
    const result = handler(makeEvent({ userAgent }));
    expect(result.statusCode).toBe(404);
  });

  it("headless browser matching is case-insensitive", () => {
    const result = handler(makeEvent({ userAgent: "HEADLESSCHROME/112.0.0.0" }));
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
// Presto-based fake user-agent blocking → 404
// =====================================================
describe("Presto fake UA blocking", () => {
  it("blocks an Opera UA with Presto engine token", () => {
    const result = handler(makeEvent({
      userAgent: "Opera/9.80 (Windows NT 6.1) Presto/2.12.388 Version/12.17"
    }));
    expect(result.statusCode).toBe(404);
  });
});

// =====================================================
// Fake iOS UA: modern iOS version but old AppleWebKit build
// =====================================================
describe("fake iOS UA blocking", () => {
  it("blocks iOS 15 UA with old AppleWebKit (e.g. 534)", () => {
    const result = handler(makeEvent({
      userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Mobile/15A372"
    }));
    expect(result.statusCode).toBe(404);
  });

  it("allows iOS 15 UA with current AppleWebKit (e.g. 605)", () => {
    const event = makeEvent({
      userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15A372 Safari/604.1"
    });
    expect(handler(event)).toEqual(event.request);
  });

  it("allows iOS 14 UA with old AppleWebKit (condition requires iOS 15+)", () => {
    const event = makeEvent({
      userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Mobile/14A372"
    });
    expect(handler(event)).toEqual(event.request);
  });
});

// =====================================================
// Stale Chrome — exact boundary and Lighthouse exception
// =====================================================
describe("stale Chrome boundary and Lighthouse exception", () => {
  it("blocks Chrome/140 (exactly at the blocked threshold)", () => {
    const result = handler(makeEvent({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
    }));
    expect(result.statusCode).toBe(404);
  });

  it("allows a Google Lighthouse UA even with an old Chrome version", () => {
    const event = makeEvent({
      userAgent: "Mozilla/5.0 (Linux; Android 7.0; Moto G (4)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.101 Mobile Safari/537.36 Chrome-Lighthouse"
    });
    expect(handler(event)).toEqual(event.request);
  });

  it("allows Obsidian UA even with a stale Chrome version", () => {
    const event = makeEvent({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) obsidian/1.6.5 Chrome/124.0.6367.243 Electron/30.1.2 Safari/537.36"
    });
    expect(handler(event)).toEqual(event.request);
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
// Pass-through for normal traffic
// =====================================================
describe("pass-through", () => {
  it("returns the request object unchanged for a normal path", () => {
    const event = makeEvent({ uri: "/about", userAgent: "Mozilla/5.0" });
    expect(handler(event)).toEqual(event.request);
  });

  it("returns the request object unchanged for the root path", () => {
    const event = makeEvent({ uri: "/" });
    expect(handler(event)).toEqual(event.request);
  });
});
