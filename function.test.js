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
    ["Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1", "Chrome for iOS (CriOS)"],
    ["Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/120.0 Mobile/15E148 Safari/604.1", "Firefox for iOS (FxiOS)"],
    ["Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko", "Internet Explorer (Trident)"],
    ["Opera/9.80 (Windows NT 6.1; WOW64) Presto/2.12.388 Version/12.18", "Opera legacy (Presto)"],
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
