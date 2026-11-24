import { beforeEach, describe, it, expect } from "vitest";
import { handler } from "./function.js";
import { kvs } from "./test-support/cloudfront-stub.js";

const BROWSER = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36";

function makeEvent({ uri = "/", userAgent = BROWSER, asn, referer } = {}) {
  const headers = {};
  if (userAgent !== null) headers["user-agent"] = { value: userAgent };
  if (asn !== undefined) headers["cloudfront-viewer-asn"] = { value: asn };
  if (referer !== undefined) headers.referer = { value: referer };
  return { request: { uri, headers } };
}

async function expectBlocked(event) {
  const result = await handler(event);
  expect(result.statusCode).toBe(404);
  expect(result.body).toBe("Not Found");
}

async function expectPassed(event) {
  expect(await handler(event)).toBe(event.request);
}

let kvsLookups;
beforeEach(() => {
  kvsLookups = [];
  kvs.exists = async (key) => {
    kvsLookups.push(key);
    return key === "3215"; // the only ISP in the fake store
  };
});

// Steps 1-4: cheap checks, no KeyValueStore read
describe("cheap checks", () => {
  it.each([null, "", "   "])("blocks a missing or empty user agent (%j)", (userAgent) =>
    expectBlocked(makeEvent({ userAgent })));

  it("blocks an undecodable URI", () => expectBlocked(makeEvent({ uri: "/%E0%A4%A" })));

  it.each([
    "/wp-login.php", "/.env", "/a/../b", "/wp-content/x", "/id_rsa", "/backup/db.sql", "/backup.zip.php",
  ])("blocks the scanner URI %s", (uri) => expectBlocked(makeEvent({ uri })));

  it.each([
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
  ])("blocks the fake Chrome UA %s", (userAgent) => expectBlocked(makeEvent({ userAgent })));

  it.each([
    "python-requests/2.31", "curl/8.0", "Baiduspider/2.0", "Mozilla/5.0 (compatible; Konqueror/3; Linux)",
    "Emacs/29.1", "CoccocBot-Web/1.0", "TPhotoBot/1.0", "Mozilla/5.0 (compatible; SEOJuice-SearchBot/1.0)",
  ])("blocks the bot UA %s", (userAgent) => expectBlocked(makeEvent({ userAgent })));

  // rationale: README.md#blocked-bot-regex
  it.each([
    ["Scrapy/2.16.0", "16509"],
    ["FeedFetcher-Google; (+http://www.google.com/feedfetcher.html)", "15169"],
    ["Mozilla/5.0 (compatible; SemrushBot/7~bm)", "24940"],
  ])("blocks the hosted bot %s by its ASN, not by UA", async (userAgent, asn) => {
    await expectBlocked(makeEvent({ userAgent, asn }));
    expect(kvsLookups).toEqual([]);
  });

  it("serves the real feed, robots.txt and favicon.ico to a blocked bot on a blocklisted ASN", async () => {
    // rationale: README.md#robots-always-allowed, README.md#favicon-always-served, README.md#feed-always-served
    await expectPassed(makeEvent({ uri: "/feed.xml", asn: "16509", userAgent: "curl/8.5.0" }));
    await expectPassed(makeEvent({ uri: "/rss.xml", asn: "16509", userAgent: "curl/8.5.0" }));
    await expectPassed(makeEvent({ uri: "/robots.txt", asn: "16509", userAgent: "Scrapy/2.16.0" }));
    await expectPassed(makeEvent({ uri: "/favicon.ico", asn: "16509", userAgent: "Scrapy/2.16.0" }));
  });

  it("keeps answering a blocked bot with a plain 404 on every other path", async () => {
    await expectBlocked(makeEvent({ uri: "/sitemap.xml", userAgent: "curl/8.0" }));
    await expectBlocked(makeEvent({ uri: "/wp-login.php", userAgent: "curl/8.0" }));
  });

  it("answers a request with no UA header with a plain 404, even on the always-served paths", async () => {
    // A UA-less client is treated as a scraper, so this guard still runs first.
    // rationale: README.md#robots-always-allowed, README.md#favicon-always-served, README.md#feed-always-served
    await expectBlocked(makeEvent({ uri: "/feed.xml", userAgent: null }));
    await expectBlocked(makeEvent({ uri: "/robots.txt", userAgent: null }));
    await expectBlocked(makeEvent({ uri: "/favicon.ico", userAgent: null }));
  });

  it("blocks cheap-check failures without reading the KeyValueStore", async () => {
    await expectBlocked(makeEvent({ uri: "/wp-login.php", asn: "3215" }));
    expect(kvsLookups).toEqual([]);
  });
});

// Step 5: .json / .js allowlists apply to everyone, whitelisted ASN included
describe("asset rules", () => {
  it("allows the listed json and js files, blocks the others", async () => {
    await expectPassed(makeEvent({ uri: "/about/data/visitors.json" }));
    await expectPassed(makeEvent({ uri: "/pagefind/pagefind.js" }));
    await expectBlocked(makeEvent({ uri: "/human.json" }));
    await expectBlocked(makeEvent({ uri: "/other.json" }));
    await expectBlocked(makeEvent({ uri: "/other.js" }));
  });

  it("serves covers regardless of referer", async () => {
    await expectPassed(makeEvent({ uri: "/assets/posts/a.webp" }));
    await expectPassed(makeEvent({ uri: "/assets/posts_640/a.webp", referer: "https://evil.example/" }));
  });

  it("applies to a whitelisted ASN as well", () =>
    expectBlocked(makeEvent({ uri: "/other.json", asn: "714" })));
});

// Steps 6-9: ASN whitelist, hosted software, blocklist, fail open
describe("ASN rules", () => {
  it.each(["60653", "199064", "714"])("passes whitelisted AS%s without a KeyValueStore read", async (asn) => {
    await expectPassed(makeEvent({ asn }));
    expect(kvsLookups).toEqual([]);
  });

  it.each([
    "Mozilla/5.0 (compatible; ibou-search/2.0;  https://ibou.com/crawlers.html)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; http://www.bing.com/bingbot.htm)",
    "http.rb/5.1.1 (Mastodon/4.2.0; +https://mastodon.example/)",
    "Feedbin feed-id:1 - 1 subscribers",
    "rss-parser",
    "FreshRSS/1.30.0 (Linux; https://freshrss.org)",
    // Catodon ships two UA forms: "<name>/<version> ( <instance-url>)" and "<name> (like Discordbot)"
    "Catodon/26.10.0 ( https://catodon.rocks)",
    "Catodon (like Discordbot)",
    "Akkoma 3.20.1; https://soc.punktrash.club <ary@punktrash.club>",
    "Haathi/0.17.0 ( https://haathi.mxhdr.net/)",
    "LivelapBot/0.2 (http://site.livelap.com/crawler)",
    "Nextcloud Social 0.24.1",
    // Pleroma sends "Pleroma <version>; <instance-url> <admin-email>[; Bot]", with no slash after the name
    "Pleroma 2.6.3-0-gee6ba27ed-develop; https://social.metadata.moe <pleroma@metadata.moe>; Bot",
  ])("passes hosted software on a blocked ASN: %s", async (userAgent) => {
    await expectPassed(makeEvent({ asn: "8075", userAgent }));
    expect(kvsLookups).toEqual([]);
  });

  it("passes Bravebot from Hetzner AS24940 by UA token, without a KeyValueStore read", async () => {
    await expectPassed(makeEvent({
      asn: "24940",
      userAgent: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Bravebot/1.0;  https://search.brave.com/help/brave-search-crawler) Chrome/W.X.Y.Z Safari/537.36",
    }));
    expect(kvsLookups).toEqual([]);
  });

  it("keeps blocking scanners that spoof the Bravebot name", async () => {
    const spoof = "Mozilla/5.0 (compatible; Bravebot/1.0;  https://brave.com/search/)";
    await expectBlocked(makeEvent({ uri: "/.env", asn: "396982", userAgent: spoof }));
    await expectBlocked(makeEvent({ uri: "/@fs/app/.env", asn: "396982", userAgent: spoof }));
    await expectBlocked(makeEvent({ uri: "/proc/self/environ", asn: "396982", userAgent: spoof }));
  });

  it("passes Googlebot from blocklisted AS15169 by UA token, without a KeyValueStore read", async () => {
    // rationale: README.md#asn-allowed-hosted-software
    await expectPassed(makeEvent({
      asn: "15169",
      userAgent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    }));
    expect(kvsLookups).toEqual([]);
  });

  it("passes Google-InspectionTool from blocklisted AS15169 by UA token, without a KeyValueStore read", async () => {
    // rationale: README.md#asn-allowed-hosted-software
    await expectPassed(makeEvent({
      asn: "15169",
      userAgent: "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.8127.36 Mobile Safari/537.36 (compatible; Google-InspectionTool/1.0)",
    }));
    expect(kvsLookups).toEqual([]);
  });

  it.each([
    "Mozilla/5.0 (compatible; Google-Images/1.0)",
    "Mozilla/5.0 (compatible; Googlebot-News/2.1; +http://news.google.com/)",
    "Mozilla/5.0 (compatible; Google-Extended/1.0; +http://www.google.com/)",
  ])("keeps blocking Google's non-indexing agent %s from AS15169 by ASN", async (userAgent) => {
    await expectBlocked(makeEvent({ asn: "15169", userAgent }));
    expect(kvsLookups).toEqual([]);
  });

  it("keeps blocking a Googlebot UA spoof on scanner paths", async () => {
    const spoof = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
    await expectBlocked(makeEvent({ uri: "/.env", asn: "15169", userAgent: spoof }));
    await expectBlocked(makeEvent({ uri: "/@fs/app/.env", asn: "15169", userAgent: spoof }));
    await expectBlocked(makeEvent({ uri: "/proc/self/environ", asn: "15169", userAgent: spoof }));
  });

  it("keeps blocking a Google-InspectionTool UA spoof on scanner paths", async () => {
    const spoof = "Mozilla/5.0 (compatible; Google-InspectionTool/1.0)";
    await expectBlocked(makeEvent({ uri: "/.env", asn: "15169", userAgent: spoof }));
    await expectBlocked(makeEvent({ uri: "/@fs/app/.env", asn: "15169", userAgent: spoof }));
    await expectBlocked(makeEvent({ uri: "/proc/self/environ", asn: "15169", userAgent: spoof }));
  });

  it.each(["16509", "8075", "4134", "4837", "4766", "199457", "15169", "135377", "37963", "24429", "51396", "56044", "132525"])("blocks blocklisted AS%s without a KeyValueStore read", async (asn) => {
    await expectBlocked(makeEvent({ asn }));
    expect(kvsLookups).toEqual([]);
  });

  it("serves the feed, robots.txt and favicon.ico to a blocklisted ASN", async () => {
    // rationale: README.md#robots-always-allowed, README.md#favicon-always-served, README.md#feed-always-served
    await expectPassed(makeEvent({ uri: "/feed.xml", asn: "16509" }));
    await expectPassed(makeEvent({ uri: "/rss.xml", asn: "16509" }));
    await expectPassed(makeEvent({ uri: "/robots.txt", asn: "16509" }));
    await expectPassed(makeEvent({ uri: "/favicon.ico", asn: "16509" }));
  });

  it("keeps giving a blocklisted ASN a plain 404 on the pages themselves", async () => {
    await expectBlocked(makeEvent({ uri: "/2026/07/some-post/", asn: "16509" }));
  });

  it("does not match an ASN that merely contains a blocklisted number", () =>
    expectPassed(makeEvent({ asn: "3215" })));

  it.each([undefined, "", "-"])("fails open without a usable ASN header (%j)", async (asn) => {
    await expectPassed(makeEvent({ asn }));
    expect(kvsLookups).toEqual([]);
  });
});

// Step 10: KeyValueStore
describe("KeyValueStore lookup", () => {
  it("passes an ASN found in the store", async () => {
    await expectPassed(makeEvent({ asn: "3215" }));
    expect(kvsLookups).toEqual(["3215"]);
  });

  it("blocks an ASN missing from the store", () => expectBlocked(makeEvent({ asn: "99999" })));

  it("passes feeds like any other request (reader on an ISP)", () =>
    expectPassed(makeEvent({ uri: "/feed.xml", asn: "3215", userAgent: "Reeder/5060003 CFNetwork/3896" })));

  it("serves the real feed to a reader on an unknown ASN", () =>
    expectPassed(makeEvent({ uri: "/feed.xml", asn: "99999", userAgent: "SomeReader/1.0" })));

  it("serves robots.txt to a crawler blocked on its ASN", () =>
    expectPassed(makeEvent({ uri: "/robots.txt", asn: "99999" })));

  it("does not exempt a path that only ends with robots.txt", () =>
    expectBlocked(makeEvent({ uri: "/evil.com/robots.txt", asn: "99999" })));

  it("serves favicon.ico to a crawler blocked on its ASN", () =>
    expectPassed(makeEvent({ uri: "/favicon.ico", asn: "99999" })));

  it("does not exempt a path that only ends with favicon.ico", () =>
    expectBlocked(makeEvent({ uri: "/evil.com/favicon.ico", asn: "99999" })));

  it("does not exempt a path that only ends with feed.xml", () =>
    expectBlocked(makeEvent({ uri: "/evil.com/feed.xml", asn: "99999" })));

  it.each(["/feed.xml.php", "/feed.xml/../.env", "/rss.xml/wp-login.php", "/feed.xml/.git/config"])(
    "does not exempt %s, which only starts with a feed path", (uri) =>
      expectBlocked(makeEvent({ uri, asn: "16509", userAgent: "curl/8.5.0" })));

  it("does not exempt a path that only ends with rss.xml", () =>
    expectBlocked(makeEvent({ uri: "/evil.com/rss.xml", asn: "99999" })));

  it("fails open when the store read throws", async () => {
    kvs.exists = async () => { throw new Error("KVS unavailable"); };
    await expectPassed(makeEvent({ asn: "99999" }));
  });
});

describe("pass-through", () => {
  it.each(["/", "/about/", "/about", "/backup.zip", "/robots.txt", "/favicon.ico", "/feed.xml", "/rss.xml"])("returns the request for %s", (uri) =>
    expectPassed(makeEvent({ uri })));
});
