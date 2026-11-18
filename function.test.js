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
    "Scrapy/2.16.0", "python-requests/2.31", "curl/8.0", "Baiduspider/2.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1)", "FeedFetcher-Google; (+http://www.google.com/feedfetcher.html)",
  ])("blocks the bot UA %s", (userAgent) => expectBlocked(makeEvent({ userAgent })));

  it("blocks bots and scanners on the feed and robots.txt too (plain 404, no fake answer)", async () => {
    await expectBlocked(makeEvent({ uri: "/feed.xml", userAgent: "Scrapy/2.16.0" }));
    await expectBlocked(makeEvent({ uri: "/robots.txt", userAgent: "Scrapy/2.16.0" }));
    await expectBlocked(makeEvent({ uri: "/feed.xml", userAgent: null }));
  });

  it("blocks cheap-check failures without reading the KeyValueStore", async () => {
    await expectBlocked(makeEvent({ uri: "/wp-login.php", asn: "3215" }));
    expect(kvsLookups).toEqual([]);
  });
});

// Step 5: .json / .js allowlists and cover referer apply to everyone, whitelisted ASN included
describe("asset rules", () => {
  it("allows the listed json and js files, blocks the others", async () => {
    await expectPassed(makeEvent({ uri: "/about/data/visitors.json" }));
    await expectPassed(makeEvent({ uri: "/pagefind/pagefind.js" }));
    await expectBlocked(makeEvent({ uri: "/human.json" }));
    await expectBlocked(makeEvent({ uri: "/other.json" }));
    await expectBlocked(makeEvent({ uri: "/other.js" }));
  });

  it("only serves covers with the site referer", async () => {
    await expectBlocked(makeEvent({ uri: "/assets/posts/a.webp" }));
    await expectBlocked(makeEvent({ uri: "/assets/posts/a.webp", referer: "https://evil.example/" }));
    await expectPassed(makeEvent({ uri: "/assets/posts/a.webp", referer: "https://post-tenebras-lire.net/x/" }));
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
  ])("passes hosted software on a blocked ASN: %s", async (userAgent) => {
    await expectPassed(makeEvent({ asn: "8075", userAgent }));
    expect(kvsLookups).toEqual([]);
  });

  it.each(["16509", "8075", "4134", "4837", "4766", "199457", "15169"])("blocks blocklisted AS%s without a KeyValueStore read", async (asn) => {
    await expectBlocked(makeEvent({ asn }));
    expect(kvsLookups).toEqual([]);
  });

  it("blocks the blocklisted ASN on the feed too (no feed exemption)", () =>
    expectBlocked(makeEvent({ uri: "/feed.xml", asn: "16509" })));

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

  it("blocks a feed reader on an unknown ASN without a whitelisted UA", () =>
    expectBlocked(makeEvent({ uri: "/feed.xml", asn: "99999", userAgent: "SomeReader/1.0" })));

  it("fails open when the store read throws", async () => {
    kvs.exists = async () => { throw new Error("KVS unavailable"); };
    await expectPassed(makeEvent({ asn: "99999" }));
  });
});

describe("pass-through", () => {
  it.each(["/", "/about/", "/about", "/backup.zip", "/robots.txt", "/feed.xml"])("returns the request for %s", (uri) =>
    expectPassed(makeEvent({ uri })));
});
