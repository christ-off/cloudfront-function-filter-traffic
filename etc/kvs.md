# CloudFront KeyValueStore (KVS) for IP ranges

**Decision: not adopted yet.** Keep `blockedIpRangeRegex` in `function.js` (simple, git-reviewed, covered by vitest and the pre-push hook). Revisit if the list grows past ~20–30 ranges or ranges must change without a code push.

## Fit
- KVS suits data that changes without redeploying the function; sub-millisecond reads, supported in `cloudfront-js-2.0`.
- Store `/24` prefixes as keys (e.g. `45.148.10`), look up the first 3 octets: O(1) `kvs.get()`, no impact on the 10 kB function limit (function.js ~8 KB).
- Limits: 5 MB per store, 10M keys. `kvs.get()` is async, so the handler must be `async function` (not an arrow).
- Exact-match only: `/16` needs an extra 2-octet lookup, `/22` must be expanded into several `/24` keys. IPv6 needs its own prefix scheme. Bot regexes stay in code.

## Costs
- Each `kvs.get` counts toward the function's compute-utilization budget and adds a lookup per request.
- Extra infra: store, function association, IAM permissions.
- Loses "blocklist in git" unless a repo file stays the source of truth. Tests need a mocked `cf.kvs()`.

## Deploy process (if adopted)
1. One-off: `aws cloudfront create-key-value-store --name ip-blocklist`; associate it with the function (`KeyValueStoreAssociations`) and add the ARN to `deploy.yml`.
2. Source of truth in repo: `blocked-ips.txt`, one prefix per line.
3. CI syncs on change: get the ETag via `aws cloudfront-keyvaluestore describe-key-value-store`, then `aws cloudfront-keyvaluestore update-keys --if-match <etag> --puts ... --deletes ...` (max 50 items per call).
4. Live globally within seconds; no function publish needed.
5. Deploy role needs `cloudfront-keyvaluestore:DescribeKeyValueStore`, `PutKey`, `DeleteKey`, `UpdateKeys`.
