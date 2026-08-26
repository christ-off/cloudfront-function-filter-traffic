---
updated: 2026-07-25
---

# currentDate
Today's date is 2026-07-25.

# CloudFront Functions JS runtime (cloudfront-js-2.0)
function.js runs in CloudFront Functions, NOT Node.js. ES5.1 base with partial ES6-ES12 allowlist — assume UNSUPPORTED unless explicitly named in the [runtime docs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/functions-javascript-runtime-20.html).

**Confirmed NOT supported (caused deploy failures):** `?.` / `??`, `catch { }` (use `catch (e) { }`)

**Also absent (write old-school equivalents):**
- Destructuring, spread `{...obj}`, default params `f(a=1)`
- `for...of`, generators, `class`, `Map`/`Set`/`WeakMap`/`WeakSet`
- `Array.from()`, `.flat()`, `.flatMap()`, `.at()`, `Object.fromEntries()`
- `async`/`await` only inside `async function` (not arrow)

Vitest passing ≠ CloudFront deployable. Before using any non-ES5.1 feature, fetch the runtime-2.0 docs page FRESH and grep for the exact feature name.

After pushing to main, check GitHub Actions deploy succeeded AND function runs without "invalid or could not run" errors (e.g. `aws cloudfront test-function`).

# Blocking patterns
Do not block Chrome requests solely because UA contains `.0.0.0` minor/patch version — real Chrome browsers report only major version to reduce fingerprinting.

# git push
Must run standalone (not chained with `&&`). A PreToolUse hook (`cloudfront-pre-push.sh`) validates `function.js` against the real runtime and blocks the push if it errors — it only fires when the Bash command literally starts with `git push`.

Size: function.js must stay below 10kB.

# Comments vs README.md
function.js keeps only short `// rationale: README.md#anchor` pointer comments — the full reasoning lives under "## Blocking rules — rationale" in README.md, keyed by anchor to the const/function it explains. Whenever you rename an identifier a pointer references, add a new rule, or change the reasoning behind one, update both sides together and check they still match — a stale anchor or an orphaned README section is a bug.
