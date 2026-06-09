When blockedBotPatterns reaches 100 entries, propose to refactor as a regexp

# CloudFront Functions JS runtime constraints
function.js runs in the CloudFront Functions JavaScript runtime (cloudfront-js-2.0), NOT Node.js/browser JS.
It is ES5.1-based with only a partial, EXPLICIT allowlist of ES6-ES12 features — assume a "modern" feature
is UNSUPPORTED unless it's literally named in the runtime-2.0 docs page. Confirmed NOT supported (caused
"SyntaxError: Token ... not supported"/"Unexpected token" deploy failures here):
  - optional chaining `?.` and nullish coalescing `??` (NOT in the supported-operators list — only ES5.1
    operators + ES7 `**` are listed; do not trust generic "ES2020 supported" marketing blurbs)
  - ES2019 optional catch binding `catch { }` (must write `catch (e) { }`)
Always write the old-school equivalent: `a && a.b && a.b.c` instead of `a?.b?.c`, `catch (e)` instead of
`catch { }`.

Other "looks like standard JS" features that are ALSO absent from the runtime-2.0 allowlist — avoid
when simplifying, even though they'd pass Vitest/Node fine:
  - destructuring (`const { a } = obj`, `const [x] = arr`) — not listed anywhere in core features
  - spread syntax (`{...obj}`, `[...arr]`, `fn(...args)`) — only function *rest parameters* are listed,
    spread is a distinct feature and isn't
  - `for...of` loops / iterator protocol / generators / `Symbol.iterator` — only `for-in` is listed
  - `class` syntax — this runtime is prototype/function-based only
  - `Map`/`Set`/`WeakMap`/`WeakSet` — entirely absent from built-in objects
  - default parameters (`function f(a = 1)`)
  - logical assignment operators `||=`, `&&=`, `??=` (ES2021)
  - `Array.from()`, `.flat()`, `.flatMap()`, `.at()`, `Object.fromEntries()`, `Object.hasOwn()` — only
    the array/object methods explicitly named in the docs are supported, not the whole modern API surface
  - top-level `await` / async arrow functions / async closures — `async`/`await` only work inside a
    plain `async function`
Vitest passing is NOT sufficient proof the code will deploy: syntax valid in Node can still fail at
CloudFront. Before relying on ANY non-ES5.1 feature, fetch the runtime-2.0 docs page FRESH and grep for
the exact feature name — don't trust memory, training data, or web-search summaries (they can be wrong,
as the "?. is supported" claim was):
https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/functions-javascript-runtime-20.html
After pushing to main, check that the GitHub Actions deploy succeeded AND that the CloudFront function
itself runs without "invalid or could not run" errors (e.g. via `aws cloudfront test-function` or by
checking distribution logs), since the deploy step can succeed while the published function is broken.

# Other filtering advice

Do not block Chrome requests solely because the User-Agent contains a `.0.0.0` minor/patch version.
Real Chrome browsers intentionally report only the major version (e.g. `Chrome/136.0.0.0`) to reduce
fingerprinting — the `.0.0.0` suffix is normal and expected, not a bot indicator.

# git push must run standalone (not chained)
A PreToolUse hook (`.claude/hooks/cloudfront-pre-push.sh`) validates function.js against the real
cloudfront-js-2.0 runtime via `aws cloudfront test-function` and BLOCKS the push if it errors — this
is exactly the safety net that would have caught the `catch { }` runtime incompatibility above.
It only fires when the Bash command literally starts with `git push` (matcher `Bash(git push*)`).
Always run `git push` as its own Bash call — never chain it with `&&` after `git add`/`git commit`,
or the matcher won't match and the hook silently won't run.
