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
`catch { }`. Vitest passing is NOT sufficient proof the code will deploy: a syntax valid in Node can still
fail at CloudFront. Before relying on ANY non-ES5.1 feature, grep the actual runtime-2.0 docs page for the
exact feature name (fetch it fresh — don't rely on memory or web-search summaries, they can be wrong):
https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/functions-javascript-runtime-20.html
After pushing to main, check that the GitHub Actions deploy succeeded AND that the CloudFront function
itself runs without "invalid or could not run" errors (e.g. via `aws cloudfront test-function` or by
checking distribution logs), since the deploy step can succeed while the published function is broken.

# git push must run standalone (not chained)
A PreToolUse hook (`.claude/hooks/cloudfront-pre-push.sh`) validates function.js against the real
cloudfront-js-2.0 runtime via `aws cloudfront test-function` and BLOCKS the push if it errors — this
is exactly the safety net that would have caught the `catch { }` runtime incompatibility above.
It only fires when the Bash command literally starts with `git push` (matcher `Bash(git push*)`).
Always run `git push` as its own Bash call — never chain it with `&&` after `git add`/`git commit`,
or the matcher won't match and the hook silently won't run.
