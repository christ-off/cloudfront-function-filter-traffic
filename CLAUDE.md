When blockedBotPatterns reaches 100 entries, propose to refactor as a regexp

# CloudFront Functions JS runtime constraints
function.js runs in the CloudFront Functions JavaScript runtime (cloudfront-js-2.0), NOT Node.js/browser JS.
It is ES5.1-based with only a partial ES6-ES12 subset (e.g. optional chaining `?.` and template literals
ARE supported, but ES2019 optional catch binding `catch { }` is NOT — always write `catch (e) { }`).
Vitest passing is NOT sufficient proof the code will deploy: a syntax-valid-in-Node change can still fail
at CloudFront with "SyntaxError: Token ... not supported in this version". Before relying on a "modern"
JS feature, verify it against the runtime docs:
https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/functions-javascript-runtime-20.html
After pushing to main, check that the GitHub Actions deploy succeeded AND that the CloudFront function
itself runs without "invalid or could not run" errors (e.g. via `aws cloudfront test-function` or by
checking distribution logs), since the deploy step can succeed while the published function is broken.
