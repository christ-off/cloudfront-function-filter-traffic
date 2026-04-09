#!/bin/bash

PROJECT_ROOT="$(pwd)"
CONFIG_FILE="$PROJECT_ROOT/.cloudfront-function-name"
EVENT_FILE="$PROJECT_ROOT/test-event.json"

export AWS_PROFILE=default

fail() {
  printf '{"continue": false, "stopReason": "CloudFront pre-push: %s"}' "$*"
  exit 0
}

# Read function name
[ -f "$CONFIG_FILE" ] || fail ".cloudfront-function-name not found — create it with your CloudFront function name"
FUNC_NAME=$(tr -d '[:space:]' < "$CONFIG_FILE")
[ -n "$FUNC_NAME" ] || fail ".cloudfront-function-name is empty"

# Check test event exists
[ -f "$EVENT_FILE" ] || fail "test-event.json not found"

# Get current function info
DESCRIBE=$(aws cloudfront describe-function --name "$FUNC_NAME" --output json 2>&1)
if [ $? -ne 0 ]; then
  fail "cannot describe function '$FUNC_NAME' — check AWS credentials and function name"
fi
ETAG=$(echo "$DESCRIBE" | jq -r '.ETag')
COMMENT=$(echo "$DESCRIBE" | jq -r '.FunctionSummary.FunctionConfig.Comment // ""')

# Strip ES module export (needed for tests but unsupported by CloudFront runtime)
DEPLOY_FILE=$(mktemp /tmp/cloudfront-function-XXXXXX.js)
grep -v '^\s*export\s*{' "$PROJECT_ROOT/function.js" > "$DEPLOY_FILE"

# Update DEVELOPMENT stage with local code
UPDATE=$(aws cloudfront update-function \
  --name "$FUNC_NAME" \
  --if-match "$ETAG" \
  --function-config "{\"Comment\":\"$COMMENT\",\"Runtime\":\"cloudfront-js-2.0\"}" \
  --function-code "fileb://$DEPLOY_FILE" \
  --output json 2>&1)
UPDATE_STATUS=$?
rm -f "$DEPLOY_FILE"
if [ $UPDATE_STATUS -ne 0 ]; then
  fail "update-function failed — verify AWS permissions and function name"
fi

NEW_ETAG=$(echo "$UPDATE" | jq -r '.ETag')

# Test on cloudfront-js-2.0 runtime
TEST=$(aws cloudfront test-function \
  --name "$FUNC_NAME" \
  --if-match "$NEW_ETAG" \
  --stage DEVELOPMENT \
  --event-object "fileb://$EVENT_FILE" \
  --output json 2>&1)
if [ $? -ne 0 ]; then
  fail "test-function CLI error — check test-event.json format"
fi

# Check for runtime errors
ERROR=$(echo "$TEST" | jq -r '.TestResult.FunctionErrorMessage // ""')
if [ -n "$ERROR" ] && [ "$ERROR" != "null" ]; then
  fail "runtime error on cloudfront-js-2.0: $ERROR"
fi

printf '{"systemMessage": "CloudFront function validated on cloudfront-js-2.0 — OK to push"}'
exit 0