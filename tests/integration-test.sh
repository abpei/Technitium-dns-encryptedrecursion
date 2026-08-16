#!/usr/bin/env bash
# Integration test script for Technitium DNS Server fork (encrypted-recursion).
# Runs automated tests against a Docker container. Exits 0 on all pass, non-zero on failure.
# Usage: ./tests/integration-test.sh [--no-cleanup] [--container-name NAME] [--repo-path PATH]
set -euo pipefail

# --- Configuration ---
CONTAINER_NAME="${CONTAINER_NAME:-dns-test}"
IMAGE_NAME="${IMAGE_NAME:-technitium-fork:test}"
REPO_PATH="${REPO_PATH:-.}"
WEB_PORT="${WEB_PORT:-15380}"
DNS_PORT="${DNS_PORT:-15353}"
DOH_PORT="${DOH_PORT:-1443}"
DOT_PORT="${DOT_PORT:-1853}"
HTTPS_WEB_PORT="${HTTPS_WEB_PORT:-13443}"
API_USER="${API_USER:-admin}"
API_PASS="${API_PASS:-admin}"
NO_CLEANUP=false
PASSED=0
FAILED=0
SKIPPED=0
TESTS=()

# --- Argument parsing ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-cleanup) NO_CLEANUP=true; shift ;;
        --container-name) CONTAINER_NAME="$2"; shift 2 ;;
        --repo-path) REPO_PATH="$2"; shift 2 ;;
        --image-name) IMAGE_NAME="$2"; shift 2 ;;
        --web-port) WEB_PORT="$2"; shift 2 ;;
        --dns-port) DNS_PORT="$2"; shift 2 ;;
        --doh-port) DOH_PORT="$2"; shift 2 ;;
        --dot-port) DOT_PORT="$2"; shift 2 ;;
        --https-web-port) HTTPS_WEB_PORT="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# --- Helper functions ---
log_test() {
    local name="$1" status="$2" detail="${3:-}"
    TESTS+=("$name|$status")
    if [[ "$status" == "PASS" ]]; then
        echo "PASS: $name"
        ((PASSED++)) || true
    elif [[ "$status" == "SKIP" ]]; then
        echo "SKIP: $name -- $detail"
        ((SKIPPED++)) || true
    else
        echo "FAIL: $name -- $detail"
        ((FAILED++)) || true
    fi
}

# Wait for a URL to return HTTP 200
wait_for_url() {
    local url="$1" timeout="${2:-60}" interval="${3:-2}"
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null | grep -q "200"; then
            return 0
        fi
        sleep "$interval"
        ((elapsed += interval))
    done
    return 1
}

# Base64url-encode a DNS query wire format for DoH GET requests
dns_query_base64url() {
    printf '\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' | base64 | tr '+/' '-_' | tr -d '='
}

# Parse RA flag from DNS wire response (byte 3, bit 7)
get_ra_flag() {
    local file="$1"
    python3 -c "
import struct, sys
with open('$file', 'rb') as f:
    data = f.read()
if len(data) >= 4:
    flags = struct.unpack('!H', data[2:4])[0]
    ra = (flags >> 7) & 1
    print(ra)
else:
    print(0)
" 2>/dev/null || echo "0"
}

# --- Cleanup function ---
cleanup() {
    if [[ "$NO_CLEANUP" == "true" ]]; then
        echo "Skipping cleanup (--no-cleanup)"
        return
    fi
    echo ""
    echo "Cleaning up container: $CONTAINER_NAME"
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    rm -f /tmp/dns-cert-*.pem /tmp/doh_query.bin /tmp/doh_response.bin /tmp/doh_ra_test.bin
}

# --- Setup ---
echo "=== Technitium DNS Fork Integration Tests ==="
echo "Container: $CONTAINER_NAME"
echo "Image: $IMAGE_NAME"
echo "Repo: $REPO_PATH"
echo ""

# Build image if needed
if ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
    echo "Building Docker image: $IMAGE_NAME"
    docker build -t "$IMAGE_NAME" "$REPO_PATH"
fi

# Remove any existing container
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

# Start container with env vars for self-signed TLS
echo "Starting container..."
docker run -d --name "$CONTAINER_NAME" \
    -p "${DNS_PORT}:53/udp" \
    -p "${DNS_PORT}:53/tcp" \
    -p "${DOH_PORT}:443/tcp" \
    -p "${DOT_PORT}:853/tcp" \
    -p "${WEB_PORT}:5380/tcp" \
    -p "${HTTPS_WEB_PORT}:53443/tcp" \
    -e DNS_SERVER_DOMAIN=localhost \
    -e DNS_SERVER_WEB_SERVICE_ENABLE_HTTPS=true \
    -e DNS_SERVER_WEB_SERVICE_USE_SELF_SIGNED_CERT=true \
    "$IMAGE_NAME"

trap cleanup EXIT

# Wait for web console
echo "Waiting for web console..."
if ! wait_for_url "http://localhost:${WEB_PORT}/" 60; then
    echo "FATAL: Web console did not start within 60 seconds"
    docker logs "$CONTAINER_NAME" 2>&1 | tail -20
    exit 1
fi
echo "Web console is ready."
echo ""

# Get API token
echo "Authenticating..."
LOGIN_RESPONSE=$(curl -s "http://localhost:${WEB_PORT}/api/user/login?user=${API_USER}&pass=${API_PASS}&includeInfo=true")
TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4)
if [[ -z "$TOKEN" ]]; then
    echo "FATAL: Failed to obtain API token"
    echo "Response: $LOGIN_RESPONSE"
    exit 1
fi
echo "Token obtained."
echo ""

# Configure DoH with DNS TLS certificate and recursion mode
echo "Configuring DoH and recursion settings..."
curl -s "http://localhost:${WEB_PORT}/api/settings/set?token=${TOKEN}&dnsTlsCertificatePath=/etc/dns/self-signed-cert.pfx&dnsTlsCertificatePassword=&enableDnsOverHttps=true&dnsOverHttpsPort=443&recursion=AllowOnlyForOptionalProtocols" -o /dev/null
echo "Settings applied. Waiting for DNS service restart..."
sleep 12

# Re-authenticate after potential restart
LOGIN_RESPONSE=$(curl -s "http://localhost:${WEB_PORT}/api/user/login?user=${API_USER}&pass=${API_PASS}&includeInfo=true")
TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4)

# Extract self-signed cert for DoH tests
CERT_FILE=$(mktemp /tmp/dns-cert-XXXXXX.pem)
docker exec "$CONTAINER_NAME" cat /etc/dns/self-signed-cert.pfx | openssl pkcs12 -clcerts -nokeys -out "$CERT_FILE" -passin pass: 2>/dev/null || true
trap 'rm -f "$CERT_FILE" /tmp/doh_query.bin /tmp/doh_response.bin /tmp/doh_ra_test.bin; cleanup' EXIT

# Create DNS query wire format file
printf '\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' > /tmp/doh_query.bin

echo "Running tests..."
echo "============================================"
echo ""

# ============================================
# TEST 1: Web console accessible via curl returning HTTP 200
# ============================================
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${WEB_PORT}/" 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" == "200" ]]; then
    log_test "1. Web console accessible (HTTP 200)" "PASS"
else
    log_test "1. Web console accessible (HTTP 200)" "FAIL" "Got HTTP $HTTP_CODE"
fi

# ============================================
# TEST 2: About page shows fork version with (dev in stats API
# ============================================
VERSION_RESPONSE=$(curl -s "http://localhost:${WEB_PORT}/api/user/login?user=${API_USER}&pass=${API_PASS}&includeInfo=true" 2>/dev/null)
VERSION=$(echo "$VERSION_RESPONSE" | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)
if echo "$VERSION" | grep -q "(dev"; then
    log_test "2. Fork version contains '(dev'" "PASS" "Version: $VERSION"
else
    log_test "2. Fork version contains '(dev'" "FAIL" "Version: $VERSION"
fi

# ============================================
# TEST 3: DoH endpoint returns valid DNS response via curl
# ============================================
DOH_HTTP=$(curl -s --cacert "$CERT_FILE" \
    "https://localhost:${DOH_PORT}/dns-query" \
    -H "Accept: application/dns-message" \
    -H "Content-Type: application/dns-message" \
    --data-binary @/tmp/doh_query.bin \
    -o /tmp/doh_response.bin \
    -w "%{http_code}" 2>/dev/null || echo "000")
DOH_SIZE=$(stat -c%s /tmp/doh_response.bin 2>/dev/null || echo "0")
if [[ "$DOH_HTTP" == "200" ]] && [[ "$DOH_SIZE" -gt 12 ]]; then
    log_test "3. DoH endpoint returns valid DNS response" "PASS" "HTTP $DOH_HTTP, ${DOH_SIZE} bytes"
else
    log_test "3. DoH endpoint returns valid DNS response" "FAIL" "HTTP $DOH_HTTP, ${DOH_SIZE} bytes"
fi

# ============================================
# TEST 4: DoT endpoint works with kdig (or dig + TLS check as fallback)
# ============================================
if command -v kdig &>/dev/null; then
    DOT_OUTPUT=$(kdig @localhost -p "${DOT_PORT}" +tls example.com 2>&1 || true)
    if echo "$DOT_OUTPUT" | grep -q "example.com"; then
        log_test "4. DoT endpoint works (kdig)" "PASS"
    else
        log_test "4. DoT endpoint works (kdig)" "FAIL" "No example.com in response"
    fi
else
    # Check if DoT port is reachable and TLS is working
    DOT_TLS=$(echo "" | timeout 5 openssl s_client -connect "localhost:${DOT_PORT}" 2>&1 || true)
    if echo "$DOT_TLS" | grep -q "BEGIN CERTIFICATE\|Protocol.*TLS\|Verify return code"; then
        log_test "4. DoT endpoint reachable (TLS listener active)" "PASS" "kdig not installed, verified TLS on port ${DOT_PORT}"
    elif timeout 2 bash -c "echo > /dev/tcp/localhost/${DOT_PORT}" 2>/dev/null; then
        log_test "4. DoT endpoint reachable (port open)" "PASS" "kdig not installed, port is open"
    else
        log_test "4. DoT endpoint reachable" "FAIL" "Port ${DOT_PORT} not reachable"
    fi
fi

# ============================================
# TEST 5: Custom landing page set via API returns custom content
# ============================================
CUSTOM_HTML="<h1>PiDoH Encrypted MapleDNS</h1><p>Visit <a href=\"https://maplecube.net/pidoh\">maplecube.net/pidoh</a> to learn more.</p>"
ENCODED_HTML=$(printf '%s' "$CUSTOM_HTML" | sed 's/ /%20/g; s/</%3C/g; s/>/%3E/g')
SET_RESULT=$(curl -s "http://localhost:${WEB_PORT}/api/settings/set?token=${TOKEN}&dohCustomLandingPageHtml=${ENCODED_HTML}" 2>/dev/null)
SET_STATUS=$(echo "$SET_RESULT" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
if [[ "$SET_STATUS" == "ok" ]]; then
    GET_RESULT=$(curl -s "http://localhost:${WEB_PORT}/api/settings/get?token=${TOKEN}" 2>/dev/null)
    if echo "$GET_RESULT" | grep -q "PiDoH Encrypted MapleDNS"; then
        log_test "5. Custom landing page set via API" "PASS"
    else
        log_test "5. Custom landing page set via API" "FAIL" "Set OK but value not found in GET"
    fi
else
    log_test "5. Custom landing page set via API" "FAIL" "Set returned: $SET_STATUS"
fi

# ============================================
# TEST 5b: DoH root URL serves custom landing page
# ============================================
LANDING_BODY=$(curl -sk "https://localhost:${DOH_PORT}/" 2>/dev/null)
if echo "$LANDING_BODY" | grep -q "PiDoH Encrypted MapleDNS"; then
    log_test "5b. DoH root URL serves custom landing page" "PASS"
else
    log_test "5b. DoH root URL serves custom landing page" "FAIL" "Custom HTML not found in response"
fi

# ============================================
# TEST 6: Recursion on port 53 denied with RA=0 for AllowOnlyForOptionalProtocols
# ============================================
DIG_OUTPUT=$(dig @localhost -p "${DNS_PORT}" example.com A +norecurse 2>&1 || true)
FLAGS=$(echo "$DIG_OUTPUT" | grep -o "flags: [^;]*" | head -1)
if echo "$FLAGS" | grep -qv "ra"; then
    log_test "6. Recursion on port 53 denied (RA=0)" "PASS" "Flags: $FLAGS"
else
    log_test "6. Recursion on port 53 denied (RA=0)" "FAIL" "RA flag present: $FLAGS"
fi

# ============================================
# TEST 7: Recursion on DoH allowed with RA=1
# ============================================
DOH_RA_HTTP=$(curl -s --cacert "$CERT_FILE" \
    "https://localhost:${DOH_PORT}/dns-query" \
    -H "Accept: application/dns-message" \
    -H "Content-Type: application/dns-message" \
    --data-binary @/tmp/doh_query.bin \
    -o /tmp/doh_ra_test.bin \
    -w "%{http_code}" 2>/dev/null || echo "000")
if [[ "$DOH_RA_HTTP" == "200" ]] && [[ -s /tmp/doh_ra_test.bin ]]; then
    RA_FLAG=$(get_ra_flag /tmp/doh_ra_test.bin)
    if [[ "$RA_FLAG" == "1" ]]; then
        log_test "7. Recursion on DoH allowed (RA=1)" "PASS"
    else
        log_test "7. Recursion on DoH allowed (RA=1)" "FAIL" "RA flag is $RA_FLAG in DoH response"
    fi
else
    log_test "7. Recursion on DoH allowed (RA=1)" "FAIL" "DoH request failed: HTTP $DOH_RA_HTTP"
fi

# ============================================
# TEST 8: Update check for update.json
# ============================================
UPDATE_RESPONSE=$(curl -s "http://localhost:${WEB_PORT}/api/user/checkForUpdate?token=${TOKEN}" 2>/dev/null)
UPDATE_STATUS=$(echo "$UPDATE_RESPONSE" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
if [[ "$UPDATE_STATUS" == "ok" ]]; then
    if echo "$UPDATE_RESPONSE" | grep -q '"updateAvailable"'; then
        UPDATE_AVAILABLE=$(echo "$UPDATE_RESPONSE" | grep -o '"updateAvailable":[a-z]*' | cut -d':' -f2)
        log_test "8. Update check API works" "PASS" "updateAvailable=$UPDATE_AVAILABLE"
    else
        log_test "8. Update check API works" "FAIL" "Missing updateAvailable field"
    fi
else
    log_test "8. Update check API works" "FAIL" "Status: $UPDATE_STATUS"
fi

# ============================================
# Summary
# ============================================
echo ""
echo "============================================"
echo "RESULTS: $PASSED passed, $FAILED failed, $SKIPPED skipped out of $((PASSED + FAILED + SKIPPED)) tests"
echo "============================================"
echo ""
for entry in "${TESTS[@]}"; do
    name="${entry%%|*}"
    status="${entry##*|}"
    case "$status" in
        PASS) echo "  [PASS] $name" ;;
        SKIP) echo "  [SKIP] $name" ;;
        FAIL) echo "  [FAIL] $name" ;;
    esac
done

if [[ $FAILED -gt 0 ]]; then
    echo ""
    echo "SOME TESTS FAILED"
    exit 1
else
    echo ""
    echo "ALL TESTS PASSED"
    exit 0
fi
