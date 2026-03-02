#!/bin/bash
set -euo pipefail

# ─── Colors ───
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_COUNT=0

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    echo -e "  ${GREEN}PASS${NC} $1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    echo -e "  ${RED}FAIL${NC} $1"
    [ -n "${2:-}" ] && echo -e "       ${RED}→ $2${NC}"
}

# ─── Wait for dependencies ───

echo "client: waiting for PKI..."
timeout 30 bash -c 'until [ -f /pki/ca.crt ] && [ -f /pki/client-valid.crt ]; do sleep 0.5; done'
echo "client: PKI ready"

echo "client: waiting for server..."
timeout 30 bash -c 'until echo > /dev/tcp/server/2345 2>/dev/null; do sleep 0.5; done'
echo "client: server reachable"

BUILD_DIR="/build/pkcs11-proxy"
TEST_PKCS11_TOOL="${BUILD_DIR}/tests/test-pkcs11-tool"
PKCS11_PROXY_LIB="${BUILD_DIR}/libpkcs11-proxy.so"

# Helper: run a PKCS#11 operation through the proxy
# Usage: run_test <client_cert> <client_key>
# Sets: TEST_OUTPUT, TEST_RC
run_test() {
    local cert="$1"
    local key="$2"

    set +e
    TEST_OUTPUT=$(
        PKCS11_PROXY_SOCKET="tls://server:2345" \
        PKCS11_PROXY_TLS_CERT="${cert}" \
        PKCS11_PROXY_TLS_KEY="${key}" \
        PKCS11_PROXY_TLS_CA="/pki/ca.crt" \
        PKCS11_PROXY_TLS_SERVER_NAME="server" \
        timeout 10 "${TEST_PKCS11_TOOL}" "${PKCS11_PROXY_LIB}" 2>/dev/null
    )
    TEST_RC=$?
    set -e
}

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Docker Compose Integration Tests            ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ─── I1: Valid client cert with correct OID → accepted ───
run_test "/pki/client-valid.crt" "/pki/client-valid.key"
if [ "${TEST_RC}" -eq 0 ] && echo "${TEST_OUTPUT}" | grep -q "CRYPTO=pass"; then
    pass "I1: Valid OID client → PKCS#11 crypto succeeds"
else
    fail "I1: Valid OID client → PKCS#11 crypto succeeds" "rc=${TEST_RC} output=${TEST_OUTPUT}"
fi

# ─── I2: Multiple sequential connections ───
all_ok=1
for i in 1 2 3; do
    run_test "/pki/client-valid.crt" "/pki/client-valid.key"
    if [ "${TEST_RC}" -ne 0 ]; then
        all_ok=0
        break
    fi
done
if [ "${all_ok}" -eq 1 ]; then
    pass "I2: Multiple sequential connections succeed"
else
    fail "I2: Multiple sequential connections succeed" "failed on iteration ${i}"
fi

# ─── I3: Client cert with wrong repo OID → rejected ───
run_test "/pki/client-wrong.crt" "/pki/client-wrong.key"
if [ "${TEST_RC}" -ne 0 ]; then
    pass "I3: Wrong-repo OID client → rejected"
else
    fail "I3: Wrong-repo OID client → rejected" "expected failure, got rc=0"
fi

# ─── I4: Client cert with no OID → rejected ───
run_test "/pki/client-no-oid.crt" "/pki/client-no-oid.key"
if [ "${TEST_RC}" -ne 0 ]; then
    pass "I4: No-OID client → rejected"
else
    fail "I4: No-OID client → rejected" "expected failure, got rc=0"
fi

# ─── I5: Valid client works again after rejections (daemon still healthy) ───
run_test "/pki/client-valid.crt" "/pki/client-valid.key"
if [ "${TEST_RC}" -eq 0 ] && echo "${TEST_OUTPUT}" | grep -q "CRYPTO=pass"; then
    pass "I5: Daemon healthy after rejections → crypto still works"
else
    fail "I5: Daemon healthy after rejections → valid client still works" "rc=${TEST_RC}"
fi

# ─── Summary ───
echo ""
echo -e "${CYAN}━━━ Integration Summary ━━━${NC}"
echo -e "  Total: ${TOTAL_COUNT}"
echo -e "  ${GREEN}Pass:  ${PASS_COUNT}${NC}"
echo -e "  ${RED}Fail:  ${FAIL_COUNT}${NC}"
echo ""

if [ "${FAIL_COUNT}" -gt 0 ]; then
    echo -e "${RED}INTEGRATION TESTS FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}ALL INTEGRATION TESTS PASSED${NC}"
    exit 0
fi
