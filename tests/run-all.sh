#!/bin/bash
set -uo pipefail

# pkcs11-proxy TLS test suite
# Run inside the test Docker container after build + PKI generation.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKI_DIR="${SCRIPT_DIR}/pki"
BUILD_DIR="${SCRIPT_DIR}/.."

TEST_SERVER="${SCRIPT_DIR}/test-tls-server"
TEST_CLIENT="${SCRIPT_DIR}/test-tls-client"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TOTAL_COUNT=0

# ─── Colors ───
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ─── Test helpers ───

log_header() {
    echo ""
    echo -e "${CYAN}━━━ $1 ━━━${NC}"
}

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    echo -e "  ${GREEN}PASS${NC} $1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    echo -e "  ${RED}FAIL${NC} $1: $2"
}

skip() {
    SKIP_COUNT=$((SKIP_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    echo -e "  ${YELLOW}SKIP${NC} $1: $2"
}

# Start the test TLS server in background, wait for it to be ready, capture port.
# Usage: start_server <server_cert> <server_key> <ca_cert> [require_mtls]
# Sets: SERVER_PID, SERVER_PORT
start_server() {
    local cert="$1"
    local key="$2"
    local ca="$3"
    local mtls="${4:-true}"

    local port_file
    port_file=$(mktemp)

    TEST_TLS_CERT="${cert}" \
    TEST_TLS_KEY="${key}" \
    TEST_TLS_CA="${ca}" \
    TEST_TLS_REQUIRE_MTLS="${mtls}" \
    TEST_TLS_PORT=0 \
    TEST_TLS_PORT_FILE="${port_file}" \
    "${TEST_SERVER}" &
    SERVER_PID=$!

    # Wait for server to write port file (up to 5s)
    local elapsed=0
    while [ ! -s "${port_file}" ] && [ "${elapsed}" -lt 50 ]; do
        sleep 0.1
        elapsed=$((elapsed + 1))
        # Check if server crashed
        if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
            SERVER_PORT=0
            rm -f "${port_file}"
            return 1
        fi
    done

    if [ -s "${port_file}" ]; then
        SERVER_PORT=$(cat "${port_file}")
        rm -f "${port_file}"
        return 0
    else
        rm -f "${port_file}"
        SERVER_PORT=0
        return 1
    fi
}

stop_server() {
    if [ -n "${SERVER_PID:-}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    SERVER_PID=""
    SERVER_PORT=""
}

# Run the test TLS client. Returns the client exit code.
# Usage: run_client <ca_cert> [cert] [key] [server_name] [max_version] [message]
run_client() {
    local ca="$1"
    local cert="${2:-}"
    local key="${3:-}"
    local server_name="${4:-localhost}"
    local max_version="${5:-1.3}"
    local message="${6:-PING}"

    local env_args=()
    env_args+=(TEST_TLS_PORT="${SERVER_PORT}")
    env_args+=(TEST_TLS_CA="${ca}")
    env_args+=(TEST_TLS_SERVER_NAME="${server_name}")
    env_args+=(TEST_TLS_MAX_VERSION="${max_version}")
    env_args+=(TEST_TLS_MESSAGE="${message}")

    if [ -n "${cert}" ]; then
        env_args+=(TEST_TLS_CERT="${cert}")
    fi
    if [ -n "${key}" ]; then
        env_args+=(TEST_TLS_KEY="${key}")
    fi

    env "${env_args[@]}" "${TEST_CLIENT}" 2>/dev/null
    return $?
}

# ─── Expect helper: run client and check exit code ───
# Usage: expect_exit <test_id> <description> <expected_exit> <ca> [cert] [key] [server_name] [max_ver] [msg]
# expected_exit can be "2|3" to accept either (for TLS 1.3 post-handshake auth errors)
expect_exit() {
    local test_id="$1"
    local desc="$2"
    local expected="$3"
    shift 3

    local actual
    run_client "$@"
    actual=$?

    # Support "2|3" style expected values
    local ok=0
    for e in $(echo "${expected}" | tr '|' ' '); do
        if [ "${actual}" -eq "${e}" ]; then
            ok=1
            break
        fi
    done

    if [ "${ok}" -eq 1 ]; then
        pass "${test_id}: ${desc}"
    else
        fail "${test_id}: ${desc}" "expected exit=${expected}, got exit=${actual}"
    fi
}

# ═══════════════════════════════════════════
# TLS 1.3 BASIC CONNECTIVITY (T01-T05)
# ═══════════════════════════════════════════

test_tls_basic() {
    log_header "TLS 1.3 Basic Connectivity"

    # T01: Valid mTLS handshake
    start_server \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" "true"
    if [ $? -ne 0 ]; then
        fail "T01" "server failed to start"
    else
        expect_exit "T01" "Valid mTLS handshake" 0 \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-valid.crt" "${PKI_DIR}/client-valid.key" \
            "localhost"
    fi
    stop_server

    # T02: Client connects without client cert (mTLS required → reject)
    # In TLS 1.3, client cert is post-handshake so error may come during data exchange (exit 3)
    start_server \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" "true"
    if [ $? -ne 0 ]; then
        fail "T02" "server failed to start"
    else
        expect_exit "T02" "No client cert → rejected" "2|3" \
            "${PKI_DIR}/root-ca.crt" \
            "" "" \
            "localhost"
    fi
    stop_server

    # T03: Client cert from wrong CA
    # Same TLS 1.3 post-handshake auth: error may come as exit 2 or 3
    start_server \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" "true"
    if [ $? -ne 0 ]; then
        fail "T03" "server failed to start"
    else
        expect_exit "T03" "Wrong CA client cert → rejected" "2|3" \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-wrong-ca.crt" "${PKI_DIR}/client-wrong-ca.key" \
            "localhost"
    fi
    stop_server

    # T04: Verify TLS 1.3 is negotiated (using openssl s_client)
    start_server \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" "true"
    if [ $? -ne 0 ]; then
        fail "T04" "server failed to start"
    else
        local s_client_output
        s_client_output=$(echo "PING" | timeout 5 openssl s_client \
            -connect "127.0.0.1:${SERVER_PORT}" \
            -tls1_3 \
            -CAfile "${PKI_DIR}/root-ca.crt" \
            -cert "${PKI_DIR}/client-valid.crt" \
            -key "${PKI_DIR}/client-valid.key" \
            2>&1 || true)
        if echo "${s_client_output}" | grep -qE "(Protocol\s*:\s*TLSv1\.3|TLSv1\.3)"; then
            pass "T04: TLS 1.3 negotiated"
        else
            fail "T04: TLS 1.3 negotiated" "TLSv1.3 not found in s_client output"
        fi
    fi
    stop_server

    # T05: TLS 1.2 client → rejected by TLS 1.3-only server
    start_server \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" "true"
    if [ $? -ne 0 ]; then
        fail "T05" "server failed to start"
    else
        expect_exit "T05" "TLS 1.2 client → rejected" 2 \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-valid.crt" "${PKI_DIR}/client-valid.key" \
            "localhost" "1.2"
    fi
    stop_server
}

# ═══════════════════════════════════════════
# OID POLICY — SERVER-SIDE (T10-T16)
# These tests validate that the server correctly
# accepts/rejects client certs based on OID policy.
#
# NOTE: T10-T16 require the OID verify callback in the
# server. Until Phase 1C is implemented, the server does
# plain CA verification only, so some will SKIP.
# ═══════════════════════════════════════════

test_oid_server_side() {
    log_header "OID JSON Policy — Server-Side"

    # For now, these tests use the basic test-tls-server which does CA-only verification.
    # Once the pkcs11-proxy TLS layer is rewritten (Phase 1C), we'll point these at
    # pkcs11-daemon instead. For now, mark OID-specific tests as SKIP.

    # T10: Client cert with valid OID policy JSON
    start_server \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" "true"
    if [ $? -ne 0 ]; then
        fail "T10" "server failed to start"
    else
        expect_exit "T10" "Valid OID client cert → accepted" 0 \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-valid.crt" "${PKI_DIR}/client-valid.key" \
            "localhost"
    fi
    stop_server

    # T11-T16: These require OID verification in the server callback.
    # They will pass once the verify callback rejects certs without/bad OID.
    skip "T11" "Requires OID verify callback (Phase 1C)"
    skip "T12" "Requires OID verify callback (Phase 1C)"
    skip "T13" "Requires OID verify callback (Phase 1C)"
    skip "T14" "Requires OID verify callback (Phase 1C)"
    skip "T15" "Requires OID verify callback (Phase 1C)"
    skip "T16" "Requires OID verify callback (Phase 1C)"
}

# ═══════════════════════════════════════════
# OID POLICY — CLIENT-SIDE (T20-T23)
# ═══════════════════════════════════════════

test_oid_client_side() {
    log_header "OID JSON Policy — Client-Side"

    # Similarly, client-side OID verification requires the updated client TLS code.
    skip "T20" "Requires OID verify callback (Phase 1C)"
    skip "T21" "Requires OID verify callback (Phase 1C)"
    skip "T22" "Requires OID verify callback (Phase 1C)"
    skip "T23" "Requires OID verify callback (Phase 1C)"
}

# ═══════════════════════════════════════════
# HOSTNAME VERIFICATION (T30-T31)
# ═══════════════════════════════════════════

test_hostname() {
    log_header "Hostname Verification"

    # T30: Correct server name
    start_server \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" "true"
    if [ $? -ne 0 ]; then
        fail "T30" "server failed to start"
    else
        expect_exit "T30" "Correct hostname → accepted" 0 \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-valid.crt" "${PKI_DIR}/client-valid.key" \
            "localhost"
    fi
    stop_server

    # T31: Wrong server name → rejected
    start_server \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" "true"
    if [ $? -ne 0 ]; then
        fail "T31" "server failed to start"
    else
        expect_exit "T31" "Wrong hostname → rejected" 2 \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-valid.crt" "${PKI_DIR}/client-valid.key" \
            "wrong.host.example.com"
    fi
    stop_server
}

# ═══════════════════════════════════════════
# DATA INTEGRITY (T40-T41)
# ═══════════════════════════════════════════

test_data_integrity() {
    log_header "Data Integrity over mTLS"

    # T40: Full round-trip with PKCS#11 via proxy
    # Requires pkcs11-daemon + SoftHSM — skip until Phase 1 is complete.
    skip "T40" "Requires pkcs11-daemon with new TLS (Phase 1)"

    # T41: Multiple sequential connections
    skip "T41" "Requires pkcs11-daemon with new TLS (Phase 1)"
}

# ═══════════════════════════════════════════
# SECCOMP (T50-T51)
# ═══════════════════════════════════════════

test_seccomp() {
    log_header "Seccomp"

    skip "T50" "Requires pkcs11-daemon with SECCOMP + new TLS (Phase 1E)"
    skip "T51" "Requires pkcs11-daemon with SECCOMP + new TLS (Phase 1E)"
}

# ═══════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   pkcs11-proxy TLS Test Suite            ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"

# Verify test binaries exist
if [ ! -x "${TEST_SERVER}" ] || [ ! -x "${TEST_CLIENT}" ]; then
    echo "ERROR: test-tls-server or test-tls-client not found. Build first."
    exit 1
fi

# Verify PKI exists
if [ ! -f "${PKI_DIR}/root-ca.crt" ]; then
    echo "ERROR: test PKI not found. Run generate-test-pki.sh first."
    exit 1
fi

test_tls_basic
test_oid_server_side
test_oid_client_side
test_hostname
test_data_integrity
test_seccomp

# ─── Summary ───
echo ""
echo -e "${CYAN}━━━ Summary ━━━${NC}"
echo -e "  Total: ${TOTAL_COUNT}"
echo -e "  ${GREEN}Pass:  ${PASS_COUNT}${NC}"
echo -e "  ${RED}Fail:  ${FAIL_COUNT}${NC}"
echo -e "  ${YELLOW}Skip:  ${SKIP_COUNT}${NC}"
echo ""

if [ "${FAIL_COUNT}" -gt 0 ]; then
    echo -e "${RED}FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}ALL PASSED${NC} (${SKIP_COUNT} skipped, pending implementation)"
    exit 0
fi
