#!/bin/bash
set -uo pipefail

# pkcs11-proxy TLS test suite
# Run inside the test Docker container after build + PKI generation.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKI_DIR="${SCRIPT_DIR}/pki"
BUILD_DIR="${SCRIPT_DIR}/.."

TEST_SERVER="${SCRIPT_DIR}/test-tls-server"
TEST_CLIENT="${SCRIPT_DIR}/test-tls-client"
TEST_PKCS11_TOOL="${SCRIPT_DIR}/test-pkcs11-tool"
PKCS11_DAEMON="${BUILD_DIR}/pkcs11-daemon"
PKCS11_PROXY_LIB="${BUILD_DIR}/libpkcs11-proxy.so"
SOFTHSM_MODULE="/usr/lib/softhsm/libsofthsm2.so"

DAEMON_PID=""

# Find a free TCP port — pure shell, no perl/python needed.
find_free_port() {
    local port
    while true; do
        port=$(( (RANDOM % 16384) + 49152 ))
        # Check /proc/net/tcp for ports in use (hex-encoded, field 2, after ':')
        if ! awk '{print $2}' /proc/net/tcp 2>/dev/null | \
             grep -qi ":$(printf '%04X' "$port")$"; then
            echo "$port"
            return
        fi
    done
}

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
# Extra env vars for OID checks: set TEST_TLS_VERIFY_OID, TEST_TLS_EXPECT_REPO,
# TEST_TLS_EXPECT_KEYSET etc. in the caller before invoking start_server.
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
    TEST_TLS_VERIFY_OID="${TEST_TLS_VERIFY_OID:-}" \
    TEST_TLS_EXPECT_SERVICE="${TEST_TLS_EXPECT_SERVICE:-}" \
    TEST_TLS_EXPECT_NAMESPACE="${TEST_TLS_EXPECT_NAMESPACE:-}" \
    TEST_TLS_EXPECT_KEYSET="${TEST_TLS_EXPECT_KEYSET:-}" \
    TEST_TLS_EXPECT_REPO="${TEST_TLS_EXPECT_REPO:-}" \
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
# Extra env vars for OID checks: set TEST_TLS_VERIFY_OID, TEST_TLS_EXPECT_SERVICE,
# TEST_TLS_EXPECT_NAMESPACE, TEST_TLS_EXPECT_KEYSET in the caller.
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

    # Forward OID verification env vars if set
    if [ -n "${TEST_TLS_VERIFY_OID:-}" ]; then
        env_args+=(TEST_TLS_VERIFY_OID="${TEST_TLS_VERIFY_OID}")
    fi
    if [ -n "${TEST_TLS_EXPECT_SERVICE:-}" ]; then
        env_args+=(TEST_TLS_EXPECT_SERVICE="${TEST_TLS_EXPECT_SERVICE}")
    fi
    if [ -n "${TEST_TLS_EXPECT_NAMESPACE:-}" ]; then
        env_args+=(TEST_TLS_EXPECT_NAMESPACE="${TEST_TLS_EXPECT_NAMESPACE}")
    fi
    if [ -n "${TEST_TLS_EXPECT_KEYSET:-}" ]; then
        env_args+=(TEST_TLS_EXPECT_KEYSET="${TEST_TLS_EXPECT_KEYSET}")
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

clear_oid_env() {
    unset TEST_TLS_VERIFY_OID TEST_TLS_EXPECT_SERVICE TEST_TLS_EXPECT_NAMESPACE
    unset TEST_TLS_EXPECT_KEYSET TEST_TLS_EXPECT_REPO
}

# Helper: start server with OID policy enforcement on client certs.
# The server verifies the client cert's OID has the expected client-policy fields.
# Usage: start_server_oid_client <server_cert> <server_key> <ca> <expect_repo> <expect_keyset>
start_server_oid_client() {
    export TEST_TLS_VERIFY_OID="true"
    export TEST_TLS_EXPECT_REPO="$4"
    export TEST_TLS_EXPECT_KEYSET="$5"
    export TEST_TLS_EXPECT_SERVICE=""
    export TEST_TLS_EXPECT_NAMESPACE=""
    start_server "$1" "$2" "$3" "true"
    local rc=$?
    clear_oid_env
    return $rc
}

# Helper: expect server exit code after it processes one client.
# Because the server verifies OID after handshake, a policy failure shows as server exit=4.
# The client may still succeed the TLS handshake but get a connection-reset / error on echo.
# Usage: expect_server_oid <test_id> <desc> <expected_server_exit> <ca> <client_cert> <client_key>
expect_server_oid() {
    local test_id="$1"
    local desc="$2"
    local expected_server_exit="$3"
    local ca="$4"
    local client_cert="$5"
    local client_key="$6"

    # Run client — it may succeed or fail depending on whether server closes connection
    run_client "${ca}" "${client_cert}" "${client_key}" "localhost" "1.3" "PING" || true

    # Wait for server to finish
    wait "${SERVER_PID}" 2>/dev/null
    local server_exit=$?

    local ok=0
    for e in $(echo "${expected_server_exit}" | tr '|' ' '); do
        if [ "${server_exit}" -eq "${e}" ]; then
            ok=1
            break
        fi
    done

    if [ "${ok}" -eq 1 ]; then
        pass "${test_id}: ${desc}"
    else
        fail "${test_id}: ${desc}" "expected server exit=${expected_server_exit}, got=${server_exit}"
    fi
    SERVER_PID=""
    SERVER_PORT=""
}

test_oid_server_side() {
    log_header "OID JSON Policy — Server-Side"

    # T10: Client cert with valid OID policy JSON (no OID enforcement — basic CA check)
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

    # T11: Valid client OID + OID enforcement → server accepts (exit 0)
    start_server_oid_client \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" "org/repo" "cosign-v1"
    if [ $? -ne 0 ]; then
        fail "T11" "server failed to start"
    else
        expect_server_oid "T11" "Valid client OID → server accepts" 0 \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-valid.crt" "${PKI_DIR}/client-valid.key"
    fi

    # T12: Client cert with no OID extension → server rejects (exit 4)
    start_server_oid_client \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" "org/repo" "cosign-v1"
    if [ $? -ne 0 ]; then
        fail "T12" "server failed to start"
    else
        expect_server_oid "T12" "No OID client cert → server rejects" 4 \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-no-oid.crt" "${PKI_DIR}/client-no-oid.key"
    fi

    # T13: Client cert with wrong repo → server rejects (exit 4)
    start_server_oid_client \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" "org/repo" "cosign-v1"
    if [ $? -ne 0 ]; then
        fail "T13" "server failed to start"
    else
        expect_server_oid "T13" "Wrong repo in client OID → server rejects" 4 \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-wrong-repo.crt" "${PKI_DIR}/client-wrong-repo.key"
    fi

    # T14: Client cert with wrong keyset → server rejects (exit 4)
    start_server_oid_client \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" "org/repo" "cosign-v1"
    if [ $? -ne 0 ]; then
        fail "T14" "server failed to start"
    else
        expect_server_oid "T14" "Wrong keyset in client OID → server rejects" 4 \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-wrong-keyset.crt" "${PKI_DIR}/client-wrong-keyset.key"
    fi

    # T15: Client cert with invalid JSON in OID → server rejects (exit 4)
    start_server_oid_client \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" "org/repo" "cosign-v1"
    if [ $? -ne 0 ]; then
        fail "T15" "server failed to start"
    else
        expect_server_oid "T15" "Invalid JSON in client OID → server rejects" 4 \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-invalid-json.crt" "${PKI_DIR}/client-invalid-json.key"
    fi

    # T16: Client cert with extra fields in OID → server rejects (exit 4)
    start_server_oid_client \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" "org/repo" "cosign-v1"
    if [ $? -ne 0 ]; then
        fail "T16" "server failed to start"
    else
        expect_server_oid "T16" "Extra fields in client OID → server rejects" 4 \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-extra-fields.crt" "${PKI_DIR}/client-extra-fields.key"
    fi
}

# ═══════════════════════════════════════════
# OID POLICY — CLIENT-SIDE (T20-T23)
# ═══════════════════════════════════════════

test_oid_client_side() {
    log_header "OID JSON Policy — Client-Side"

    # T20: Client verifies server cert with valid OID → accepted
    start_server \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" "true"
    if [ $? -ne 0 ]; then
        fail "T20" "server failed to start"
    else
        export TEST_TLS_VERIFY_OID="true"
        export TEST_TLS_EXPECT_SERVICE="pkcs11-proxy"
        export TEST_TLS_EXPECT_NAMESPACE="sigstore"
        export TEST_TLS_EXPECT_KEYSET="cosign-v1"
        expect_exit "T20" "Client verifies valid server OID → accepted" 0 \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-valid.crt" "${PKI_DIR}/client-valid.key" \
            "localhost"
        clear_oid_env
    fi
    stop_server

    # T21: Client verifies server cert with no OID → rejected (exit 4)
    start_server \
        "${PKI_DIR}/server-no-oid.crt" "${PKI_DIR}/server-no-oid.key" \
        "${PKI_DIR}/root-ca.crt" "true"
    if [ $? -ne 0 ]; then
        fail "T21" "server failed to start"
    else
        export TEST_TLS_VERIFY_OID="true"
        export TEST_TLS_EXPECT_SERVICE="pkcs11-proxy"
        export TEST_TLS_EXPECT_NAMESPACE="sigstore"
        export TEST_TLS_EXPECT_KEYSET="cosign-v1"
        expect_exit "T21" "Client verifies server with no OID → rejected" 4 \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-valid.crt" "${PKI_DIR}/client-valid.key" \
            "localhost"
        clear_oid_env
    fi
    stop_server

    # T22: Client verifies server cert with wrong service → rejected (exit 4)
    start_server \
        "${PKI_DIR}/server-wrong-svc.crt" "${PKI_DIR}/server-wrong-svc.key" \
        "${PKI_DIR}/root-ca.crt" "true"
    if [ $? -ne 0 ]; then
        fail "T22" "server failed to start"
    else
        export TEST_TLS_VERIFY_OID="true"
        export TEST_TLS_EXPECT_SERVICE="pkcs11-proxy"
        export TEST_TLS_EXPECT_NAMESPACE="sigstore"
        export TEST_TLS_EXPECT_KEYSET="cosign-v1"
        expect_exit "T22" "Client verifies server with wrong service → rejected" 4 \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-valid.crt" "${PKI_DIR}/client-valid.key" \
            "localhost"
        clear_oid_env
    fi
    stop_server

    # T23: Client verifies server cert with wrong namespace → rejected (exit 4)
    start_server \
        "${PKI_DIR}/server-wrong-ns.crt" "${PKI_DIR}/server-wrong-ns.key" \
        "${PKI_DIR}/root-ca.crt" "true"
    if [ $? -ne 0 ]; then
        fail "T23" "server failed to start"
    else
        export TEST_TLS_VERIFY_OID="true"
        export TEST_TLS_EXPECT_SERVICE="pkcs11-proxy"
        export TEST_TLS_EXPECT_NAMESPACE="sigstore"
        export TEST_TLS_EXPECT_KEYSET="cosign-v1"
        expect_exit "T23" "Client verifies server with wrong namespace → rejected" 4 \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-valid.crt" "${PKI_DIR}/client-valid.key" \
            "localhost"
        clear_oid_env
    fi
    stop_server
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

# Start pkcs11-daemon with TLS, listening on a random port.
# Usage: start_daemon <server_cert> <server_key> <ca_cert>
# Sets: DAEMON_PID, DAEMON_PORT
start_daemon() {
    local cert="$1"
    local key="$2"
    local ca="$3"

    # Find a free port
    local port
    port=$(find_free_port)

    PKCS11_PROXY_TLS_CERT="${cert}" \
    PKCS11_PROXY_TLS_KEY="${key}" \
    PKCS11_PROXY_TLS_CA="${ca}" \
    PKCS11_PROXY_TLS_REQUIRE_MTLS="true" \
    "${PKCS11_DAEMON}" "${SOFTHSM_MODULE}" "tls://0.0.0.0:${port}" &
    DAEMON_PID=$!
    DAEMON_PORT="${port}"

    # Give daemon time to start listening
    sleep 0.5

    if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
        DAEMON_PID=""
        DAEMON_PORT=""
        return 1
    fi
    return 0
}

stop_daemon() {
    if [ -n "${DAEMON_PID:-}" ] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
        kill "${DAEMON_PID}" 2>/dev/null || true
        wait "${DAEMON_PID}" 2>/dev/null || true
    fi
    DAEMON_PID=""
    DAEMON_PORT=""
}

# Run pkcs11-tool through proxy, connecting to daemon via TLS.
# Usage: run_pkcs11_tool <ca_cert> <client_cert> <client_key> [server_name]
# Returns: exit code of test-pkcs11-tool. Stdout captured in PKCS11_OUTPUT.
run_pkcs11_tool() {
    local ca="$1"
    local cert="$2"
    local key="$3"
    local server_name="${4:-localhost}"

    PKCS11_OUTPUT=$(
        PKCS11_PROXY_SOCKET="tls://127.0.0.1:${DAEMON_PORT}" \
        PKCS11_PROXY_TLS_CERT="${cert}" \
        PKCS11_PROXY_TLS_KEY="${key}" \
        PKCS11_PROXY_TLS_CA="${ca}" \
        PKCS11_PROXY_TLS_SERVER_NAME="${server_name}" \
        timeout 5 "${TEST_PKCS11_TOOL}" "${PKCS11_PROXY_LIB}" 2>/dev/null
    )
    return $?
}

test_data_integrity() {
    log_header "Data Integrity over mTLS"

    # T40: Full round-trip with PKCS#11 via proxy over TLS
    start_daemon \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt"
    if [ $? -ne 0 ]; then
        fail "T40" "daemon failed to start"
    else
        run_pkcs11_tool \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-valid.crt" "${PKI_DIR}/client-valid.key"
        local rc=$?
        if [ "${rc}" -eq 0 ] && echo "${PKCS11_OUTPUT}" | grep -q "CRYPTO=pass"; then
            pass "T40: PKCS#11 crypto round-trip over mTLS"
        else
            fail "T40: PKCS#11 crypto round-trip over mTLS" "exit=${rc} output=${PKCS11_OUTPUT}"
        fi
    fi
    stop_daemon

    # T41: Multiple sequential connections
    start_daemon \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt"
    if [ $? -ne 0 ]; then
        fail "T41" "daemon failed to start"
    else
        local all_ok=1
        for i in 1 2 3; do
            run_pkcs11_tool \
                "${PKI_DIR}/root-ca.crt" \
                "${PKI_DIR}/client-valid.crt" "${PKI_DIR}/client-valid.key"
            if [ $? -ne 0 ]; then
                all_ok=0
                break
            fi
        done
        if [ "${all_ok}" -eq 1 ]; then
            pass "T41: Multiple sequential PKCS#11 connections"
        else
            fail "T41: Multiple sequential PKCS#11 connections" "failed on iteration ${i}"
        fi
    fi
    stop_daemon
}

# ═══════════════════════════════════════════
# SECCOMP (T50-T51)
# ═══════════════════════════════════════════

PKCS11_DAEMON_SECCOMP="${BUILD_DIR}/pkcs11-daemon-seccomp"

# Start seccomp-enabled daemon with TLS.
# Usage: start_daemon_seccomp <server_cert> <server_key> <ca_cert>
start_daemon_seccomp() {
    local cert="$1"
    local key="$2"
    local ca="$3"

    local port
    port=$(find_free_port)

    PKCS11_PROXY_TLS_CERT="${cert}" \
    PKCS11_PROXY_TLS_KEY="${key}" \
    PKCS11_PROXY_TLS_CA="${ca}" \
    PKCS11_PROXY_TLS_REQUIRE_MTLS="true" \
    "${PKCS11_DAEMON_SECCOMP}" "${SOFTHSM_MODULE}" "tls://0.0.0.0:${port}" &
    DAEMON_PID=$!
    DAEMON_PORT="${port}"

    sleep 0.5

    if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
        DAEMON_PID=""
        DAEMON_PORT=""
        return 1
    fi
    return 0
}

test_seccomp() {
    log_header "Seccomp"

    if [ ! -x "${PKCS11_DAEMON_SECCOMP}" ]; then
        skip "T50" "pkcs11-daemon-seccomp not built"
        skip "T51" "pkcs11-daemon-seccomp not built"
        return
    fi

    # T50: PKCS#11 round-trip works with SECCOMP enabled
    start_daemon_seccomp \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt"
    if [ $? -ne 0 ]; then
        fail "T50" "seccomp daemon failed to start"
    else
        run_pkcs11_tool \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-valid.crt" "${PKI_DIR}/client-valid.key"
        local rc=$?
        if [ "${rc}" -eq 0 ] && echo "${PKCS11_OUTPUT}" | grep -q "CRYPTO=pass"; then
            pass "T50: PKCS#11 crypto round-trip with SECCOMP"
        else
            fail "T50: PKCS#11 crypto round-trip with SECCOMP" "exit=${rc} output=${PKCS11_OUTPUT}"
        fi
    fi
    stop_daemon

    # T51: Multiple connections with SECCOMP
    start_daemon_seccomp \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt"
    if [ $? -ne 0 ]; then
        fail "T51" "seccomp daemon failed to start"
    else
        local all_ok=1
        for i in 1 2 3; do
            run_pkcs11_tool \
                "${PKI_DIR}/root-ca.crt" \
                "${PKI_DIR}/client-valid.crt" "${PKI_DIR}/client-valid.key"
            if [ $? -ne 0 ]; then
                all_ok=0
                break
            fi
        done
        if [ "${all_ok}" -eq 1 ]; then
            pass "T51: Multiple PKCS#11 connections with SECCOMP"
        else
            fail "T51: Multiple PKCS#11 connections with SECCOMP" "failed on iteration ${i}"
        fi
    fi
    stop_daemon
}

# ═══════════════════════════════════════════
# OID POLICY via DAEMON (T60-T63)
# ═══════════════════════════════════════════

# Start daemon with OID policy enforcement enabled.
# Usage: start_daemon_with_policy <server_cert> <server_key> <ca_cert> <policy_repo> <policy_keyset>
start_daemon_with_policy() {
    local cert="$1"
    local key="$2"
    local ca="$3"
    local policy_repo="$4"
    local policy_keyset="$5"

    local port
    port=$(find_free_port)

    PKCS11_PROXY_TLS_CERT="${cert}" \
    PKCS11_PROXY_TLS_KEY="${key}" \
    PKCS11_PROXY_TLS_CA="${ca}" \
    PKCS11_PROXY_TLS_REQUIRE_MTLS="true" \
    PKCS11_PROXY_TLS_POLICY_REPO="${policy_repo}" \
    PKCS11_PROXY_TLS_POLICY_KEYSET="${policy_keyset}" \
    "${PKCS11_DAEMON}" "${SOFTHSM_MODULE}" "tls://0.0.0.0:${port}" &
    DAEMON_PID=$!
    DAEMON_PORT="${port}"

    sleep 0.5

    if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
        DAEMON_PID=""
        DAEMON_PORT=""
        return 1
    fi
    return 0
}

test_oid_policy_daemon() {
    log_header "OID Policy via Daemon"

    # T60: Valid OID client cert → daemon accepts PKCS#11 operation
    start_daemon_with_policy \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" \
        "org/repo" "cosign-v1"
    if [ $? -ne 0 ]; then
        fail "T60" "daemon failed to start"
    else
        run_pkcs11_tool \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-valid.crt" "${PKI_DIR}/client-valid.key"
        local rc=$?
        if [ "${rc}" -eq 0 ] && echo "${PKCS11_OUTPUT}" | grep -q "CRYPTO=pass"; then
            pass "T60: Valid OID client → daemon accepts (crypto)"
        else
            fail "T60: Valid OID client → daemon accepts (crypto)" "exit=${rc} output=${PKCS11_OUTPUT}"
        fi
    fi
    stop_daemon

    # T61: Client cert with no OID → daemon rejects
    start_daemon_with_policy \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" \
        "org/repo" "cosign-v1"
    if [ $? -ne 0 ]; then
        fail "T61" "daemon failed to start"
    else
        run_pkcs11_tool \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-no-oid.crt" "${PKI_DIR}/client-no-oid.key"
        local rc=$?
        if [ "${rc}" -ne 0 ]; then
            pass "T61: No-OID client → daemon rejects"
        else
            fail "T61: No-OID client → daemon rejects" "expected failure but got rc=0"
        fi
    fi
    stop_daemon

    # T62: Client cert with wrong repo → daemon rejects
    start_daemon_with_policy \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" \
        "org/repo" "cosign-v1"
    if [ $? -ne 0 ]; then
        fail "T62" "daemon failed to start"
    else
        run_pkcs11_tool \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-wrong-repo.crt" "${PKI_DIR}/client-wrong-repo.key"
        local rc=$?
        if [ "${rc}" -ne 0 ]; then
            pass "T62: Wrong-repo client → daemon rejects"
        else
            fail "T62: Wrong-repo client → daemon rejects" "expected failure but got rc=0"
        fi
    fi
    stop_daemon

    # T63: Client cert with wrong keyset → daemon rejects
    start_daemon_with_policy \
        "${PKI_DIR}/server-valid.crt" "${PKI_DIR}/server-valid.key" \
        "${PKI_DIR}/root-ca.crt" \
        "org/repo" "cosign-v1"
    if [ $? -ne 0 ]; then
        fail "T63" "daemon failed to start"
    else
        run_pkcs11_tool \
            "${PKI_DIR}/root-ca.crt" \
            "${PKI_DIR}/client-wrong-keyset.crt" "${PKI_DIR}/client-wrong-keyset.key"
        local rc=$?
        if [ "${rc}" -ne 0 ]; then
            pass "T63: Wrong-keyset client → daemon rejects"
        else
            fail "T63: Wrong-keyset client → daemon rejects" "expected failure but got rc=0"
        fi
    fi
    stop_daemon
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
test_oid_policy_daemon

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
