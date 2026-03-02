#!/bin/sh
set -eu

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
    printf "  ${GREEN}PASS${NC} %s\n" "$1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    printf "  ${RED}FAIL${NC} %s\n" "$1"
    [ -n "${2:-}" ] && printf "       ${RED}→ %s${NC}\n" "$2"
}

TARGET="${SSLSCAN_TARGET:-server:2345}"

echo ""
printf "${CYAN}╔══════════════════════════════════════════════╗${NC}\n"
printf "${CYAN}║   sslscan TLS Verification                    ║${NC}\n"
printf "${CYAN}╚══════════════════════════════════════════════╝${NC}\n"
echo ""

# Run sslscan once, capture output
OUTPUT=$(sslscan --no-colour "${TARGET}" 2>&1 || true)
echo "${OUTPUT}"
echo ""

# ─── S1: TLS 1.3 is enabled ───
if echo "${OUTPUT}" | grep -qE "TLSv1\.3\s+enabled"; then
    pass "S1: TLS 1.3 enabled"
else
    fail "S1: TLS 1.3 enabled" "TLSv1.3 not found enabled"
fi

# ─── S2: Legacy protocols are disabled ───
old_ok=1
for proto in "SSLv2" "SSLv3" "TLSv1.0" "TLSv1.1" "TLSv1.2"; do
    if echo "${OUTPUT}" | grep -qE "${proto}\s+enabled"; then
        fail "S2: Legacy protocols disabled" "${proto} is enabled"
        old_ok=0
        break
    fi
done
if [ "${old_ok}" -eq 1 ]; then
    pass "S2: Legacy protocols disabled (SSLv2/v3, TLS 1.0/1.1/1.2)"
fi

# ─── S3: Expected TLS 1.3 ciphers present ───
cipher_ok=1
for cipher in "TLS_AES_256_GCM_SHA384" "TLS_CHACHA20_POLY1305_SHA256" "TLS_AES_128_GCM_SHA256"; do
    if ! echo "${OUTPUT}" | grep -q "${cipher}"; then
        fail "S3: TLS 1.3 ciphers" "missing ${cipher}"
        cipher_ok=0
        break
    fi
done
if [ "${cipher_ok}" -eq 1 ]; then
    pass "S3: TLS 1.3 ciphers (AES-256-GCM, ChaCha20, AES-128-GCM)"
fi

# ─── S4: TLS compression disabled ───
if echo "${OUTPUT}" | grep -qiE "compression.*disabled"; then
    pass "S4: TLS compression disabled"
else
    fail "S4: TLS compression disabled" "compression not confirmed disabled"
fi

# ─── S5: Not vulnerable to Heartbleed ───
if echo "${OUTPUT}" | grep -qi "not vulnerable to heartbleed"; then
    pass "S5: Not vulnerable to Heartbleed"
elif echo "${OUTPUT}" | grep -qi "heartbleed"; then
    fail "S5: Not vulnerable to Heartbleed" "possible vulnerability detected"
else
    pass "S5: Not vulnerable to Heartbleed (not applicable)"
fi

# ─── Summary ───
echo ""
printf "${CYAN}━━━ sslscan Summary ━━━${NC}\n"
printf "  Total: %d\n" "${TOTAL_COUNT}"
printf "  ${GREEN}Pass:  %d${NC}\n" "${PASS_COUNT}"
printf "  ${RED}Fail:  %d${NC}\n" "${FAIL_COUNT}"
echo ""

if [ "${FAIL_COUNT}" -gt 0 ]; then
    printf "${RED}SSLSCAN VERIFICATION FAILED${NC}\n"
    exit 1
else
    printf "${GREEN}ALL SSLSCAN CHECKS PASSED${NC}\n"
    exit 0
fi
