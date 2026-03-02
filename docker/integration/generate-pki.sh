#!/bin/bash
set -euo pipefail

# Generate ephemeral PKI for Docker Compose integration test.
# Writes certs to /pki (shared volume).
# Reuses certificate templates from the test suite.

# Prevent step CLI from trying to access /dev/tty for config
export STEPPATH="/tmp/step"
mkdir -p "${STEPPATH}"

PKI_DIR="/pki"
BUILD_DIR="/build/pkcs11-proxy"
TPL_DIR="${BUILD_DIR}/tests/templates"

echo "=== Integration test PKI generation ==="

SERVER_POLICY='{"v":1,"service":"pkcs11-proxy","namespace":"sigstore","keyset":"cosign-v1"}'
CLIENT_POLICY_VALID='{"v":1,"iss":"https://token.actions.githubusercontent.com","repo":"org/repo","workflow":"build-and-sign.yml","ref":"refs/heads/main","aud":"pkcs11-proxy","keyset":"cosign-v1"}'
CLIENT_POLICY_WRONG='{"v":1,"iss":"https://token.actions.githubusercontent.com","repo":"evil/repo","workflow":"build-and-sign.yml","ref":"refs/heads/main","aud":"pkcs11-proxy","keyset":"cosign-v1"}'

# Helper: create a leaf cert with OID policy using the test suite's templates.
# Usage: gen_leaf <name> <cn> <template> <ca_cert> <ca_key> [policy_json] [extra_args...]
gen_leaf() {
    local name="$1"
    local cn="$2"
    local template="$3"
    local ca_cert="$4"
    local ca_key="$5"
    local policy_json="${6:-}"
    shift 6 2>/dev/null || shift 5

    echo "  Generating: ${name}"

    local set_file_args=()
    if [ -n "${policy_json}" ]; then
        local vars_file="/tmp/.vars-${name}.json"
        printf '{"oidPolicy": %s}\n' "$(echo "${policy_json}" | jq -Rs '.')" > "${vars_file}"
        set_file_args=(--set-file "${vars_file}")
    fi

    step certificate create "${cn}" \
        "${PKI_DIR}/${name}.crt" "${PKI_DIR}/${name}.key" \
        --template "${template}" \
        --ca "${ca_cert}" --ca-key "${ca_key}" \
        --kty EC --curve P-256 \
        --not-after 24h \
        --no-password --insecure \
        "${set_file_args[@]}" \
        "$@"
}

# ─── Root CA ───
step certificate create "Integration Test CA" \
    "${PKI_DIR}/ca.crt" "${PKI_DIR}/ca.key" \
    --profile root-ca \
    --kty EC --curve P-256 \
    --not-after 24h \
    --no-password --insecure

# ─── Server cert with OID policy ───
gen_leaf "server" "pkcs11-proxy" "${TPL_DIR}/server-valid.tpl" \
    "${PKI_DIR}/ca.crt" "${PKI_DIR}/ca.key" \
    "${SERVER_POLICY}" \
    --san server --san localhost --san 127.0.0.1

# ─── Client cert with valid OID policy ───
gen_leaf "client-valid" "ci-runner" "${TPL_DIR}/client-valid.tpl" \
    "${PKI_DIR}/ca.crt" "${PKI_DIR}/ca.key" \
    "${CLIENT_POLICY_VALID}"

# ─── Client cert with wrong repo (should be rejected) ───
gen_leaf "client-wrong" "evil-runner" "${TPL_DIR}/client-valid.tpl" \
    "${PKI_DIR}/ca.crt" "${PKI_DIR}/ca.key" \
    "${CLIENT_POLICY_WRONG}"

# ─── Client cert with no OID (should be rejected) ───
gen_leaf "client-no-oid" "plain-runner" "${TPL_DIR}/client-no-oid.tpl" \
    "${PKI_DIR}/ca.crt" "${PKI_DIR}/ca.key"

# Make readable by all containers
chmod 644 "${PKI_DIR}"/*.crt "${PKI_DIR}"/*.key

echo ""
echo "=== PKI files generated ==="
ls -la "${PKI_DIR}"/
echo "=== DONE ==="
