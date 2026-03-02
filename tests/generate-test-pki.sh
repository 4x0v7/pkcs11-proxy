#!/bin/bash
set -euo pipefail

# Generate test PKI for pkcs11-proxy TLS tests.
# Uses smallstep `step` CLI with templates for custom OID extensions.
#
# OID 1.7.4.4.6.3.3.4.4.8 = SIGNEDGIT (private, unregistered)
#
# Output directory: tests/pki/
# Requires: step CLI in PATH

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKI_DIR="${SCRIPT_DIR}/pki"
TPL_DIR="${SCRIPT_DIR}/templates"
OID="1.7.4.4.6.3.3.4.4.8"

command -v step >/dev/null 2>&1 || { echo "ERROR: step CLI not found in PATH"; exit 1; }

rm -rf "${PKI_DIR}"
mkdir -p "${PKI_DIR}"

# ─── Policy JSON payloads ───

SERVER_POLICY_VALID='{"v":1,"service":"pkcs11-proxy","namespace":"sigstore","keyset":"cosign-v1"}'
SERVER_POLICY_WRONG_SVC='{"v":1,"service":"wrong-service","namespace":"sigstore","keyset":"cosign-v1"}'
SERVER_POLICY_WRONG_NS='{"v":1,"service":"pkcs11-proxy","namespace":"wrong-ns","keyset":"cosign-v1"}'

CLIENT_POLICY_VALID='{"v":1,"iss":"https://token.actions.githubusercontent.com","repo":"org/repo","workflow":"build-and-sign.yml","ref":"refs/heads/main","aud":"pkcs11-proxy","keyset":"cosign-v1"}'
CLIENT_POLICY_WRONG_REPO='{"v":1,"iss":"https://token.actions.githubusercontent.com","repo":"evil/repo","workflow":"build-and-sign.yml","ref":"refs/heads/main","aud":"pkcs11-proxy","keyset":"cosign-v1"}'
CLIENT_POLICY_WRONG_KEYSET='{"v":1,"iss":"https://token.actions.githubusercontent.com","repo":"org/repo","workflow":"build-and-sign.yml","ref":"refs/heads/main","aud":"pkcs11-proxy","keyset":"wrong-keyset"}'
CLIENT_POLICY_EXTRA_FIELDS='{"v":1,"iss":"https://token.actions.githubusercontent.com","repo":"org/repo","workflow":"build-and-sign.yml","ref":"refs/heads/main","aud":"pkcs11-proxy","keyset":"cosign-v1","sneaky":"field"}'
CLIENT_POLICY_INVALID_JSON='this is not json {{'

# Generate oversized payload (>16KB)
CLIENT_POLICY_OVERSIZED='{"v":1,"iss":"https://token.actions.githubusercontent.com","repo":"org/repo","padding":"'
CLIENT_POLICY_OVERSIZED+=$(printf '%0.sA' $(seq 1 17000))
CLIENT_POLICY_OVERSIZED+='"}'

# ─── 1. Root CA ───

echo "=== Generating Root CA ==="
step certificate create "Test Root CA" \
    "${PKI_DIR}/root-ca.crt" "${PKI_DIR}/root-ca.key" \
    --profile root-ca \
    --kty EC --curve P-256 \
    --not-after 87600h \
    --no-password --insecure

# ─── 2. Wrong CA (separate root for negative tests) ───

echo "=== Generating Wrong CA ==="
step certificate create "Wrong Root CA" \
    "${PKI_DIR}/wrong-ca.crt" "${PKI_DIR}/wrong-ca.key" \
    --profile root-ca \
    --kty EC --curve P-256 \
    --not-after 87600h \
    --no-password --insecure

# ─── Helper: create a leaf cert signed by a CA with a template ───
# Usage: gen_leaf <name> <cn> <template> <ca_cert> <ca_key> [policy_json] [extra_args...]
# If policy_json is non-empty, it's written as a string value to a temp JSON file
# and passed via --set-file to avoid step's --set parsing JSON objects into Go maps.

gen_leaf() {
    local name="$1"
    local cn="$2"
    local template="$3"
    local ca_cert="$4"
    local ca_key="$5"
    local policy_json="${6:-}"
    shift 6 2>/dev/null || shift 5
    # Remaining args are --san flags

    echo "  Generating: ${name}"

    local set_file_args=()
    if [ -n "${policy_json}" ]; then
        local vars_file="${PKI_DIR}/.vars-${name}.json"
        # Write a JSON file where oidPolicy is a string (not parsed as object)
        printf '{"oidPolicy": %s}\n' "$(echo "${policy_json}" | jq -Rs '.')" > "${vars_file}"
        set_file_args=(--set-file "${vars_file}")
    fi

    step certificate create "${cn}" \
        "${PKI_DIR}/${name}.crt" "${PKI_DIR}/${name}.key" \
        --template "${template}" \
        --ca "${ca_cert}" --ca-key "${ca_key}" \
        --kty EC --curve P-256 \
        --not-after 8760h \
        --no-password --insecure \
        "${set_file_args[@]}" \
        "$@"
}

# ─── 3. Server certs ───

echo "=== Generating Server Certs ==="

gen_leaf "server-valid" "pkcs11-proxy" "${TPL_DIR}/server-valid.tpl" \
    "${PKI_DIR}/root-ca.crt" "${PKI_DIR}/root-ca.key" \
    "${SERVER_POLICY_VALID}" \
    --san localhost --san 127.0.0.1

gen_leaf "server-no-oid" "pkcs11-proxy" "${TPL_DIR}/server-no-oid.tpl" \
    "${PKI_DIR}/root-ca.crt" "${PKI_DIR}/root-ca.key" \
    "" \
    --san localhost --san 127.0.0.1

gen_leaf "server-wrong-svc" "pkcs11-proxy" "${TPL_DIR}/server-valid.tpl" \
    "${PKI_DIR}/root-ca.crt" "${PKI_DIR}/root-ca.key" \
    "${SERVER_POLICY_WRONG_SVC}" \
    --san localhost --san 127.0.0.1

gen_leaf "server-wrong-ns" "pkcs11-proxy" "${TPL_DIR}/server-valid.tpl" \
    "${PKI_DIR}/root-ca.crt" "${PKI_DIR}/root-ca.key" \
    "${SERVER_POLICY_WRONG_NS}" \
    --san localhost --san 127.0.0.1

# ─── 4. Client certs ───

echo "=== Generating Client Certs ==="

gen_leaf "client-valid" "ci-runner" "${TPL_DIR}/client-valid.tpl" \
    "${PKI_DIR}/root-ca.crt" "${PKI_DIR}/root-ca.key" \
    "${CLIENT_POLICY_VALID}"

gen_leaf "client-no-oid" "ci-runner" "${TPL_DIR}/client-no-oid.tpl" \
    "${PKI_DIR}/root-ca.crt" "${PKI_DIR}/root-ca.key"

gen_leaf "client-wrong-repo" "ci-runner" "${TPL_DIR}/client-valid.tpl" \
    "${PKI_DIR}/root-ca.crt" "${PKI_DIR}/root-ca.key" \
    "${CLIENT_POLICY_WRONG_REPO}"

gen_leaf "client-wrong-keyset" "ci-runner" "${TPL_DIR}/client-valid.tpl" \
    "${PKI_DIR}/root-ca.crt" "${PKI_DIR}/root-ca.key" \
    "${CLIENT_POLICY_WRONG_KEYSET}"

gen_leaf "client-invalid-json" "ci-runner" "${TPL_DIR}/client-valid.tpl" \
    "${PKI_DIR}/root-ca.crt" "${PKI_DIR}/root-ca.key" \
    "${CLIENT_POLICY_INVALID_JSON}"

gen_leaf "client-oversized" "ci-runner" "${TPL_DIR}/client-valid.tpl" \
    "${PKI_DIR}/root-ca.crt" "${PKI_DIR}/root-ca.key" \
    "${CLIENT_POLICY_OVERSIZED}"

gen_leaf "client-extra-fields" "ci-runner" "${TPL_DIR}/client-valid.tpl" \
    "${PKI_DIR}/root-ca.crt" "${PKI_DIR}/root-ca.key" \
    "${CLIENT_POLICY_EXTRA_FIELDS}"

gen_leaf "client-wrong-ca" "ci-runner" "${TPL_DIR}/client-valid.tpl" \
    "${PKI_DIR}/wrong-ca.crt" "${PKI_DIR}/wrong-ca.key" \
    "${CLIENT_POLICY_VALID}"

# ─── 5. Summary ───

echo ""
echo "=== Test PKI generated in ${PKI_DIR} ==="
echo "Files:"
ls -1 "${PKI_DIR}"/*.crt "${PKI_DIR}"/*.key 2>/dev/null | while read -r f; do echo "  ${f}"; done

echo ""
echo "Verify server-valid cert has OID ${OID}:"
step certificate inspect "${PKI_DIR}/server-valid.crt" --format json \
    | jq -r '.extensions[] | select(.id == "'"${OID}"'") | .value' 2>/dev/null \
    && echo "  OID found." \
    || echo "  OID not found (will check with openssl)."

echo ""
echo "Done."
