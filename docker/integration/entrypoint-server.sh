#!/bin/bash
set -euo pipefail

# Wait for PKI to be generated
echo "server: waiting for PKI..."
timeout 30 bash -c 'until [ -f /pki/ca.crt ] && [ -f /pki/server.crt ]; do sleep 0.5; done'
echo "server: PKI ready"

# Initialize SoftHSM token — PINs read from files, never on CLI
mkdir -p /var/lib/softhsm/tokens
softhsm2-util --init-token --slot 0 --label cosign \
    --pin "$(cat /etc/softhsm/pin)" --so-pin "$(cat /etc/softhsm/so-pin)" 2>/dev/null || true

echo "server: starting daemon on tls://0.0.0.0:2345"

exec /build/pkcs11-proxy/pkcs11-daemon \
    /usr/lib/softhsm/libsofthsm2.so \
    "tls://0.0.0.0:2345"
