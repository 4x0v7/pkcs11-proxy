# pkcs11-proxy

A network proxy for PKCS#11 cryptographic tokens. Tunnels PKCS#11 operations over the network with **TLS 1.3 mutual authentication**, **OID-based JSON policy verification**, and **seccomp syscall filtering**.

This allows cryptographic keys (e.g. code-signing keys in a HSM) to be accessed remotely by CI/CD runners through a secure, policy-enforced channel.

## Architecture

```
┌──────────────────┐         TLS 1.3 mTLS          ┌───────────────────────┐
│  Client          │ ◄──────────────────────────►  │  Server (Daemon)      │
│                  │                               │                       │
│  Application     │                               │  pkcs11-daemon        │
│    ↓             │                               │    ↓                  │
│  libpkcs11-proxy │                               │  gck-rpc-dispatch     │
│  (PKCS#11 shim)  │                               │    ↓                  │
│                  │                               │  SoftHSM / HSM module │
└──────────────────┘                               └───────────────────────┘
```

- **`pkcs11-daemon`** — Loads a real PKCS#11 module (e.g. SoftHSM, CloudHSM) and listens on a TCP/TLS socket.
- **`libpkcs11-proxy.so`** — A PKCS#11 shared library that forwards all calls to the remote daemon over the network.

## Features

- **TLS 1.3 only** — No fallback to TLS 1.2 or earlier. Ciphersuites: `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256`.
- **Mutual TLS (mTLS)** — Both client and server present certificates. Server requires client certs by default.
- **OID JSON policy verification** — Custom X.509 extension carries a JSON workload identity payload. Server verifies the client is from an authorized CI repository and keyset. Client verifies the server is the expected signing service. See [Workload Identity](#oid-json-policy-verification-workload-identity).
- **Seccomp syscall filtering** — Daemon and dispatch threads run under strict seccomp-BPF filters, reducing attack surface.
- **Hostname verification** — Client verifies the server certificate's SAN against the expected hostname.
- **Dagger CI pipeline** — Reproducible test pipeline via [Dagger](https://dagger.io/) with layer-cached builds and always-run test execution.

## Building

### Prerequisites

- CMake >= 2.4
- OpenSSL >= 1.1.1 (TLS 1.3 support)
- libseccomp-dev (Linux, optional — for seccomp builds)
- pkg-config

### Standard build

```bash
cmake .
make
```

This produces:
- `pkcs11-daemon` — The server daemon
- `libpkcs11-proxy.so` — The client PKCS#11 library

### Seccomp-enabled build

```bash
gcc -o pkcs11-daemon-seccomp \
    src/daemon/gck-rpc-daemon-standalone.c src/common/gck-rpc-dispatch.c \
    src/common/gck-rpc-message.c src/common/gck-rpc-util.c \
    src/common/egg-buffer.c src/tls/gck-rpc-tls.c \
    src/tls/gck-rpc-tls-policy.c src/seccomp/syscall-reporter.c \
    ext/cjson/cJSON.c \
    -D_GNU_SOURCE -DSECCOMP -DDEBUG_SECCOMP \
    -Iinclude -I. -Iext -Ipkcs11 \
    -ldl -lpthread -lssl -lcrypto -lseccomp -Wall -Wextra
```

### Docker build

Both images use [Chainguard Wolfi](https://images.chainguard.dev/directory/image/wolfi-base/overview) (`cgr.dev/chainguard/wolfi-base`) — a minimal, glibc-based, zero-CVE container base.

```bash
task build          # Production image (Wolfi, ~129 MB)
task test:build     # Test image with SoftHSM + step CLI + test PKI
```

## Quick Start

### 1. Generate certificates

Use [step CLI](https://smallstep.com/docs/step-cli/) to create a CA and leaf certificates:

```bash
# Root CA
step certificate create "My Root CA" ca.crt ca.key \
    --profile root-ca --kty EC --curve P-256 --no-password --insecure

# Server cert
step certificate create "pkcs11-proxy" server.crt server.key \
    --ca ca.crt --ca-key ca.key \
    --kty EC --curve P-256 --no-password --insecure \
    --san localhost --san 127.0.0.1

# Client cert
step certificate create "ci-runner" client.crt client.key \
    --ca ca.crt --ca-key ca.key \
    --kty EC --curve P-256 --no-password --insecure
```

### 2. Start the daemon

```bash
PKCS11_PROXY_TLS_CERT=server.crt \
PKCS11_PROXY_TLS_KEY=server.key \
PKCS11_PROXY_TLS_CA=ca.crt \
pkcs11-daemon /usr/lib/softhsm/libsofthsm2.so tls://0.0.0.0:2345
```

### 3. Use the proxy library

```bash
PKCS11_PROXY_SOCKET=tls://127.0.0.1:2345 \
PKCS11_PROXY_TLS_CERT=client.crt \
PKCS11_PROXY_TLS_KEY=client.key \
PKCS11_PROXY_TLS_CA=ca.crt \
PKCS11_PROXY_TLS_SERVER_NAME=localhost \
pkcs11-tool --module=libpkcs11-proxy.so -L
```

## Environment Variables

### Connection

| Variable | Used by | Required | Description |
|---|---|---|---|
| `PKCS11_DAEMON_SOCKET` | Server | No | Listen address. Overridden by CLI arg. Default: Unix socket. |
| `PKCS11_PROXY_SOCKET` | Client | Yes | Server address to connect to. |

**Socket formats:**
- `unix:///path/to/socket` — Unix domain socket
- `tcp://host:port` — Plain TCP (no encryption)
- `tls://host:port` — TLS 1.3 encrypted connection

### TLS Configuration

All TLS variables are read by both the daemon and the client library.

| Variable | Used by | Required | Description |
|---|---|---|---|
| `PKCS11_PROXY_TLS_CERT` | Both | Server: Yes, Client: Yes for mTLS | Path to PEM certificate chain file. |
| `PKCS11_PROXY_TLS_KEY` | Both | Server: Yes, Client: Yes for mTLS | Path to PEM private key file. |
| `PKCS11_PROXY_TLS_CA` | Both | Yes (for `tls://`) | Path to CA bundle (PEM) for peer certificate verification. |
| `PKCS11_PROXY_TLS_SERVER_NAME` | Client | No | Expected server hostname for certificate verification. If unset, hostname verification is skipped. |
| `PKCS11_PROXY_TLS_REQUIRE_MTLS` | Server | No | `"true"` (default) to require client certificates. Set to `"false"` to allow anonymous clients. |

### OID JSON Policy Verification (Workload Identity)

Policy verification adds a second layer of authorization **on top of mTLS**. While mTLS ensures the peer has a valid certificate from your CA, policy verification ensures the peer's certificate was issued for a *specific workload* — binding the TLS session to an identity like "this GitHub Actions workflow in this repository".

This is designed for CI/CD signing use cases (e.g. [Sigstore cosign](https://docs.sigstore.dev/)) where:

1. A CI pipeline (e.g. GitHub Actions) needs to access a remote HSM to sign artifacts
2. The CI runner receives a short-lived OIDC token containing claims about the workload (which repo, which workflow, which git ref)
3. Those claims are embedded as a JSON payload inside a custom X.509 certificate extension
4. The daemon verifies that only the *intended* CI workload can access the signing keys

**Without policy verification**, any client with a valid CA-signed certificate can connect. **With policy verification**, the daemon additionally checks that the client certificate carries the correct workload identity claims — preventing a compromised runner from a different repository from accessing the signing keys.

Policy verification is **optional** and **off by default**. When the relevant environment variables are unset, policy checking is silently skipped and only standard mTLS applies.

#### Server-side (validates client certificates)

Set these on the **daemon** to restrict which workloads can connect:

| Variable | Required | Description |
|---|---|---|
| `PKCS11_PROXY_TLS_POLICY_REPO` | Yes (to enable) | Authorized workload identifier (e.g. `"org/repo"`). This is the CI source repository that is permitted to access the signing keys. Matched against the `repo` field in the client cert's OID extension. |
| `PKCS11_PROXY_TLS_POLICY_KEYSET` | Yes (to enable) | Logical key group name (e.g. `"cosign-v1"`). Allows the same daemon to serve multiple keysets while ensuring clients only access the keyset they were issued credentials for. Matched against the `keyset` field. |
| `PKCS11_PROXY_TLS_POLICY_SERVICE_NS` | Optional | Expected namespace for in-cluster service clients (e.g. `"sigstore"`). When set alongside `PKCS11_PROXY_TLS_POLICY_KEYSET`, the daemon also accepts service-client certificates (same schema as the server policy: `v`, `service`, `namespace`, `keyset`, `purpose`). |

`PKCS11_PROXY_TLS_POLICY_KEYSET` plus at least one of `PKCS11_PROXY_TLS_POLICY_REPO` or `PKCS11_PROXY_TLS_POLICY_SERVICE_NS` must be set to activate server-side policy checking. When both are set, CI client policy is tried first; if it does not match, service-client policy is tried as a fallback.

The CI client certificate's OID extension (`1.7.4.4.6.3.3.4.4.8`) must contain a JSON object with **exactly** these 10 fields:

```json
{
  "v": 2,
  "sub": "repo:org/repo:ref:refs/heads/main",
  "iss": "https://token.actions.githubusercontent.com",
  "repo": "org/repo",
  "workflow": "build-and-sign.yml",
  "ref": "refs/heads/main",
  "sha": "abc123def456...",
  "runner": "ubuntu-latest",
  "aud": "pkcs11-proxy",
  "keyset": "cosign-v1"
}
```

| Field | Validation | Description |
|---|---|---|
| `v` | Must be `2` | Schema version. |
| `sub` | Must be present (value not enforced) | OIDC subject claim. Composite identifier for the CI identity. Logged for audit, not enforced. |
| `iss` | Must be present (value not enforced) | OIDC issuer URL. Identifies the identity provider (e.g. GitHub Actions OIDC). |
| `repo` | **Must match** `PKCS11_PROXY_TLS_POLICY_REPO` | Source repository of the CI workload. This is the primary access control — only workflows from this repo can connect. |
| `workflow` | Must be present (value not enforced) | CI workflow name. Logged for audit, not enforced. |
| `ref` | Must be present (value not enforced) | Git ref (branch/tag). Logged for audit, not enforced. |
| `sha` | Must be present (value not enforced) | Git commit SHA. Logged for audit, not enforced. |
| `runner` | Must be present (value not enforced) | CI runner environment. Logged for audit, not enforced. |
| `aud` | Must be present (value not enforced) | Audience claim. Logged for audit, not enforced. |
| `keyset` | **Must match** `PKCS11_PROXY_TLS_POLICY_KEYSET` | Logical key group the client is authorized to use. |

Extra fields are rejected. Missing fields are rejected. This strict schema prevents injection of unexpected claims.

#### Client-side (validates server certificates)

Set these on the **client** to verify the daemon's identity via its OID policy extension:

| Variable | Required | Description |
|---|---|---|
| `PKCS11_PROXY_TLS_POLICY_SERVICE` | Yes (to enable) | Expected service name (e.g. `"pkcs11-proxy"`). Prevents connecting to a rogue daemon impersonating the signing service. |
| `PKCS11_PROXY_TLS_POLICY_NAMESPACE` | Yes (to enable) | Expected deployment namespace (e.g. `"sigstore"`). Distinguishes between production, staging, or per-tenant deployments. |
| `PKCS11_PROXY_TLS_POLICY_KEYSET` | Yes (to enable) | Expected keyset name (e.g. `"cosign-v1"`). Ensures the server is authorized to serve the keyset the client expects. |

**All three** must be set to activate client-side policy checking.

The server certificate's OID extension must contain a JSON object with **exactly** these 5 fields:

```json
{
  "v": 2,
  "service": "pkcs11-proxy",
  "namespace": "sigstore",
  "keyset": "cosign-v1",
  "purpose": "signing"
}
```

| Field | Validation | Description |
|---|---|---|
| `v` | Must be `2` | Schema version. |
| `service` | **Must match** `PKCS11_PROXY_TLS_POLICY_SERVICE` | Service type identifier. |
| `namespace` | **Must match** `PKCS11_PROXY_TLS_POLICY_NAMESPACE` | Deployment scope / tenant. |
| `keyset` | **Must match** `PKCS11_PROXY_TLS_POLICY_KEYSET` | Logical key group served. |
| `purpose` | Must be present (value not enforced) | Operational purpose of the service (e.g. `"signing"`). Logged for audit, not enforced. |

## OID Extension in Certificates

The policy JSON is embedded as an X.509 extension with OID `1.7.4.4.6.3.3.4.4.8`. The extension value is ASN.1 encoded as:

```
OCTET STRING { UTF8String { <json bytes> } }
```

Maximum policy size: 16 KB.

To create certificates with this extension using step CLI, use a certificate template that includes the OID:

```json
{
  "subject": {{ toJson .Subject }},
  "keyUsage": ["digitalSignature"],
  "extKeyUsage": ["clientAuth"],
  "extensions": [
    {
      "id": "1.7.4.4.6.3.3.4.4.8",
      "value": {{ .Insecure.User.oidPolicy }}
    }
  ]
}
```

Then generate with:

```bash
echo '{"oidPolicy": "...json..."}' > vars.json
step certificate create "ci-runner" client.crt client.key \
    --template client.tpl \
    --ca ca.crt --ca-key ca.key \
    --set-file vars.json \
    --no-password --insecure
```

## Deployment Examples

### Daemon with full policy enforcement

```bash
PKCS11_PROXY_TLS_CERT=/etc/pkcs11-proxy/server.crt \
PKCS11_PROXY_TLS_KEY=/etc/pkcs11-proxy/server.key \
PKCS11_PROXY_TLS_CA=/etc/pkcs11-proxy/ca.crt \
PKCS11_PROXY_TLS_REQUIRE_MTLS=true \
PKCS11_PROXY_TLS_POLICY_REPO="myorg/myrepo" \
PKCS11_PROXY_TLS_POLICY_KEYSET="cosign-v1" \
pkcs11-daemon /usr/lib/softhsm/libsofthsm2.so tls://0.0.0.0:2345
```

### Client with server policy verification

```bash
PKCS11_PROXY_SOCKET=tls://hsm.example.com:2345 \
PKCS11_PROXY_TLS_CERT=/run/secrets/client.crt \
PKCS11_PROXY_TLS_KEY=/run/secrets/client.key \
PKCS11_PROXY_TLS_CA=/run/secrets/ca.crt \
PKCS11_PROXY_TLS_SERVER_NAME=hsm.example.com \
PKCS11_PROXY_TLS_POLICY_SERVICE=pkcs11-proxy \
PKCS11_PROXY_TLS_POLICY_NAMESPACE=sigstore \
PKCS11_PROXY_TLS_POLICY_KEYSET=cosign-v1 \
cosign sign --key "pkcs11:token=cosign;object=mykey?pin-value=1234" ...
```

## Testing

### Run the full test suite

```bash
task test               # Build + run all unit tests
task test:build         # Build test Docker image only
task test:run           # Run tests (image must exist)
task test:shell         # Interactive shell in test container
```

### Unit test coverage (34 tests)

| Tests | Category | Description |
|---|---|---|
| T01–T05 | TLS 1.3 Basic | mTLS handshake, no cert, wrong CA, protocol enforcement |
| T10–T16 | OID Policy (Server) | Valid/missing/wrong OID in client certs (via test harness) |
| T20–T23 | OID Policy (Client) | Valid/missing/wrong OID in server certs (via test harness) |
| T30–T31 | Hostname | Correct/wrong hostname verification |
| T40–T41 | Data Integrity | Full PKCS#11 crypto round-trip over mTLS (EC P-256 keygen, ECDSA sign/verify) |
| T50–T51 | Seccomp | PKCS#11 crypto round-trip with seccomp-BPF syscall filtering enabled |
| T60–T63 | OID Policy (Daemon) | Production daemon with policy enforcement (accept valid, reject wrong repo, reject no OID, reject wrong keyset) |
| T64–T67 | OID Policy (Logging) | Daemon startup shows enforcement enabled/disabled, logs pretty-printed OID JSON on accept, logs rejection reason |
| T70–T73 | Concurrent Connections | Health-probe race resilience: crypto after probes, concurrent probes, interleaved sessions |

### Integration tests (5 tests)

Multi-container tests using ephemeral PKI, a real pkcs11-daemon with SoftHSM, and a client exercising the full proxy stack:

| Test | Description |
|---|---|
| I1 | Valid OID client performs full PKCS#11 crypto (EC keygen, ECDSA sign/verify) through the proxy |
| I2 | Multiple sequential connections succeed (session resilience) |
| I3 | Client cert with wrong `repo` claim is rejected by daemon policy |
| I4 | Client cert with no OID extension is rejected by daemon policy |
| I5 | Daemon remains healthy after policy rejections — valid client still succeeds |

#### Docker Compose

```bash
task test:integration
```

Uses `docker/docker-compose.test.yml` with three services: `pki` (ephemeral CA + certs), `server` (pkcs11-daemon + SoftHSM), `client` (test runner). See `docker/integration/run.sh` for orchestration.

#### Dagger

```bash
task dagger:test          # Unit tests via Dagger
task dagger:integration   # Integration tests via Dagger
```

The [Dagger](https://dagger.io/) module (`.dagger/`) replicates the Docker Compose integration pipeline as pure Dagger Functions with no `docker-compose` dependency. The Docker image build (including the slow `apk` layer) is layer-cached; test execution always re-runs via `cache="never"`.

| Function | Description |
|---|---|
| `test` | Builds test image, runs 34 unit tests |
| `integration-test` | Generates ephemeral PKI, starts daemon as a Dagger service, runs 5 integration tests via service binding |
| `sslscan` | Runs sslscan against the daemon to audit TLS configuration |
| `trivy-scan` | Scans production server image with Trivy for vulnerabilities |

## Development Tools

### Prerequisites

Run `task reqs` to check which tools are installed:

```bash
$ task reqs
── Build ──
✓ docker
✓ cmake
✓ gcc
✓ pkg-config

── C Linting ──
✓ clang-format
✓ clang-tidy
✓ cppcheck

── Python Linting ──
✓ ruff
✓ ty

── CI ──
✓ dagger
✓ task
```

**Install C linting tools:**

```bash
# Ubuntu/Debian
sudo apt-get install clang-format clang-tidy cppcheck

# macOS
brew install clang-format llvm cppcheck

# Wolfi/Alpine (in Docker)
apk add clang-extra-tools cppcheck
```

### Task Commands

| Command | Description |
|---|---|
| `task reqs` | Check development tool install status |
| `task build` | Build production server Docker image |
| `task test` | Build test image + run all tests |
| `task test:shell` | Interactive shell in test container |
| `task test:integration` | Multi-container integration tests |
| `task lint` | Run all linters (C + Python) |
| `task lint:c` | Run all C linters (format + cppcheck + clang-tidy) |
| `task lint:c:fmt` | Auto-format C code with clang-format |
| `task lint:c:fmt:check` | Check C formatting (dry-run, fails on diff) |
| `task lint:c:cppcheck` | Run cppcheck static analysis |
| `task lint:c:tidy` | Run clang-tidy (needs cmake) |
| `task lint:py` | Run all Python linters (ruff + ty) |
| `task check` | Full pre-commit check (lint + test) |
| `task dagger:lint` | Run C linters via Dagger (containerized) |
| `task dagger:test` | Unit tests via Dagger |
| `task dagger:integration` | Integration tests via Dagger |
| `task dagger:sslscan` | TLS audit via Dagger |
| `task dagger:trivy` | Trivy vulnerability scan via Dagger |

### C Code Quality

The project uses three complementary C analysis tools:

- **[clang-format](https://clang.llvm.org/docs/ClangFormat.html)** — Enforces consistent code style. Config: `.clang-format`.
- **[clang-tidy](https://clang.llvm.org/extra/clang-tidy/)** — Catches bugs, undefined behavior, and style issues. Config: `.clang-tidy`. Needs `compile_commands.json` (generated by cmake).
- **[cppcheck](https://cppcheck.sourceforge.io/)** — Deep static analysis for null derefs, leaks, buffer overflows.

Run locally or containerized via Dagger (no local tool install required):

```bash
task lint:c              # Local — requires clang-format, clang-tidy, cppcheck
task dagger:lint         # Containerized — only requires dagger
```

## Project Structure

```
├── src/
│   ├── daemon/
│   │   └── gck-rpc-daemon-standalone.c  # Server daemon (main, signal handling)
│   ├── proxy/
│   │   └── gck-rpc-module.c             # Client PKCS#11 proxy library
│   ├── common/
│   │   ├── gck-rpc-dispatch.c           # Server RPC dispatch threads
│   │   ├── gck-rpc-message.c            # RPC message serialization
│   │   ├── gck-rpc-util.c               # Shared utilities
│   │   └── egg-buffer.c                 # Dynamic buffer implementation
│   ├── tls/
│   │   ├── gck-rpc-tls.c                # TLS 1.3 init, handshake, policy wiring
│   │   └── gck-rpc-tls-policy.c         # OID JSON extraction and validation
│   └── seccomp/
│       └── syscall-reporter.c           # Seccomp syscall reporter
├── include/                             # All header files
│   ├── config.h, egg-buffer.h
│   ├── gck-rpc-layer.h, gck-rpc-private.h
│   ├── gck-rpc-tls.h, gck-rpc-tls-policy.h
│   └── seccomp-bpf.h, syscall-reporter.h
├── ext/cjson/                           # Embedded cJSON library
├── .dagger/
│   └── src/pkcs_11_proxy/main.py        # Dagger CI module (test + integration-test)
├── docker/
│   ├── Dockerfile.server                # Production image (Wolfi, multi-stage)
│   ├── Dockerfile.test                  # Test image (SoftHSM + step CLI + test PKI)
│   ├── docker-compose.test.yml          # Integration test compose file
│   └── integration/
│       ├── run.sh                       # Compose orchestration script
│       ├── generate-pki.sh              # Ephemeral PKI for integration tests
│       ├── entrypoint-server.sh         # Server container entrypoint
│       └── entrypoint-client.sh         # Client container entrypoint (I1–I5)
├── tests/
│   ├── run-all.sh                       # Unit test runner (T01–T73)
│   ├── generate-test-pki.sh             # Unit test PKI generator (step CLI)
│   ├── templates/                       # Step CLI certificate templates
│   ├── test-tls-server.c                # TLS test harness (server)
│   ├── test-tls-client.c                # TLS test harness (client)
│   └── test-pkcs11-tool.c               # PKCS#11 crypto test (EC keygen, ECDSA sign/verify)
├── .clang-format                        # clang-format style config
├── .clang-tidy                          # clang-tidy checks config
├── CMakeLists.txt                       # Build system
└── Taskfile.yml                         # Task runner (build, test, lint, CI)
```

## Security Considerations

### Defense in depth

The authentication stack has three independent layers, each addressing a different threat:

| Layer | Mechanism | Threat mitigated |
|---|---|---|
| 1. Transport encryption | TLS 1.3 only | Eavesdropping, MITM, protocol downgrade |
| 2. Mutual authentication | mTLS with CA-pinned certificates | Unauthorized clients/servers without valid certs |
| 3. Workload identity | OID JSON policy in X.509 extensions | Lateral movement — valid cert from wrong workload |

Layer 3 is the key differentiator: even if an attacker compromises a CI runner and obtains a valid CA-signed certificate, the daemon rejects it unless the certificate's embedded workload claims match the expected repository and keyset.

### Implementation details

- **TLS 1.3 only** — No downgrade possible. `SSL_CTX_set_min_proto_version(TLS1_3_VERSION)`.
- **No compression** — `SSL_OP_NO_COMPRESSION` prevents CRIME attacks.
- **Seccomp-BPF** — Daemon and dispatch threads run with syscall whitelists. Blocked syscalls kill the process (`SCMP_ACT_KILL`).
- **Policy JSON size limit** — 16 KB max prevents DoS via oversized extensions.
- **Strict field checking** — Extra fields in policy JSON are rejected to prevent injection of unexpected claims.
- **No PSK** — Only certificate-based authentication is supported.

## License

GNU Library General Public License v2 (LGPL-2.0). See `COPYING.LIB`.
