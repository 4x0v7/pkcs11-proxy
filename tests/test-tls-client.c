/*
 * test-tls-client.c - Minimal TLS 1.3 client for testing pkcs11-proxy TLS layer.
 *
 * Connects to a TLS server, performs handshake with optional mTLS, sends data, reads echo.
 * Used by the test harness to validate client-side TLS behavior.
 *
 * Environment variables:
 *   TEST_TLS_HOST        - server host (default: 127.0.0.1)
 *   TEST_TLS_PORT        - server port (required)
 *   TEST_TLS_CERT        - client certificate PEM file (optional, for mTLS)
 *   TEST_TLS_KEY         - client private key PEM file (optional, for mTLS)
 *   TEST_TLS_CA          - CA certificate for verifying server cert
 *   TEST_TLS_SERVER_NAME - expected server hostname for verification (default: localhost)
 *   TEST_TLS_MAX_VERSION - "1.2" to force TLS 1.2 (for negative test), default: 1.3
 *   TEST_TLS_MESSAGE     - message to send (default: "PING")
 *   TEST_TLS_VERIFY_OID - "true" to verify server OID policy extension
 *   TEST_TLS_EXPECT_SERVICE   - expected service field
 *   TEST_TLS_EXPECT_NAMESPACE - expected namespace field
 *   TEST_TLS_EXPECT_KEYSET    - expected keyset field
 *
 * Exit codes:
 *   0 = handshake + echo succeeded
 *   1 = configuration/setup error
 *   2 = handshake failed (expected in negative tests)
 *   3 = data exchange error
 *   4 = echo mismatch or OID policy verification failed
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "gck-rpc-tls-policy.h"

static const char *getenv_or(const char *name, const char *def) {
	const char *v = getenv(name);
	return (v && v[0]) ? v : def;
}

int main(void) {
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	int sock = -1;
	int ret = 1;

	const char *host = getenv_or("TEST_TLS_HOST", "127.0.0.1");
	const char *port_str = getenv("TEST_TLS_PORT");
	const char *cert_file = getenv("TEST_TLS_CERT");
	const char *key_file = getenv("TEST_TLS_KEY");
	const char *ca_file = getenv("TEST_TLS_CA");
	const char *server_name = getenv_or("TEST_TLS_SERVER_NAME", "localhost");
	const char *max_version = getenv_or("TEST_TLS_MAX_VERSION", "1.3");
	const char *message = getenv_or("TEST_TLS_MESSAGE", "PING");

	if (!port_str || !ca_file) {
		fprintf(stderr, "test-tls-client: TEST_TLS_PORT and TEST_TLS_CA required\n");
		return 1;
	}

	int port = atoi(port_str);

	/* Create TLS context */
	ctx = SSL_CTX_new(TLS_method());
	if (!ctx) {
		fprintf(stderr, "test-tls-client: SSL_CTX_new failed\n");
		goto cleanup;
	}

	/* Set protocol version */
	if (strcmp(max_version, "1.2") == 0) {
		/* Force TLS 1.2 only — for negative test T05 */
		SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
		SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
	} else {
		SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
		SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
	}

	SSL_CTX_set_ciphersuites(ctx,
		"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256");
	SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

	/* Load CA for server verification */
	if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
		fprintf(stderr, "test-tls-client: failed to load CA %s\n", ca_file);
		goto cleanup;
	}

	/* Load client cert+key for mTLS (optional) */
	if (cert_file && key_file) {
		if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) != 1) {
			fprintf(stderr, "test-tls-client: failed to load cert %s\n", cert_file);
			goto cleanup;
		}
		if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
			fprintf(stderr, "test-tls-client: failed to load key %s\n", key_file);
			goto cleanup;
		}
	}

	/* Enable server cert verification */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	/* Connect TCP */
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("test-tls-client: socket");
		goto cleanup;
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, host, &addr.sin_addr);

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("test-tls-client: connect");
		goto cleanup;
	}

	/* TLS handshake */
	ssl = SSL_new(ctx);
	if (!ssl) {
		fprintf(stderr, "test-tls-client: SSL_new failed\n");
		goto cleanup;
	}

	SSL_set_fd(ssl, sock);

	/* Hostname verification */
	if (server_name && server_name[0]) {
		SSL_set_tlsext_host_name(ssl, server_name);
		SSL_set1_host(ssl, server_name);
	}

	int hs = SSL_connect(ssl);
	if (hs != 1) {
		int ssl_err = SSL_get_error(ssl, hs);
		char errbuf[256];
		ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
		fprintf(stderr, "test-tls-client: handshake failed (ssl_err=%d): %s\n",
			ssl_err, errbuf);
		ret = 2;
		goto cleanup;
	}

	fprintf(stderr, "test-tls-client: handshake OK, protocol=%s cipher=%s\n",
		SSL_get_version(ssl), SSL_get_cipher_name(ssl));

	/* OID policy verification of server cert (if requested) */
	const char *verify_oid = getenv("TEST_TLS_VERIFY_OID");
	if (verify_oid && strcmp(verify_oid, "true") == 0) {
		X509 *peer_cert = SSL_get0_peer_certificate(ssl);
		if (!peer_cert) {
			fprintf(stderr, "test-tls-client: OID check: no peer cert\n");
			ret = 4;
			goto cleanup;
		}

		int json_len = 0;
		char *json = policy_extract_json(peer_cert, &json_len);
		if (!json) {
			fprintf(stderr, "test-tls-client: OID check: no OID extension found\n");
			ret = 4;
			goto cleanup;
		}

		fprintf(stderr, "test-tls-client: OID policy JSON: %.*s\n", json_len, json);

		const char *expect_svc = getenv("TEST_TLS_EXPECT_SERVICE");
		const char *expect_ns = getenv("TEST_TLS_EXPECT_NAMESPACE");
		const char *expect_ks = getenv("TEST_TLS_EXPECT_KEYSET");
		PolicyResult pr = policy_validate_server(json, json_len, expect_svc, expect_ns, expect_ks);

		free(json);

		if (pr != POLICY_OK) {
			fprintf(stderr, "test-tls-client: OID policy REJECTED: %s\n",
				policy_result_str(pr));
			ret = 4;
			goto cleanup;
		}
		fprintf(stderr, "test-tls-client: OID policy ACCEPTED\n");
	}

	/* Send message */
	int msg_len = (int)strlen(message);
	if (SSL_write(ssl, message, msg_len) != msg_len) {
		fprintf(stderr, "test-tls-client: SSL_write failed\n");
		ret = 3;
		goto cleanup;
	}

	/* Read echo */
	char buf[4096];
	int n = SSL_read(ssl, buf, sizeof(buf) - 1);
	if (n <= 0) {
		fprintf(stderr, "test-tls-client: SSL_read failed\n");
		ret = 3;
		goto cleanup;
	}

	buf[n] = '\0';
	fprintf(stderr, "test-tls-client: echo received: %s\n", buf);

	/* Verify echo matches */
	if (n != msg_len || memcmp(buf, message, msg_len) != 0) {
		fprintf(stderr, "test-tls-client: echo mismatch!\n");
		ret = 4;
		goto cleanup;
	}

	fprintf(stderr, "test-tls-client: SUCCESS\n");
	ret = 0;

cleanup:
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	if (ctx) SSL_CTX_free(ctx);
	if (sock >= 0) close(sock);

	return ret;
}
