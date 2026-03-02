/*
 * test-tls-server.c - Minimal TLS 1.3 server for testing pkcs11-proxy TLS layer.
 *
 * Listens on a port, performs TLS handshake with mTLS, then echoes data back.
 * Used by the test harness to validate server-side TLS behavior.
 *
 * Environment variables:
 *   TEST_TLS_PORT       - port to listen on (default: 0 = auto-assign, printed to stdout)
 *   TEST_TLS_CERT       - server certificate PEM file
 *   TEST_TLS_KEY        - server private key PEM file
 *   TEST_TLS_CA         - CA certificate for verifying client certs
 *   TEST_TLS_REQUIRE_MTLS - "true" to require client certs (default: true)
 *   TEST_TLS_PORT_FILE  - if set, write assigned port number to this file
 *   TEST_TLS_VERIFY_OID - "true" to verify client OID policy extension
 *   TEST_TLS_EXPECT_SERVICE   - expected service field (server-side policy check)
 *   TEST_TLS_EXPECT_NAMESPACE - expected namespace field
 *   TEST_TLS_EXPECT_KEYSET    - expected keyset field
 *   TEST_TLS_EXPECT_REPO      - expected repo field (client-side policy on peer)
 *
 * Exit codes:
 *   0 = handshake + echo succeeded
 *   1 = configuration/setup error
 *   2 = handshake failed (expected in negative tests)
 *   3 = data exchange error
 *   4 = OID policy verification failed
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "gck-rpc-tls-policy.h"

static volatile int running = 1;

static void sighandler(int sig) {
	(void)sig;
	running = 0;
}

static const char *getenv_or(const char *name, const char *def) {
	const char *v = getenv(name);
	return (v && v[0]) ? v : def;
}

int main(void) {
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	int listen_fd = -1, client_fd = -1;
	int ret = 1;

	signal(SIGTERM, sighandler);
	signal(SIGPIPE, SIG_IGN);

	const char *cert_file = getenv("TEST_TLS_CERT");
	const char *key_file = getenv("TEST_TLS_KEY");
	const char *ca_file = getenv("TEST_TLS_CA");
	const char *require_mtls_str = getenv_or("TEST_TLS_REQUIRE_MTLS", "true");
	int port = atoi(getenv_or("TEST_TLS_PORT", "0"));
	const char *port_file = getenv("TEST_TLS_PORT_FILE");
	int require_mtls = (strcmp(require_mtls_str, "true") == 0);

	if (!cert_file || !key_file || !ca_file) {
		fprintf(stderr, "test-tls-server: TEST_TLS_CERT, TEST_TLS_KEY, TEST_TLS_CA required\n");
		return 1;
	}

	/* Create TLS 1.3 context */
	ctx = SSL_CTX_new(TLS_method());
	if (!ctx) {
		fprintf(stderr, "test-tls-server: SSL_CTX_new failed\n");
		goto cleanup;
	}

	if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) ||
	    !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) {
		fprintf(stderr, "test-tls-server: failed to set TLS 1.3\n");
		goto cleanup;
	}

	SSL_CTX_set_ciphersuites(ctx,
		"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256");
	SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

	if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) != 1) {
		fprintf(stderr, "test-tls-server: failed to load cert %s\n", cert_file);
		goto cleanup;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
		fprintf(stderr, "test-tls-server: failed to load key %s\n", key_file);
		goto cleanup;
	}
	if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
		fprintf(stderr, "test-tls-server: failed to load CA %s\n", ca_file);
		goto cleanup;
	}

	if (require_mtls) {
		SSL_CTX_set_verify(ctx,
			SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	}

	/* Listen socket */
	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		perror("test-tls-server: socket");
		goto cleanup;
	}

	int optval = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(port);

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("test-tls-server: bind");
		goto cleanup;
	}

	/* Get assigned port */
	socklen_t addrlen = sizeof(addr);
	getsockname(listen_fd, (struct sockaddr *)&addr, &addrlen);
	int assigned_port = ntohs(addr.sin_port);

	if (listen(listen_fd, 1) < 0) {
		perror("test-tls-server: listen");
		goto cleanup;
	}

	/* Write port to file and stdout */
	fprintf(stdout, "LISTENING:%d\n", assigned_port);
	fflush(stdout);

	if (port_file) {
		FILE *pf = fopen(port_file, "w");
		if (pf) {
			fprintf(pf, "%d", assigned_port);
			fclose(pf);
		}
	}

	/* Accept one connection */
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
	if (client_fd < 0) {
		if (errno == EINTR && !running) {
			ret = 0;
			goto cleanup;
		}
		perror("test-tls-server: accept");
		goto cleanup;
	}

	/* TLS handshake */
	ssl = SSL_new(ctx);
	if (!ssl) {
		fprintf(stderr, "test-tls-server: SSL_new failed\n");
		goto cleanup;
	}

	SSL_set_fd(ssl, client_fd);

	int hs = SSL_accept(ssl);
	if (hs != 1) {
		int ssl_err = SSL_get_error(ssl, hs);
		char errbuf[256];
		ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
		fprintf(stderr, "test-tls-server: handshake failed (ssl_err=%d): %s\n",
			ssl_err, errbuf);
		ret = 2;
		goto cleanup;
	}

	fprintf(stderr, "test-tls-server: handshake OK, protocol=%s cipher=%s\n",
		SSL_get_version(ssl), SSL_get_cipher_name(ssl));

	/* OID policy verification (if requested) */
	const char *verify_oid = getenv("TEST_TLS_VERIFY_OID");
	if (verify_oid && strcmp(verify_oid, "true") == 0) {
		X509 *peer_cert = SSL_get0_peer_certificate(ssl);
		if (!peer_cert) {
			fprintf(stderr, "test-tls-server: OID check: no peer cert\n");
			ret = 4;
			goto cleanup;
		}

		int json_len = 0;
		char *json = policy_extract_json(peer_cert, &json_len);
		if (!json) {
			fprintf(stderr, "test-tls-server: OID check: no OID extension found\n");
			ret = 4;
			goto cleanup;
		}

		fprintf(stderr, "test-tls-server: OID policy JSON: %.*s\n", json_len, json);

		/* Determine which validation to use based on env vars */
		const char *expect_repo = getenv("TEST_TLS_EXPECT_REPO");
		PolicyResult pr;

		if (expect_repo) {
			/* Validate as client policy */
			const char *expect_keyset = getenv_or("TEST_TLS_EXPECT_KEYSET", "cosign-v1");
			pr = policy_validate_client(json, json_len, expect_repo, expect_keyset);
		} else {
			/* Validate as server policy (checking client cert's server-style fields) */
			const char *expect_svc = getenv("TEST_TLS_EXPECT_SERVICE");
			const char *expect_ns = getenv("TEST_TLS_EXPECT_NAMESPACE");
			const char *expect_ks = getenv("TEST_TLS_EXPECT_KEYSET");
			pr = policy_validate_server(json, json_len, expect_svc, expect_ns, expect_ks);
		}

		free(json);

		if (pr != POLICY_OK) {
			fprintf(stderr, "test-tls-server: OID policy REJECTED: %s\n",
				policy_result_str(pr));
			ret = 4;
			goto cleanup;
		}
		fprintf(stderr, "test-tls-server: OID policy ACCEPTED\n");
	}

	/* Echo: read some data, send it back */
	char buf[4096];
	int n = SSL_read(ssl, buf, sizeof(buf) - 1);
	if (n <= 0) {
		fprintf(stderr, "test-tls-server: SSL_read failed\n");
		ret = 3;
		goto cleanup;
	}

	buf[n] = '\0';
	fprintf(stderr, "test-tls-server: received %d bytes: %s\n", n, buf);

	if (SSL_write(ssl, buf, n) != n) {
		fprintf(stderr, "test-tls-server: SSL_write failed\n");
		ret = 3;
		goto cleanup;
	}

	ret = 0;

cleanup:
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	if (ctx) SSL_CTX_free(ctx);
	if (client_fd >= 0) close(client_fd);
	if (listen_fd >= 0) close(listen_fd);

	return ret;
}
