/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-rpc-tls.c - TLS 1.3 mTLS with certificate-based authentication

   Copyright (C) 2013, NORDUnet A/S
   Copyright (C) 2025, SIGNEDGIT

   pkcs11-proxy is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   pkcs11-proxy is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Original TLS-PSK author: Fredrik Thulin <fredrik@thulin.net>
*/

#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "gck-rpc-private.h"
#include "gck-rpc-tls-policy.h"
#include "gck-rpc-tls.h"

#include <assert.h>

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

/* -----------------------------------------------------------------------------
 * LOGGING and DEBUGGING
 */
#ifndef DEBUG_OUTPUT
#define DEBUG_OUTPUT 0
#endif
#if DEBUG_OUTPUT
#define debug(x) gck_rpc_debug x
#else
#define debug(x)
#endif
#define warning(x) gck_rpc_warn x

/* -----------------------------------------------------------------------------
 * TLS 1.3 CIPHERSUITES
 */
#define PKCS11PROXY_TLS13_CIPHERSUITES  \
	"TLS_AES_256_GCM_SHA384:"       \
	"TLS_CHACHA20_POLY1305_SHA256:" \
	"TLS_AES_128_GCM_SHA256"

/* -----------------------------------------------------------------------------
 * HELPER: get env var with optional default
 */
static const char *
_getenv_or(const char *name, const char *def)
{
	const char *v = getenv(name);
	return (v && v[0]) ? v : def;
}

/* -----------------------------------------------------------------------------
 * TLS 1.3 certificate-based mTLS
 */

/* Initialize OpenSSL and create an SSL CTX. Should be called just once.
 *
 * Reads configuration from environment variables:
 *   PKCS11_PROXY_TLS_CERT        - PEM certificate chain
 *   PKCS11_PROXY_TLS_KEY         - PEM private key
 *   PKCS11_PROXY_TLS_CA          - CA bundle for peer verification
 *   PKCS11_PROXY_TLS_SERVER_NAME - expected server hostname (client only)
 *   PKCS11_PROXY_TLS_REQUIRE_MTLS - "true" to require client certs (server, default true)
 *
 * Returns 0 on failure and 1 on success.
 */
int
gck_rpc_init_tls(GckRpcTlsState *state, enum gck_rpc_tls_caller caller)
{
	const char *cert_file, *key_file, *ca_file, *require_mtls_str;
	int require_mtls;

	if (state->initialized == 1) {
		warning(("TLS state already initialized"));
		return 0;
	}

	assert(caller == GCK_RPC_TLS_CLIENT || caller == GCK_RPC_TLS_SERVER);

	cert_file = getenv("PKCS11_PROXY_TLS_CERT");
	key_file = getenv("PKCS11_PROXY_TLS_KEY");
	ca_file = getenv("PKCS11_PROXY_TLS_CA");
	require_mtls_str = _getenv_or("PKCS11_PROXY_TLS_REQUIRE_MTLS", "true");
	require_mtls = (strcmp(require_mtls_str, "true") == 0);

	/* Validate required env vars */
	if (!ca_file || !ca_file[0]) {
		gck_rpc_warn("PKCS11_PROXY_TLS_CA is required");
		return 0;
	}

	if (caller == GCK_RPC_TLS_SERVER) {
		if (!cert_file || !cert_file[0] || !key_file || !key_file[0]) {
			gck_rpc_warn("PKCS11_PROXY_TLS_CERT and PKCS11_PROXY_TLS_KEY are required "
			             "for server");
			return 0;
		}
	}

	/* Create TLS 1.3 context */
	state->ssl_ctx = SSL_CTX_new(TLS_method());

	if (state->ssl_ctx == NULL || !SSL_CTX_set_min_proto_version(state->ssl_ctx, TLS1_3_VERSION)
	    || !SSL_CTX_set_max_proto_version(state->ssl_ctx, TLS1_3_VERSION)) {
		gck_rpc_warn("can't initialize SSL_CTX for TLS 1.3");
		return 0;
	}

	/* Set TLS 1.3 ciphersuites */
	SSL_CTX_set_ciphersuites(state->ssl_ctx, PKCS11PROXY_TLS13_CIPHERSUITES);

	/* Restrict key exchange to EC curves only (no ffdhe) */
	if (!SSL_CTX_set1_groups_list(state->ssl_ctx, "P-256:P-384:P-521:X25519:X448")) {
		gck_rpc_warn("can't set supported groups");
		return 0;
	}

	/* Disable compression, for security (CRIME Attack). */
	SSL_CTX_set_options(state->ssl_ctx, SSL_OP_NO_COMPRESSION | SSL_OP_IGNORE_UNEXPECTED_EOF);

	/* Load CA bundle for peer verification */
	if (SSL_CTX_load_verify_locations(state->ssl_ctx, ca_file, NULL) != 1) {
		gck_rpc_warn("can't load CA bundle: %s", ca_file);
		return 0;
	}

	/* Load certificate and key (always for server, optional for client mTLS) */
	if (cert_file && cert_file[0] && key_file && key_file[0]) {
		if (SSL_CTX_use_certificate_chain_file(state->ssl_ctx, cert_file) != 1) {
			gck_rpc_warn("can't load certificate: %s", cert_file);
			return 0;
		}
		if (SSL_CTX_use_PrivateKey_file(state->ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
			gck_rpc_warn("can't load private key: %s", key_file);
			return 0;
		}
		if (SSL_CTX_check_private_key(state->ssl_ctx) != 1) {
			gck_rpc_warn("certificate/key mismatch");
			return 0;
		}
		debug(("Loaded cert=%s key=%s", cert_file, key_file));
	}

	/* Configure peer verification */
	if (caller == GCK_RPC_TLS_SERVER && require_mtls) {
		SSL_CTX_set_verify(state->ssl_ctx,
		                   SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
		debug(("Server: mTLS required"));
	} else if (caller == GCK_RPC_TLS_CLIENT) {
		SSL_CTX_set_verify(state->ssl_ctx, SSL_VERIFY_PEER, NULL);
		debug(("Client: server verification enabled"));
	}

	state->type = caller;
	state->initialized = 1;

	debug(("Initialized TLS 1.3 %s", caller == GCK_RPC_TLS_CLIENT ? "client" : "server"));

	return 1;
}

/* Set up SSL for a new socket. Call this after accept() or connect().
 *
 * Returns 1 on success and 0 on failure.
 */
int
gck_rpc_start_tls(GckRpcTlsState *state, int sock)
{
	int res;
	char buf[256];
	const char *server_name;

	state->ssl = SSL_new(state->ssl_ctx);
	if (!state->ssl) {
		warning(("can't initialize SSL"));
		return 0;
	}

	state->bio = BIO_new_socket(sock, BIO_NOCLOSE);
	if (!state->bio) {
		warning(("can't initialize SSL BIO"));
		return 0;
	}

	SSL_set_bio(state->ssl, state->bio, state->bio);

	if (state->type == GCK_RPC_TLS_CLIENT) {
		/* Set hostname verification for client */
		server_name = getenv("PKCS11_PROXY_TLS_SERVER_NAME");
		if (server_name && server_name[0]) {
			SSL_set_tlsext_host_name(state->ssl, server_name);
			SSL_set1_host(state->ssl, server_name);
			debug(("Client: hostname verification for '%s'", server_name));
		}

		res = SSL_connect(state->ssl);
	} else {
		res = SSL_accept(state->ssl);
	}

	if (res != 1) {
		int ssl_err = SSL_get_error(state->ssl, res);
		ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
		debug(("TLS handshake failed: %i/%i (%s)", res, ssl_err, buf));
		(void)ssl_err; /* used by debug() macro when DEBUG_OUTPUT=1 */
		return 0;
	}

	gck_rpc_log("TLS handshake OK: %s %s", SSL_get_version(state->ssl),
	            SSL_get_cipher_name(state->ssl));

	/* OID policy verification (optional — skipped when env vars are unset) */
	if (state->type == GCK_RPC_TLS_SERVER) {
		const char *policy_repo = getenv("PKCS11_PROXY_TLS_POLICY_REPO");
		const char *policy_keyset = getenv("PKCS11_PROXY_TLS_POLICY_KEYSET");
		const char *policy_svc_ns = getenv("PKCS11_PROXY_TLS_POLICY_SERVICE_NS");

		if (policy_keyset && policy_keyset[0]
		    && ((policy_repo && policy_repo[0]) || (policy_svc_ns && policy_svc_ns[0]))) {
			X509 *peer = SSL_get0_peer_certificate(state->ssl);
			char *json;
			int json_len;
			PolicyResult pr;

			if (!peer) {
				warning(("OID policy: no client certificate"));
				return 0;
			}

			json = policy_extract_json(peer, &json_len);
			if (!json) {
				warning(("OID policy: no policy extension in client cert"));
				return 0;
			}

			/* Try CI client policy first (v2: v, sub, iss, repo, workflow, ref, sha, runner, aud, keyset) */
			pr = POLICY_ERR_MISSING_FIELD;
			if (policy_repo && policy_repo[0]) {
				pr = policy_validate_client(json, json_len, policy_repo,
				                            policy_keyset);
			}

			/* Fall back to service client policy (v, service, namespace, keyset) */
			if (pr != POLICY_OK && policy_svc_ns && policy_svc_ns[0]) {
				pr = policy_validate_service_client(json, json_len, policy_svc_ns,
				                                    policy_keyset);
				if (pr == POLICY_OK) {
					gck_rpc_log("OID policy OK (service-client)");
					{
						char *pretty = policy_pretty_json(json, json_len);
						gck_rpc_log("%s", pretty ? pretty : json);
						free(pretty);
					}
					free(json);
					goto policy_done;
				}
			}

			if (pr != POLICY_OK) {
				char *pretty = policy_pretty_json(json, json_len);
				warning(("OID policy rejected client: %s\nReceived:\n%s",
				         policy_result_str(pr), pretty ? pretty : json));
				free(pretty);
				free(json);
				return 0;
			}

			/* Log the validated CI client identity */
			gck_rpc_log("OID policy OK (ci-client)");
			{
				char *pretty = policy_pretty_json(json, json_len);
				gck_rpc_log("%s", pretty ? pretty : json);
				free(pretty);
			}
			free(json);
		}
	policy_done:;
	} else {
		/* Client-side: validate server cert OID policy */
		const char *policy_service = getenv("PKCS11_PROXY_TLS_POLICY_SERVICE");
		const char *policy_namespace = getenv("PKCS11_PROXY_TLS_POLICY_NAMESPACE");
		const char *policy_keyset = getenv("PKCS11_PROXY_TLS_POLICY_KEYSET");

		if (policy_service && policy_service[0] && policy_namespace && policy_namespace[0]
		    && policy_keyset && policy_keyset[0]) {
			X509 *peer = SSL_get0_peer_certificate(state->ssl);
			char *json;
			int json_len;
			PolicyResult pr;

			if (!peer) {
				warning(("OID policy: no server certificate"));
				return 0;
			}

			json = policy_extract_json(peer, &json_len);
			if (!json) {
				warning(("OID policy: no policy extension in server cert"));
				return 0;
			}

			pr = policy_validate_server(json, json_len, policy_service,
			                            policy_namespace, policy_keyset);

			if (pr != POLICY_OK) {
				char *pretty = policy_pretty_json(json, json_len);
				warning(("OID policy rejected server: %s\nReceived:\n%s",
				         policy_result_str(pr), pretty ? pretty : json));
				free(pretty);
				free(json);
				return 0;
			}

			/* Log the validated server identity */
			gck_rpc_log("OID policy OK (server)");
			{
				char *pretty = policy_pretty_json(json, json_len);
				gck_rpc_log("%s", pretty ? pretty : json);
				free(pretty);
			}
			free(json);
		}
	}

	return 1;
}

/* Un-initialize everything SSL related. Call this on application shut down.
 */
void
gck_rpc_close_tls(GckRpcTlsState *state)
{
	if (state->ssl) {
		SSL_shutdown(state->ssl);
		SSL_free(state->ssl);
		state->ssl = NULL;
		state->bio = NULL; /* freed by SSL_free */
	}

	if (state->ssl_ctx) {
		SSL_CTX_free(state->ssl_ctx);
		state->ssl_ctx = NULL;
	}
}

/* Clean up a per-connection SSL (does not free ssl_ctx). */
void
gck_rpc_close_tls_conn(SSL *ssl)
{
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl); /* also frees the BIO */
	}
}

/* Per-connection TLS: create SSL/BIO from the shared ssl_ctx.
 *
 * Each accepted connection gets its own SSL/BIO pair so that concurrent
 * connections (including health-probe connections) don't clobber each other.
 *
 * Returns 1 on success, 0 on failure.  Outputs via out_ssl / out_bio.
 */
int
gck_rpc_start_tls_conn(GckRpcTlsState *ctx, int sock, SSL **out_ssl, BIO **out_bio)
{
	SSL *ssl;
	BIO *bio;
	int res;
	char buf[256];
	const char *server_name;

	assert(ctx && ctx->ssl_ctx);

	ssl = SSL_new(ctx->ssl_ctx);
	if (!ssl) {
		warning(("can't initialize SSL"));
		return 0;
	}

	bio = BIO_new_socket(sock, BIO_NOCLOSE);
	if (!bio) {
		warning(("can't initialize SSL BIO"));
		SSL_free(ssl);
		return 0;
	}

	SSL_set_bio(ssl, bio, bio);

	if (ctx->type == GCK_RPC_TLS_CLIENT) {
		server_name = getenv("PKCS11_PROXY_TLS_SERVER_NAME");
		if (server_name && server_name[0]) {
			SSL_set_tlsext_host_name(ssl, server_name);
			SSL_set1_host(ssl, server_name);
			debug(("Client: hostname verification for '%s'", server_name));
		}
		res = SSL_connect(ssl);
	} else {
		res = SSL_accept(ssl);
	}

	if (res != 1) {
		int ssl_err = SSL_get_error(ssl, res);
		ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
		/* Health probes cause SSL_ERROR_SYSCALL / SSL_ERROR_ZERO_RETURN —
		 * downgrade to debug to avoid log noise. */
		debug(("TLS handshake failed: %i/%i (%s)", res, ssl_err, buf));
		(void)ssl_err; /* used by debug() macro when DEBUG_OUTPUT=1 */
		SSL_free(ssl); /* also frees bio */
		return 0;
	}

	gck_rpc_log("TLS handshake OK: %s %s", SSL_get_version(ssl), SSL_get_cipher_name(ssl));

	/* OID policy verification (optional — skipped when env vars are unset) */
	if (ctx->type == GCK_RPC_TLS_SERVER) {
		const char *policy_repo = getenv("PKCS11_PROXY_TLS_POLICY_REPO");
		const char *policy_keyset = getenv("PKCS11_PROXY_TLS_POLICY_KEYSET");
		const char *policy_svc_ns = getenv("PKCS11_PROXY_TLS_POLICY_SERVICE_NS");

		if (policy_keyset && policy_keyset[0]
		    && ((policy_repo && policy_repo[0]) || (policy_svc_ns && policy_svc_ns[0]))) {
			X509 *peer = SSL_get0_peer_certificate(ssl);
			char *json;
			int json_len;
			PolicyResult pr;

			if (!peer) {
				warning(("OID policy: no client certificate"));
				SSL_free(ssl);
				return 0;
			}

			json = policy_extract_json(peer, &json_len);
			if (!json) {
				warning(("OID policy: no policy extension in client cert"));
				SSL_free(ssl);
				return 0;
			}

			/* Try CI client policy first (v2: v, sub, iss, repo, workflow, ref, sha, runner, aud, keyset) */
			pr = POLICY_ERR_MISSING_FIELD;
			if (policy_repo && policy_repo[0]) {
				pr = policy_validate_client(json, json_len, policy_repo,
				                            policy_keyset);
			}

			/* Fall back to service client policy (v, service, namespace, keyset) */
			if (pr != POLICY_OK && policy_svc_ns && policy_svc_ns[0]) {
				pr = policy_validate_service_client(json, json_len, policy_svc_ns,
				                                    policy_keyset);
				if (pr == POLICY_OK) {
					gck_rpc_log("OID policy OK (service-client)");
					{
						char *pretty = policy_pretty_json(json, json_len);
						gck_rpc_log("%s", pretty ? pretty : json);
						free(pretty);
					}
					free(json);
					goto conn_policy_done;
				}
			}

			if (pr != POLICY_OK) {
				char *pretty = policy_pretty_json(json, json_len);
				warning(("OID policy rejected client: %s\nReceived:\n%s",
				         policy_result_str(pr), pretty ? pretty : json));
				free(pretty);
				free(json);
				SSL_free(ssl);
				return 0;
			}

			/* Log the validated CI client identity */
			gck_rpc_log("OID policy OK (ci-client)");
			{
				char *pretty = policy_pretty_json(json, json_len);
				gck_rpc_log("%s", pretty ? pretty : json);
				free(pretty);
			}
			free(json);
		}
	conn_policy_done:;
	} else {
		const char *policy_service = getenv("PKCS11_PROXY_TLS_POLICY_SERVICE");
		const char *policy_namespace = getenv("PKCS11_PROXY_TLS_POLICY_NAMESPACE");
		const char *policy_keyset = getenv("PKCS11_PROXY_TLS_POLICY_KEYSET");

		if (policy_service && policy_service[0] && policy_namespace && policy_namespace[0]
		    && policy_keyset && policy_keyset[0]) {
			X509 *peer = SSL_get0_peer_certificate(ssl);
			char *json;
			int json_len;
			PolicyResult pr;

			if (!peer) {
				warning(("OID policy: no server certificate"));
				SSL_free(ssl);
				return 0;
			}

			json = policy_extract_json(peer, &json_len);
			if (!json) {
				warning(("OID policy: no policy extension in server cert"));
				SSL_free(ssl);
				return 0;
			}

			pr = policy_validate_server(json, json_len, policy_service,
			                            policy_namespace, policy_keyset);

			if (pr != POLICY_OK) {
				char *pretty = policy_pretty_json(json, json_len);
				warning(("OID policy rejected server: %s\nReceived:\n%s",
				         policy_result_str(pr), pretty ? pretty : json));
				free(pretty);
				free(json);
				SSL_free(ssl);
				return 0;
			}

			/* Log the validated server identity */
			gck_rpc_log("OID policy OK (server)");
			{
				char *pretty = policy_pretty_json(json, json_len);
				gck_rpc_log("%s", pretty ? pretty : json);
				free(pretty);
			}
			free(json);
		}
	}

	*out_ssl = ssl;
	*out_bio = bio;
	return 1;
}

/* Send data using SSL.
 *
 * Returns the number of bytes written.
 */
int
gck_rpc_tls_write_all(GckRpcTlsState *state, void *data, unsigned int len)
{
	return gck_rpc_tls_write_all_conn(state->ssl, data, len);
}

int
gck_rpc_tls_write_all_conn(SSL *ssl, void *data, unsigned int len)
{
	int bytes;
	unsigned long error;
	char buf[256];

	assert(ssl);
	assert(data);
	assert(len > 0);

	bytes = SSL_write(ssl, data, (int)len);

	if (bytes <= 0) {
		while ((error = ERR_get_error())) {
			ERR_error_string_n(error, buf, sizeof(buf));
			debug(("SSL_write error: %s", buf));
		}
		return 0;
	}

	return bytes;
}

/* Read data using SSL.
 *
 * Returns the number of bytes read.
 */
int
gck_rpc_tls_read_all(GckRpcTlsState *state, void *data, unsigned int len)
{
	return gck_rpc_tls_read_all_conn(state->ssl, data, len);
}

int
gck_rpc_tls_read_all_conn(SSL *ssl, void *data, unsigned int len)
{
	int bytes, ssl_err;
	unsigned long error;
	char buf[256];

	assert(ssl);
	assert(data);
	assert(len > 0);

	bytes = SSL_read(ssl, data, (int)len);

	if (bytes <= 0) {
		ssl_err = SSL_get_error(ssl, bytes);
		debug(("tls_read: SSL_read returned %d, SSL_get_error=%d (wanted %u bytes)", bytes,
		       ssl_err, len));
		(void)ssl_err; /* used by debug() macro when DEBUG_OUTPUT=1 */
		while ((error = ERR_get_error())) {
			ERR_error_string_n(error, buf, sizeof(buf));
			debug(("SSL_read error: %s", buf));
		}
		return 0;
	}

	return bytes;
}
