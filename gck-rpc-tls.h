/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-rpc-tls.h - TLS 1.3 mTLS with certificate-based authentication

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

#ifndef GCKRPC_TLS_H_
#define GCKRPC_TLS_H_

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#if OPENSSL_VERSION_NUMBER < 0x10101000L
# error "OpenSSL version >= 1.1.1 required (TLS 1.3 support)"
#endif

enum gck_rpc_tls_caller {
	GCK_RPC_TLS_CLIENT,
	GCK_RPC_TLS_SERVER
};

typedef struct {
	int initialized;
	SSL_CTX *ssl_ctx;
	BIO *bio;
	SSL *ssl;
	enum gck_rpc_tls_caller type;
} GckRpcTlsState;

/* Environment variables:
 *   PKCS11_PROXY_TLS_CERT        - PEM certificate chain
 *   PKCS11_PROXY_TLS_KEY         - PEM private key
 *   PKCS11_PROXY_TLS_CA          - CA bundle for peer verification
 *   PKCS11_PROXY_TLS_SERVER_NAME - expected server hostname (client only)
 *   PKCS11_PROXY_TLS_REQUIRE_MTLS - "true" to require client certs (server, default true)
 */

/* Initialize TLS context. Reads env vars for cert/key/CA paths.
 * Returns 1 on success, 0 on failure.
 */
int gck_rpc_init_tls(GckRpcTlsState *state, enum gck_rpc_tls_caller caller);

/* Perform TLS handshake on an established socket.
 * Returns 1 on success, 0 on failure.
 */
int gck_rpc_start_tls(GckRpcTlsState *state, int sock);

/* Send data over TLS. Returns bytes written, or 0 on error. */
int gck_rpc_tls_write_all(GckRpcTlsState *state, void *data, unsigned int len);

/* Read data over TLS. Returns bytes read, or 0 on error. */
int gck_rpc_tls_read_all(GckRpcTlsState *state, void *data, unsigned int len);

/* Clean up TLS state. */
void gck_rpc_close_tls(GckRpcTlsState *state);

#endif /* GCKRPC_TLS_H_ */
