/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-rpc-tls-policy.h - OID JSON policy extraction and validation

   Copyright (C) 2025, SIGNEDGIT

   pkcs11-proxy is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   pkcs11-proxy is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
*/

#ifndef GCKRPC_TLS_POLICY_H_
#define GCKRPC_TLS_POLICY_H_

#include <openssl/x509.h>

/* OID 1.7.4.4.6.3.3.4.4.8 = SIGNEDGIT policy extension */
#define PKCS11_PROXY_POLICY_OID "1.7.4.4.6.3.3.4.4.8"

/* Maximum allowed policy JSON size (16 KB) */
#define PKCS11_PROXY_POLICY_MAX_SIZE 16384

/* Policy validation result codes */
typedef enum {
	POLICY_OK = 0,
	POLICY_ERR_NO_EXTENSION,  /* OID extension not found in cert */
	POLICY_ERR_ASN1_DECODE,   /* Failed to decode ASN.1 UTF8String */
	POLICY_ERR_OVERSIZED,     /* Policy JSON exceeds max size */
	POLICY_ERR_INVALID_JSON,  /* Not valid JSON */
	POLICY_ERR_MISSING_FIELD, /* Required field missing */
	POLICY_ERR_WRONG_VALUE,   /* Field value doesn't match expected */
	POLICY_ERR_EXTRA_FIELDS   /* Unexpected fields present */
} PolicyResult;

/* Extract raw JSON string from the policy OID extension of a certificate.
 * Caller must free the returned string.
 * Returns NULL if the extension is not found or cannot be decoded.
 * Sets *out_len to the length of the returned string.
 */
char *policy_extract_json(X509 *cert, int *out_len);

/* Validate a server policy JSON against expected values.
 * Expected fields: v, service, namespace, keyset
 * Returns POLICY_OK on success.
 */
PolicyResult policy_validate_server(const char *json, int json_len, const char *expected_service,
                                    const char *expected_namespace, const char *expected_keyset);

/* Validate a client policy JSON against expected values.
 * Expected fields: v, iss, repo, workflow, ref, aud, keyset
 * Returns POLICY_OK on success.
 */
PolicyResult policy_validate_client(const char *json, int json_len, const char *expected_repo,
                                    const char *expected_keyset);

/* Return a human-readable string for a PolicyResult. */
const char *policy_result_str(PolicyResult r);

/* Pretty-print a raw JSON string.  Caller must free() the result.
 * Returns NULL on parse error (caller should fall back to raw string).
 */
char *policy_pretty_json(const char *json, int json_len);

#endif /* GCKRPC_TLS_POLICY_H_ */
