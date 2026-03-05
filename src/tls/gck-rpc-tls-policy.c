/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-rpc-tls-policy.c - OID JSON policy extraction and validation

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

#include <stdlib.h>
#include <string.h>

#include "ext/cjson/cJSON.h"
#include "gck-rpc-tls-policy.h"

#include <openssl/asn1.h>
#include <openssl/obj_mac.h>
#include <openssl/x509v3.h>

/* -----------------------------------------------------------------------------
 * LOGGING
 */
#include <stdarg.h>
#include <stdio.h>

#ifndef DEBUG_OUTPUT
#define DEBUG_OUTPUT 0
#endif

static void
_policy_warn(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	(void)fprintf(stderr, "policy: ");
	(void)vfprintf(stderr, fmt, ap);
	(void)fprintf(stderr, "\n");
	va_end(ap);
}

#if DEBUG_OUTPUT
#define debug(x) _policy_warn x
#else
#define debug(x)
#endif
#define warning(x) _policy_warn x

const char *
policy_result_str(PolicyResult r)
{
	switch (r) {
	case POLICY_OK:
		return "OK";
	case POLICY_ERR_NO_EXTENSION:
		return "OID extension not found";
	case POLICY_ERR_ASN1_DECODE:
		return "ASN.1 decode failed";
	case POLICY_ERR_OVERSIZED:
		return "policy JSON exceeds max size";
	case POLICY_ERR_INVALID_JSON:
		return "invalid JSON";
	case POLICY_ERR_MISSING_FIELD:
		return "required field missing";
	case POLICY_ERR_WRONG_VALUE:
		return "field value mismatch";
	case POLICY_ERR_EXTRA_FIELDS:
		return "unexpected extra fields";
	}
	return "unknown error";
}

/* Extract the raw JSON string from the SIGNEDGIT OID extension.
 *
 * The extension value is an OCTET STRING wrapping a UTF8String:
 *   OCTET STRING { UTF8String { <json bytes> } }
 *
 * Returns a malloc'd NUL-terminated string, or NULL on error.
 */
char *
policy_extract_json(X509 *cert, int *out_len)
{
	ASN1_OBJECT *oid;
	int ext_idx;
	X509_EXTENSION *ext;
	ASN1_OCTET_STRING *ext_data;
	const unsigned char *p;
	long len;
	int tag, xclass;
	char *json;

	if (out_len) {
		*out_len = 0;
	}

	oid = OBJ_txt2obj(PKCS11_PROXY_POLICY_OID, 1);
	if (!oid) {
		warning(("can't create OID object for %s", PKCS11_PROXY_POLICY_OID));
		return NULL;
	}

	ext_idx = X509_get_ext_by_OBJ(cert, oid, -1);
	ASN1_OBJECT_free(oid);

	if (ext_idx < 0) {
		debug(("OID %s not found in certificate", PKCS11_PROXY_POLICY_OID));
		return NULL;
	}

	ext = X509_get_ext(cert, ext_idx);
	if (!ext) {
		return NULL;
	}

	ext_data = X509_EXTENSION_get_data(ext);
	if (!ext_data || ext_data->length <= 0) {
		return NULL;
	}

	/* Decode the UTF8String inside the OCTET STRING */
	p = ext_data->data;
	len = ext_data->length;

	/* Parse ASN.1 tag + length to get the inner content */
	if (ASN1_get_object(&p, &len, &tag, &xclass, ext_data->length) != 0) {
		warning(("failed to parse ASN.1 in OID extension"));
		return NULL;
	}

	if (tag != V_ASN1_UTF8STRING) {
		warning(("OID extension is not a UTF8String (tag=%d)", tag));
		return NULL;
	}

	if (len <= 0 || len > PKCS11_PROXY_POLICY_MAX_SIZE) {
		warning(("OID extension content length invalid: %ld", len));
		return NULL;
	}

	json = malloc(len + 1);
	if (!json) {
		return NULL;
	}

	memcpy(json, p, len);
	json[len] = '\0';

	if (out_len) {
		*out_len = (int)len;
	}

	debug(("Extracted OID policy JSON (%ld bytes)", len));
	return json;
}

/* Helper: check a required string field in a cJSON object.
 * If expected is non-NULL, also checks the value matches.
 * Returns POLICY_OK, POLICY_ERR_MISSING_FIELD, or POLICY_ERR_WRONG_VALUE.
 */
static PolicyResult
_check_string_field(const cJSON *root, const char *field, const char *expected)
{
	const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, field);
	if (!item || !cJSON_IsString(item)) {
		warning(("policy: missing or non-string field '%s'", field));
		return POLICY_ERR_MISSING_FIELD;
	}
	if (expected && strcmp(item->valuestring, expected) != 0) {
		warning(("policy: field '%s' = '%s', expected '%s'", field, item->valuestring,
		         expected));
		return POLICY_ERR_WRONG_VALUE;
	}
	return POLICY_OK;
}

/* Helper: check the version field (must be number == 1) */
static PolicyResult
_check_version(const cJSON *root)
{
	const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, "v");
	if (!item || !cJSON_IsNumber(item)) {
		warning(("policy: missing or non-numeric 'v' field"));
		return POLICY_ERR_MISSING_FIELD;
	}
	if (item->valueint != 1) {
		warning(("policy: unsupported version %d", item->valueint));
		return POLICY_ERR_WRONG_VALUE;
	}
	return POLICY_OK;
}

/* Helper: count the number of keys in a cJSON object */
static int
_count_fields(const cJSON *root)
{
	int count = 0;
	const cJSON *item;
	cJSON_ArrayForEach(item, root)
	{
		count++;
	}
	return count;
}

/* Helper: warn about unexpected fields not in the allowed set.
 * allowed is a NULL-terminated array of field names.
 */
static void
_warn_extra_fields(const cJSON *root, const char *const *allowed, int allowed_count,
                   const char *label)
{
	const cJSON *item;
	char extras[512];
	int pos = 0;

	cJSON_ArrayForEach(item, root)
	{
		int found = 0;
		for (int i = 0; i < allowed_count; i++) {
			if (strcmp(item->string, allowed[i]) == 0) {
				found = 1;
				break;
			}
		}
		if (!found && pos < (int)sizeof(extras) - 2) {
			if (pos > 0) {
				extras[pos++] = ',';
				extras[pos++] = ' ';
			}
			int n = snprintf(extras + pos, sizeof(extras) - (size_t)pos, "'%s'",
			                 item->string);
			if (n > 0)
				pos += n;
		}
	}
	extras[pos] = '\0';

	warning(("%s policy has %d fields (expected %d); extra: %s", label, _count_fields(root),
	         allowed_count, extras));
}

PolicyResult
policy_validate_server(const char *json, int json_len, const char *expected_service,
                       const char *expected_namespace, const char *expected_keyset)
{
	cJSON *root;
	PolicyResult r;

	if (!json || json_len <= 0) {
		return POLICY_ERR_INVALID_JSON;
	}

	if (json_len > PKCS11_PROXY_POLICY_MAX_SIZE) {
		return POLICY_ERR_OVERSIZED;
	}

	root = cJSON_ParseWithLength(json, json_len);
	if (!root) {
		warning(("policy: failed to parse server JSON"));
		return POLICY_ERR_INVALID_JSON;
	}

	/* Server policy expected fields: v, service, namespace, keyset (4 fields) */
	r = _check_version(root);
	if (r != POLICY_OK) {
		goto done;
	}

	r = _check_string_field(root, "service", expected_service);
	if (r != POLICY_OK) {
		goto done;
	}

	r = _check_string_field(root, "namespace", expected_namespace);
	if (r != POLICY_OK) {
		goto done;
	}

	r = _check_string_field(root, "keyset", expected_keyset);
	if (r != POLICY_OK) {
		goto done;
	}

	if (_count_fields(root) != 4) {
		static const char *const server_fields[]
		    = { "v", "service", "namespace", "keyset" };
		_warn_extra_fields(root, server_fields, 4, "server");
		r = POLICY_ERR_EXTRA_FIELDS;
		goto done;
	}

	r = POLICY_OK;

done:
	cJSON_Delete(root);
	return r;
}

PolicyResult
policy_validate_client(const char *json, int json_len, const char *expected_repo,
                       const char *expected_keyset)
{
	cJSON *root;
	PolicyResult r;

	if (!json || json_len <= 0) {
		return POLICY_ERR_INVALID_JSON;
	}

	if (json_len > PKCS11_PROXY_POLICY_MAX_SIZE) {
		return POLICY_ERR_OVERSIZED;
	}

	root = cJSON_ParseWithLength(json, json_len);
	if (!root) {
		warning(("policy: failed to parse client JSON"));
		return POLICY_ERR_INVALID_JSON;
	}

	/* Client policy expected fields: v, iss, repo, workflow, ref, aud, keyset (7 fields) */
	r = _check_version(root);
	if (r != POLICY_OK) {
		goto done;
	}

	r = _check_string_field(root, "iss", NULL);
	if (r != POLICY_OK) {
		goto done;
	}

	r = _check_string_field(root, "repo", expected_repo);
	if (r != POLICY_OK) {
		goto done;
	}

	r = _check_string_field(root, "workflow", NULL);
	if (r != POLICY_OK) {
		goto done;
	}

	r = _check_string_field(root, "ref", NULL);
	if (r != POLICY_OK) {
		goto done;
	}

	r = _check_string_field(root, "aud", NULL);
	if (r != POLICY_OK) {
		goto done;
	}

	r = _check_string_field(root, "keyset", expected_keyset);
	if (r != POLICY_OK) {
		goto done;
	}

	if (_count_fields(root) != 7) {
		static const char *const client_fields[]
		    = { "v", "iss", "repo", "workflow", "ref", "aud", "keyset" };
		_warn_extra_fields(root, client_fields, 7, "client");
		r = POLICY_ERR_EXTRA_FIELDS;
		goto done;
	}

	r = POLICY_OK;

done:
	cJSON_Delete(root);
	return r;
}

PolicyResult
policy_validate_service_client(const char *json, int json_len,
                               const char *expected_namespace,
                               const char *expected_keyset)
{
	cJSON *root;
	PolicyResult r;

	if (!json || json_len <= 0) {
		return POLICY_ERR_INVALID_JSON;
	}

	if (json_len > PKCS11_PROXY_POLICY_MAX_SIZE) {
		return POLICY_ERR_OVERSIZED;
	}

	root = cJSON_ParseWithLength(json, json_len);
	if (!root) {
		warning(("policy: failed to parse service client JSON"));
		return POLICY_ERR_INVALID_JSON;
	}

	/* Service client policy expected fields: v, service, namespace, keyset (4 fields) */
	r = _check_version(root);
	if (r != POLICY_OK) {
		goto done;
	}

	r = _check_string_field(root, "service", NULL);
	if (r != POLICY_OK) {
		goto done;
	}

	r = _check_string_field(root, "namespace", expected_namespace);
	if (r != POLICY_OK) {
		goto done;
	}

	r = _check_string_field(root, "keyset", expected_keyset);
	if (r != POLICY_OK) {
		goto done;
	}

	if (_count_fields(root) != 4) {
		static const char *const svc_fields[]
		    = { "v", "service", "namespace", "keyset" };
		_warn_extra_fields(root, svc_fields, 4, "service-client");
		r = POLICY_ERR_EXTRA_FIELDS;
		goto done;
	}

	r = POLICY_OK;

done:
	cJSON_Delete(root);
	return r;
}

char *
policy_pretty_json(const char *json, int json_len)
{
	cJSON *root;
	char *pretty;

	if (!json || json_len <= 0)
		return NULL;

	root = cJSON_ParseWithLength(json, (size_t)json_len);
	if (!root)
		return NULL;

	pretty = cJSON_Print(root);
	cJSON_Delete(root);
	return pretty;
}
