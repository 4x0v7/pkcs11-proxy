/*
 * test-pkcs11-tool.c - PKCS#11 test client exercising real crypto via proxy.
 *
 * Loads a PKCS#11 module (e.g. libpkcs11-proxy.so), then exercises:
 *   1. Token enumeration (C_GetSlotList, C_GetTokenInfo)
 *   2. Session login (C_OpenSession, C_Login)
 *   3. EC P-256 key pair generation (C_GenerateKeyPair)
 *   4. ECDSA sign + verify (C_SignInit/C_Sign, C_VerifyInit/C_Verify)
 *   5. Object destruction (C_DestroyObject)
 *   6. Session close + finalize
 *
 * Usage: test-pkcs11-tool <pkcs11-module-path>
 *   Environment: PKCS11_TEST_PIN (default "1234")
 *
 * Exit codes:
 *   0 = all operations succeeded
 *   1 = error
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "pkcs11/pkcs11.h"

#define TEST_PIN_DEFAULT "1234"
#define TEST_DATA "pkcs11-proxy integration test payload"
#define DEFAULT_SIGN_ITERATIONS 1

static void print_hex(const char *label, CK_BYTE *data, CK_ULONG len)
{
	fprintf(stderr, "%s (%lu bytes): ", label, len);
	for (CK_ULONG i = 0; i < len && i < 16; i++)
		fprintf(stderr, "%02x", data[i]);
	if (len > 16)
		fprintf(stderr, "...");
	fprintf(stderr, "\n");
}

int main(int argc, char *argv[])
{
	void *module;
	CK_C_GetFunctionList fn_get_list;
	CK_FUNCTION_LIST_PTR funcs;
	CK_RV rv;
	CK_SLOT_ID slots[16];
	CK_ULONG slot_count = 16;
	CK_TOKEN_INFO token_info;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE pub_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE priv_key = CK_INVALID_HANDLE;
	const char *pin;

	if (argc != 2) {
		fprintf(stderr, "usage: test-pkcs11-tool <pkcs11-module>\n");
		return 1;
	}

	pin = getenv("PKCS11_TEST_PIN");
	if (!pin || !pin[0])
		pin = TEST_PIN_DEFAULT;

	/* ─── Load module ─── */

	module = dlopen(argv[1], RTLD_NOW);
	if (!module) {
		fprintf(stderr, "dlopen failed: %s\n", dlerror());
		return 1;
	}

	fn_get_list = (CK_C_GetFunctionList)dlsym(module, "C_GetFunctionList");
	if (!fn_get_list) {
		fprintf(stderr, "C_GetFunctionList not found\n");
		return 1;
	}

	rv = fn_get_list(&funcs);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_GetFunctionList failed: 0x%lx\n", rv);
		return 1;
	}

	/* ─── 1. Initialize + enumerate ─── */

	rv = funcs->C_Initialize(NULL);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_Initialize failed: 0x%lx\n", rv);
		return 1;
	}

	rv = funcs->C_GetSlotList(CK_TRUE, slots, &slot_count);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_GetSlotList failed: 0x%lx\n", rv);
		goto finalize;
	}

	if (slot_count == 0) {
		fprintf(stderr, "No tokens found\n");
		goto finalize;
	}

	rv = funcs->C_GetTokenInfo(slots[0], &token_info);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_GetTokenInfo failed: 0x%lx\n", rv);
		goto finalize;
	}

	/* Token label is space-padded, 32 bytes */
	{
		char label[33];
		memcpy(label, token_info.label, 32);
		label[32] = '\0';
		for (int i = 31; i >= 0 && label[i] == ' '; i--)
			label[i] = '\0';
		printf("TOKEN_LABEL=%s\n", label);
		printf("SLOT_COUNT=%lu\n", slot_count);
	}

	/* ─── 2. Open session + login ─── */

	rv = funcs->C_OpenSession(slots[0],
		CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_OpenSession failed: 0x%lx\n", rv);
		goto finalize;
	}

	rv = funcs->C_Login(session, CKU_USER,
		(CK_UTF8CHAR_PTR)pin, (CK_ULONG)strlen(pin));
	if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
		fprintf(stderr, "C_Login failed: 0x%lx\n", rv);
		goto close_session;
	}

	printf("SESSION=open LOGIN=ok\n");

	/* ─── 3. Generate EC P-256 key pair ─── */

	{
		CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };

		/* OID for P-256: 1.2.840.10045.3.1.7 (DER encoded) */
		CK_BYTE ec_params[] = {
			0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
		};

		CK_BBOOL ck_true = CK_TRUE;
		CK_BBOOL ck_false = CK_FALSE;
		CK_BYTE key_id[] = { 0x01 };
		CK_UTF8CHAR pub_label[] = "test-pub";
		CK_UTF8CHAR priv_label[] = "test-priv";

		CK_ATTRIBUTE pub_tmpl[] = {
			{ CKA_TOKEN,     &ck_false, sizeof(ck_false) },
			{ CKA_VERIFY,    &ck_true,  sizeof(ck_true)  },
			{ CKA_EC_PARAMS, ec_params, sizeof(ec_params) },
			{ CKA_LABEL,     pub_label, sizeof(pub_label) - 1 },
			{ CKA_ID,        key_id,    sizeof(key_id) },
		};

		CK_ATTRIBUTE priv_tmpl[] = {
			{ CKA_TOKEN,       &ck_false, sizeof(ck_false) },
			{ CKA_PRIVATE,     &ck_true,  sizeof(ck_true)  },
			{ CKA_SENSITIVE,   &ck_true,  sizeof(ck_true)  },
			{ CKA_SIGN,        &ck_true,  sizeof(ck_true)  },
			{ CKA_LABEL,       priv_label, sizeof(priv_label) - 1 },
			{ CKA_ID,          key_id,    sizeof(key_id) },
		};

		rv = funcs->C_GenerateKeyPair(session, &mech,
			pub_tmpl, sizeof(pub_tmpl) / sizeof(pub_tmpl[0]),
			priv_tmpl, sizeof(priv_tmpl) / sizeof(priv_tmpl[0]),
			&pub_key, &priv_key);
		if (rv != CKR_OK) {
			fprintf(stderr, "C_GenerateKeyPair failed: 0x%lx\n", rv);
			goto logout;
		}

		printf("KEYGEN=EC_P256 PUB=%lu PRIV=%lu\n",
			(unsigned long)pub_key, (unsigned long)priv_key);
	}

	/* ─── 4. Sign + Verify ─── */

	{
		CK_MECHANISM sign_mech = { CKM_ECDSA, NULL, 0 };
		CK_BYTE signature[128];
		CK_ULONG sig_len;
		CK_BYTE data[] = TEST_DATA;
		CK_ULONG data_len = sizeof(data) - 1;

		const char *iter_env = getenv("PKCS11_TEST_SIGN_ITERATIONS");
		int sign_iterations = iter_env ? atoi(iter_env) : DEFAULT_SIGN_ITERATIONS;
		if (sign_iterations < 1)
			sign_iterations = 1;

		for (int iter = 0; iter < sign_iterations; iter++) {
			sig_len = sizeof(signature);

			/* Sign */
			rv = funcs->C_SignInit(session, &sign_mech, priv_key);
			if (rv != CKR_OK) {
				fprintf(stderr, "C_SignInit failed (iter %d): 0x%lx\n", iter, rv);
				goto destroy_keys;
			}

			rv = funcs->C_Sign(session, data, data_len, signature, &sig_len);
			if (rv != CKR_OK) {
				fprintf(stderr, "C_Sign failed (iter %d): 0x%lx\n", iter, rv);
				goto destroy_keys;
			}

			/* Verify */
			rv = funcs->C_VerifyInit(session, &sign_mech, pub_key);
			if (rv != CKR_OK) {
				fprintf(stderr, "C_VerifyInit failed (iter %d): 0x%lx\n", iter, rv);
				goto destroy_keys;
			}

			rv = funcs->C_Verify(session, data, data_len, signature, sig_len);
			if (rv != CKR_OK) {
				fprintf(stderr, "C_Verify failed (iter %d): 0x%lx\n", iter, rv);
				goto destroy_keys;
			}
		}

		print_hex("SIGNATURE", signature, sig_len);
		printf("SIGN=ok SIG_LEN=%lu ITERATIONS=%d\n", sig_len, sign_iterations);
		printf("VERIFY=ok\n");

		/* Verify with tampered data should fail */
		rv = funcs->C_VerifyInit(session, &sign_mech, pub_key);
		if (rv != CKR_OK) {
			fprintf(stderr, "C_VerifyInit(tamper) failed: 0x%lx\n", rv);
			goto destroy_keys;
		}

		data[0] ^= 0xFF; /* flip a byte */
		rv = funcs->C_Verify(session, data, data_len, signature, sig_len);
		if (rv == CKR_SIGNATURE_INVALID) {
			printf("VERIFY_TAMPER=correctly_rejected\n");
		} else {
			fprintf(stderr, "C_Verify(tampered) unexpected rv: 0x%lx\n", rv);
			goto destroy_keys;
		}
	}

	printf("CRYPTO=pass\n");

	/* ─── 5. Cleanup ─── */

destroy_keys:
	if (pub_key != CK_INVALID_HANDLE)
		funcs->C_DestroyObject(session, pub_key);
	if (priv_key != CK_INVALID_HANDLE)
		funcs->C_DestroyObject(session, priv_key);

logout:
	funcs->C_Logout(session);

close_session:
	if (session != CK_INVALID_HANDLE)
		funcs->C_CloseSession(session);

finalize:
	funcs->C_Finalize(NULL);
	dlclose(module);

	/* Success only if we got all the way through crypto */
	if (rv == CKR_OK || rv == CKR_SIGNATURE_INVALID) {
		return 0;
	}
	return 1;
}
