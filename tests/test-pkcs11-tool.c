/*
 * test-pkcs11-tool.c - Minimal PKCS#11 test client.
 *
 * Loads a PKCS#11 module (e.g. libpkcs11-proxy.so), calls C_Initialize,
 * C_GetSlotList, and C_GetTokenInfo on the first slot. Prints token label.
 *
 * Usage: test-pkcs11-tool <pkcs11-module-path>
 *
 * Exit codes:
 *   0 = success (token found)
 *   1 = error
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "pkcs11/pkcs11.h"

int main(int argc, char *argv[])
{
	void *module;
	CK_C_GetFunctionList fn_get_list;
	CK_FUNCTION_LIST_PTR funcs;
	CK_RV rv;
	CK_SLOT_ID slots[16];
	CK_ULONG slot_count = 16;
	CK_TOKEN_INFO token_info;

	if (argc != 2) {
		fprintf(stderr, "usage: test-pkcs11-tool <pkcs11-module>\n");
		return 1;
	}

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

	rv = funcs->C_Initialize(NULL);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_Initialize failed: 0x%lx\n", rv);
		return 1;
	}

	rv = funcs->C_GetSlotList(CK_TRUE, slots, &slot_count);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_GetSlotList failed: 0x%lx\n", rv);
		funcs->C_Finalize(NULL);
		return 1;
	}

	if (slot_count == 0) {
		fprintf(stderr, "No tokens found\n");
		funcs->C_Finalize(NULL);
		return 1;
	}

	rv = funcs->C_GetTokenInfo(slots[0], &token_info);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_GetTokenInfo failed: 0x%lx\n", rv);
		funcs->C_Finalize(NULL);
		return 1;
	}

	/* Token label is space-padded, 32 bytes */
	char label[33];
	memcpy(label, token_info.label, 32);
	label[32] = '\0';
	/* Trim trailing spaces */
	for (int i = 31; i >= 0 && label[i] == ' '; i--)
		label[i] = '\0';

	printf("TOKEN_LABEL=%s\n", label);
	printf("SLOT_COUNT=%lu\n", slot_count);

	funcs->C_Finalize(NULL);
	dlclose(module);

	return 0;
}
