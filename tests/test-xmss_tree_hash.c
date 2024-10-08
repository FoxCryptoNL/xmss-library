/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Pepijn Westen
 */

#include "libxmss.c"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(void)
{
    bool success = true;

    XmssSigningContext *context_ptr_dynamic = NULL;

#if !XMSS_ENABLE_SHA256
    const uint32_t any_supported_param_set = XMSS_PARAM_SHAKE256_10_256;
    XmssNativeValue256 expected_root = { {
        0xba62bdc3, 0x9af136a6, 0x3e66f19d, 0x3cfcda23, 0x2cf5cf48, 0x5aec1e22, 0xc35d739b, 0xdc511425,
    } };
#else
    const uint32_t any_supported_param_set = XMSS_PARAM_SHA2_10_256;
    const XmssNativeValue256 expected_root = { {
        0x9d898033, 0xe37af48e, 0x6a116f8b, 0x15651cc2, 0x67734670, 0x07ad1937, 0x5d38c23c, 0x690c3483
    } };
#endif
    success = success && (xmss_context_initialize(&context_ptr_dynamic, any_supported_param_set, realloc, free, NULL) == XMSS_OKAY);

    uint8_t random[32] = {0};
    uint8_t secure_random[96] = {0};
    XmssNativeValue256 root = {0};

    for (size_t i = 0; i < sizeof(secure_random); i++) {
        secure_random[i] = (uint8_t)i;
    }


    XmssBuffer random_buffer = {sizeof(random), random};
    XmssBuffer secure_random_buffer = {sizeof(secure_random), secure_random};

    XmssKeyContext *key_context = NULL;
    XmssPrivateKeyStatelessBlob *stateless_blob = NULL;
    XmssPrivateKeyStatefulBlob *stateful_blob = NULL;
    XmssIndexObfuscationSetting index_obfuscation_setting = XMSS_INDEX_OBFUSCATION_OFF;

    // call xmss_generate_private_key with some reasonable params
    success = success && (xmss_generate_private_key(&key_context, &stateless_blob, &stateful_blob,
            &secure_random_buffer, index_obfuscation_setting, &random_buffer, context_ptr_dynamic) == XMSS_OKAY);

    success = success && (xmss_tree_hash(&root, key_context, NULL, 0, 10) == XMSS_OKAY);

    if (memcmp(&root, &expected_root, sizeof(XmssNativeValue256))) {
        success = false;
        printf("xmss_tree_hash returned an unexpected result:\n");
        for (size_t i = 0; i < XMSS_VALUE_256_WORDS; i++) {
            printf("%08"PRIx32" ", root.data[i]);
        }
        printf("\n");
        printf("expected result:\n");
        for (size_t i = 0; i < XMSS_VALUE_256_WORDS; i++) {
            printf("%08"PRIx32" ", expected_root.data[i]);
        }

    }

    printf("\n");

    xmss_free_key_context(key_context);
    free(stateless_blob);
    free(stateful_blob);
    free(context_ptr_dynamic);

     return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
