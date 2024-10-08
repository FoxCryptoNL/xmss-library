/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Pepijn Westen
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "endianness.h"
#include "signing.h"
#include "signing_private.h"


int main(void)
{
    bool success = true;

    XmssSigningContext *context_ptr_dynamic = NULL;

#if !XMSS_ENABLE_SHA256
    const uint32_t any_supported_param_set = XMSS_PARAM_SHAKE256_10_256;
    XmssNativeValue256 expected_root = { {
        0xba62bdc3, 0x9af136a6, 0x3e66f19d, 0x3cfcda23, 0x2cf5cf48, 0x5aec1e22, 0xc35d739b, 0xdc511425,
    } };
    /* Public key as exported from dotnet implementation: https://github.com/dorssel/dotnet-xmss/
      * with OID added manually. */
    uint8_t expected_pk[] = {
        0, 0, 0, 16, /* algorithm OID */
        186, 98, 189, 195, 154, 241, 54, 166, 62, 102, 241, 157, 60, 252, 218, 35, 44, 245, 207, 72, 90, 236, 30, 34,
        195, 93, 115, 155, 220, 81, 20, 37, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82,
        83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95
       };
#else
    const uint32_t any_supported_param_set = XMSS_PARAM_SHA2_10_256;
    XmssNativeValue256 expected_root = { {
        0x9d898033, 0xe37af48e, 0x6a116f8b, 0x15651cc2, 0x67734670, 0x07ad1937, 0x5d38c23c, 0x690c3483
    } };
    /* Public key as exported from dotnet implementation: https://github.com/dorssel/dotnet-xmss/
      * with OID added manually. */
    uint8_t expected_pk[] = {
        0, 0, 0, 1, /* algorithm OID */
        157, 137, 128, 51, 227, 122, 244, 142, 106, 17, 111, 139, 21, 101, 28, 194, 103, 115, 70, 112, 7, 173, 25, 55,
        93, 56, 194, 60, 105, 12, 52, 131, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82,
        83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95
    };
#endif
    XmssValue256 expected_root_be;
    native_to_big_endian_256(&expected_root_be, &expected_root);
    success = success && xmss_context_initialize(&context_ptr_dynamic, any_supported_param_set, realloc, free, NULL);

    uint8_t random[32] = {0};
    uint8_t secure_random[96] = {0};

    for (size_t i = 0; i < sizeof(secure_random); i++) {
        secure_random[i] = (uint8_t)i;
    }

    XmssBuffer random_buffer = {sizeof(random), random};
    XmssBuffer secure_random_buffer = {sizeof(secure_random), secure_random};

    XmssKeyContext *key_context = NULL;
    XmssPrivateKeyStatelessBlob *stateless_blob = NULL;
    XmssPrivateKeyStatefulBlob *stateful_blob = NULL;
    XmssIndexObfuscationSetting index_obfuscation_setting = XMSS_INDEX_OBFUSCATION_ON;

    /* Call xmss_generate_private_key with some reasonable params. */
    success = success && xmss_generate_private_key(&key_context, &stateless_blob, &stateful_blob,
            &secure_random_buffer, index_obfuscation_setting, &random_buffer, context_ptr_dynamic) == XMSS_OKAY;

    XmssKeyGenerationContext *keygen_context = NULL;
    XmssPublicKeyInternalBlob *public_key_blob = NULL;
    XmssInternalCache *internal_cache = NULL;
    XmssInternalCache *generation_cache = NULL;
    const uint32_t num_partitions = 8;
    success = success && XMSS_OKAY ==
        xmss_generate_public_key(&keygen_context, &internal_cache, &generation_cache, key_context,
            XMSS_CACHE_TOP, 0, num_partitions);
    for (uint32_t i = 0; i < num_partitions; i++) {
            success = success && XMSS_OKAY == xmss_calculate_public_key_part(keygen_context, i);
    }
    success = success && XMSS_OKAY == xmss_finish_calculate_public_key(&public_key_blob, &keygen_context,
            key_context);
    success = success && (keygen_context == NULL);

    success = success && XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE(XMSS_CACHE_TOP, 0, any_supported_param_set) -
                            sizeof(XmssPublicKeyInternalBlob) == public_key_blob->data_size;
    success = success && keygen_context == NULL;
    XmssPublicKeyInternal *public_key_internal = (XmssPublicKeyInternal *)public_key_blob->data;
    if (success) {
        if (memcmp(&public_key_internal->root, &expected_root_be, sizeof(XmssValue256))) {
            success = false;
            printf("xmss_finish_calculate_public_key returned an unexpected result:\n");
            for (size_t i = 0; i < sizeof(XmssValue256); i++) {
                printf("%02x", public_key_internal->root.data[i]);
            }
            printf("\n");
            printf("Expected result:\n");
            for (size_t i = 0; i < sizeof(XmssValue256); i++) {
                printf("%02x", expected_root_be.data[i]);
            }
            printf("\n");
        }
    } else {
        printf("One of the public key generation functions failed.\n");
    }

    XmssPublicKey exported_public_key = { 0 };
    success = success && XMSS_OKAY == xmss_export_public_key(&exported_public_key, key_context);
    /* Check public key against expected public key. */
    success = success && memcmp(expected_pk, (uint8_t *)&exported_public_key, sizeof(XmssPublicKey)) == 0;

    /* Check public key against signing key_context. */
    success = success && XMSS_OKAY == xmss_verify_exported_public_key(&exported_public_key, key_context);

    xmss_free_key_context(key_context);
    free(stateless_blob);
    free(stateful_blob);
    free(context_ptr_dynamic);

    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
