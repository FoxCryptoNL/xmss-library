/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Pepijn Westen
 */

#include <stdlib.h>
#include <stdbool.h>

#include "config.h"
#include "signing.h"

int main(void)
{
    bool success = true;

    XmssSigningContext *context_ptr_dynamic = NULL;

#if XMSS_ENABLE_SHA256
    const uint32_t any_supported_param_set = XMSS_PARAM_SHA2_10_256;
#else
    const uint32_t any_supported_param_set = XMSS_PARAM_SHAKE256_10_256;
#endif
    success = success && xmss_context_initialize(&context_ptr_dynamic, any_supported_param_set, realloc, free, NULL);

    uint8_t random[32] = {0};
    uint8_t secure_random[96] = {0};

    XmssBuffer random_buffer = {sizeof(random), random};
    XmssBuffer secure_random_buffer = {sizeof(secure_random), secure_random};

    XmssKeyContext *key_context = NULL;
    XmssPrivateKeyStatelessBlob *stateless_blob = NULL;
    XmssPrivateKeyStatefulBlob *stateful_blob = NULL;
    XmssIndexObfuscationSetting index_obfuscation_setting = XMSS_INDEX_OBFUSCATION_ON;

    context_ptr_dynamic = NULL;
    success = success && xmss_context_initialize(&context_ptr_dynamic, any_supported_param_set, realloc, free, NULL);

    // call xmss_generate_private_key with some reasonable params
    success = success && XMSS_OKAY == xmss_generate_private_key(&key_context, &stateless_blob, &stateful_blob,
            &secure_random_buffer, index_obfuscation_setting, &random_buffer, context_ptr_dynamic);

    key_context = NULL;
    /* Test that the generated blobs can be loaded again successfully. */
    success = success && XMSS_OKAY == xmss_load_private_key(&key_context, stateless_blob, stateful_blob,
        context_ptr_dynamic);

    xmss_free_key_context(key_context);
    free(stateless_blob);
    free(stateful_blob);
    free(context_ptr_dynamic);

     return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
