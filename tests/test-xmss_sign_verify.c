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
#include "verification.h"

/*
 * Run sign and verify test, in which a single signature is generated and verified as a sanity check.
 * Generates a key for the provided parameter set, places a signature and verifies that the signature verifies.
*/
static bool sign_verify_test(XmssParameterSetOID test_parameter_set)
{
    bool success = true;

    XmssSigningContext *context_ptr_dynamic = NULL;
    XmssKeyContext *key_context = NULL;
    XmssPrivateKeyStatelessBlob *stateless_blob = NULL;
    XmssPrivateKeyStatefulBlob *stateful_blob = NULL;
    XmssKeyGenerationContext *keygen_context = NULL;
    XmssPublicKeyInternalBlob *public_key_blob = NULL;
    XmssInternalCache *internal_cache = NULL;
    XmssInternalCache *generation_cache = NULL;
    XmssPublicKey exported_public_key = { 0 };
    XmssSignatureBlob *signature_blob = NULL;

    success = success && xmss_context_initialize(&context_ptr_dynamic, test_parameter_set, realloc, free, NULL);

    uint8_t random[32] = {0};
    uint8_t secure_random[96] = {0};

    for (size_t i = 0; i < sizeof(secure_random); i++) {
        secure_random[i] = (uint8_t)i;
    }

    XmssBuffer random_buffer = {sizeof(random), random};
    XmssBuffer secure_random_buffer = {sizeof(secure_random), secure_random};

    XmssIndexObfuscationSetting index_obfuscation_setting = XMSS_INDEX_OBFUSCATION_OFF;

    /* Call xmss_generate_private_key with some reasonable params. */
    success = success && xmss_generate_private_key(&key_context, &stateless_blob, &stateful_blob,
            &secure_random_buffer, index_obfuscation_setting, &random_buffer, context_ptr_dynamic) == XMSS_OKAY;

    success = success && XMSS_OKAY == xmss_generate_public_key(&keygen_context, &internal_cache, &generation_cache,
            key_context, XMSS_CACHE_TOP, 0, 1);
    success = success && XMSS_OKAY == xmss_calculate_public_key_part(keygen_context, 0);
    success = success && XMSS_OKAY == xmss_finish_calculate_public_key(&public_key_blob, &keygen_context,
            key_context);
    success = success && (keygen_context == NULL);

    success = success && XMSS_OKAY == xmss_export_public_key(&exported_public_key, key_context);
    success = success && XMSS_OKAY == xmss_request_future_signatures(&stateful_blob, key_context, 1);

    // The message, 10 * the maximum block size (136 for SHAKE)
    uint8_t message_buffer[10 * 136];
    for (size_t i = 0; i < sizeof(message_buffer); ++i) {
        // some "random" stuff, doesn't really matter
        message_buffer[i] = (uint8_t)((13 + 31 * i) & 0xff);
    }
    XmssBuffer message = {sizeof(message_buffer), message_buffer};

    // Sign the message
    success = success && XMSS_OKAY == xmss_sign_message(&signature_blob, key_context, &message);

    // Verify that the signature verifies
    XmssVerificationContext verification_ctx = {0};
    XmssSignature *signature = xmss_get_signature_struct(signature_blob);
    const uint8_t *volatile part_verify = NULL;
    success = success && XMSS_OKAY == xmss_verification_init(&verification_ctx, &exported_public_key, signature,
        signature_blob->data_size);
    success = success && XMSS_OKAY == xmss_verification_update(&verification_ctx, message.data, message.data_size,
        &part_verify);
    success = success && part_verify == message.data;
    success = success && XMSS_OKAY == xmss_verification_check(&verification_ctx, &exported_public_key);
    // redundant, for fault tolerance
    success = success && XMSS_OKAY == xmss_verification_check(&verification_ctx, &exported_public_key);

    // Verify message with different "corner case" part sizes (block size SHA256: 64, SHAKE256/256: 136)
    // We'll test every combination of first part size + part size for the remainder (i.e., this is 400+ test cases).
    size_t part_sizes[] = {
        0,
        1,
        2,
        64 - 2,
        64 - 1,
        64,
        64 + 1,
        64 + 2,
        136 - 2,
        136 - 1,
        136,
        136 + 1,
        136 + 2,
        2 * 64 - 2,
        2 * 64 - 1,
        2 * 64,
        2 * 64 + 1,
        2 * 64 + 2,
        2 * 136 - 2,
        2 * 136 - 1,
        2 * 136,
        2 * 136 + 1,
        2 * 136 + 2,
        sizeof(message_buffer) - 2,
        sizeof(message_buffer) - 1,
    };
    for (size_t first_index = 0; first_index < sizeof(part_sizes) / sizeof(size_t); ++first_index) {
        // We need to skip size 0 for the remaining parts
        for (size_t other_index = 1; other_index < sizeof(part_sizes) / sizeof(size_t); ++other_index) {
            const uint8_t *part = message.data;
            size_t remaining = message.data_size;
            // size of the first part
            size_t part_size = part_sizes[first_index];

            success = success && XMSS_OKAY == xmss_verification_init(&verification_ctx, &exported_public_key, signature,
                signature_blob->data_size);
            while (remaining > 0) {
                if (part_size > remaining) {
                    // we've reached the end, this is the final part
                    part_size = remaining;
                }

                success = success && XMSS_OKAY == xmss_verification_update(&verification_ctx, part, part_size,
                    &part_verify);
                success = success && part_verify == part;

                part += part_size;
                remaining -= part_size;
                // size of the remaining parts, if any
                part_size = part_sizes[other_index];
            }
            success = success && XMSS_OKAY == xmss_verification_check(&verification_ctx, &exported_public_key);
            // redundant, for fault tolerance
            success = success && XMSS_OKAY == xmss_verification_check(&verification_ctx, &exported_public_key);
        }
    }

    free(signature_blob);
    free(keygen_context);
    xmss_free_key_context(key_context);
    free(public_key_blob);
    free(stateless_blob);
    free(stateful_blob);
    free(context_ptr_dynamic);
    free(internal_cache);
    free(generation_cache);

    return success;
}

int main(void)
{
    bool success = true;

#if XMSS_ENABLE_SHA256
    success = success && sign_verify_test(XMSS_PARAM_SHA2_10_256);
#endif
#if XMSS_ENABLE_SHAKE256_256
    success = success && sign_verify_test(XMSS_PARAM_SHAKE256_10_256);
#endif
#if (!XMSS_ENABLE_SHA256) && (!XMSS_ENABLE_SHAKE256_256)
# error "Invalid configuration"
#endif

    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
