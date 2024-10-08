/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#include <stdlib.h>

#include "errors.h"
#include "verification.h"
#include "version.h"
#if XMSS_ENABLE_SIGNING
#   include "signing.h"
#endif


int main(void)
{
    (void)xmss_error_to_description(XMSS_OKAY);
    (void)xmss_error_to_name(XMSS_OKAY);
    (void)xmss_library_get_version();
    (void)xmss_verification_check(NULL, NULL);
    (void)xmss_verification_init(NULL, NULL, NULL, 0);
    (void)xmss_verification_update(NULL, NULL, 0, NULL);

#if XMSS_ENABLE_SIGNING
    (void)xmss_calculate_public_key_part(NULL, 0);
    (void)xmss_context_initialize(NULL, XMSS_PARAM_SHA2_10_256, NULL, NULL, NULL);
    (void)xmss_export_public_key(NULL, NULL);
    (void)xmss_finish_calculate_public_key(NULL, NULL, NULL);
    (void)xmss_free_key_context(NULL);
    (void)xmss_free_key_generation_context(NULL);
    (void)xmss_free_signing_context(NULL);
    (void)xmss_generate_private_key(NULL, NULL, NULL, NULL, XMSS_INDEX_OBFUSCATION_OFF, NULL, NULL);
    (void)xmss_generate_public_key(NULL, NULL, NULL, NULL,XMSS_CACHE_NONE, 0, 0);
    (void)xmss_get_caching_in_public_key(NULL, NULL, NULL);
    (void)xmss_get_signature_count(NULL, NULL, NULL);
    (void)xmss_load_private_key(NULL, NULL, NULL, NULL);
    (void)xmss_load_public_key(NULL, NULL, NULL);
    (void)xmss_merge_signature_space(NULL, NULL, NULL);
    (void)xmss_partition_signature_space(NULL, NULL, NULL, 0);
    (void)xmss_request_future_signatures(NULL, NULL, 0);
    (void)xmss_sign_message(NULL, NULL, NULL);
    (void)xmss_verify_exported_public_key(NULL, NULL);
    (void)xmss_verify_public_key(NULL, NULL, NULL);
    (void)xmss_verify_private_key_stateless(NULL, NULL);
    (void)xmss_verify_private_key_stateful(NULL, NULL, NULL, NULL);
#endif

    return EXIT_SUCCESS;
}
