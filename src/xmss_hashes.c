/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * Abstraction layer for the XMSS hash functions.
 */

#include "config.h"

#include "xmss_hashes.h"

#if XMSS_ENABLE_HASH_ABSTRACTION
# if XMSS_ENABLE_SHA256
#  include "sha256_xmss_hashes.h"
# endif

# if XMSS_ENABLE_SHAKE256_256
#  include "shake256_256_xmss_hashes.h"
# endif
#endif

#include "structures.h"

XmssError xmss_get_hash_functions(
#if XMSS_ENABLE_HASH_ABSTRACTION
    const xmss_hashes **const hash_functions,
#endif
    const XmssParameterSetOID parameter_set)
{
#if XMSS_ENABLE_HASH_ABSTRACTION
    if (hash_functions == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }
#endif

    switch (parameter_set) {
        case XMSS_PARAM_SHA2_10_256:
        case XMSS_PARAM_SHA2_16_256:
        case XMSS_PARAM_SHA2_20_256:
# if XMSS_ENABLE_SHA256
#  if XMSS_ENABLE_HASH_ABSTRACTION
            *hash_functions = &sha256_xmss_hashes;
#  endif
# else
            /* The parameter set is not supported. */
            return XMSS_ERR_INVALID_ARGUMENT;
# endif
            break;

        case XMSS_PARAM_SHAKE256_10_256:
        case XMSS_PARAM_SHAKE256_16_256:
        case XMSS_PARAM_SHAKE256_20_256:
# if XMSS_ENABLE_SHAKE256_256
#  if XMSS_ENABLE_HASH_ABSTRACTION
            *hash_functions = &shake256_256_xmss_hashes;
#  endif
# else
            /* The parameter set is not supported. */
            return XMSS_ERR_INVALID_ARGUMENT;
# endif
            break;

        default:
            /* The parameter set is invalid. */
            return XMSS_ERR_INVALID_ARGUMENT;
    }

    return XMSS_OKAY;
}
