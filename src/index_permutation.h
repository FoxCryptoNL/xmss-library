/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Pepijn Westen
 */

/**
 * @file
 * @brief
 * Pseudo-random permutation of an XMSS key's index space.
 */

#pragma once

#ifndef XMSS_INDEX_PERMUTATION_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_INDEX_PERMUTATION_H_INCLUDED

#include "xmss_config.h"

#include "compat.h"
#include "libxmss.h"
#include "opaque_structures.h"
#include "signing_private.h"
#include "structures.h"
#include "types.h"
#include "xmss_hashes.h"

/**
 * @brief
 * Generate a pseudo-random permutation.
 *
 * @details
 * Generates a pseudo-random permutation with range [0, num_elements - 1], using a fisher-yates shuffle algorithm and
 * a pseudo-random generator based on PRFindex.
 * The resulting permutation is the same regardless of endianness.
 * The random number generation is based on a modified version of PRFKeygen.
 * @param[in]   hash_functions          The hash functions to use.
 * @param[out]  permutation             The array where the generated permutation will be stored.
 * @param[in]   num_elements            The number of elements for which to generate the permutation.
 * @param[in]   index_permutation_seed  The seed for the pseudorandom permutation generation.
 * @param[in]   SEED                    The public seed of the XMSS key.
 * @retval XMSS_OKAY The permutation was successfully generated.
 * @retval XMSS_ERR_NULL_POINTER permutation, index_permutation_seed or SEED was NULL.
*/
LIBXMSS_STATIC
XmssError generate_pseudorandom_permutation(HASH_FUNCTIONS_PARAMETER uint32_t *permutation,
    uint32_t num_elements, const XmssNativeValue256 *index_permutation_seed, const XmssNativeValue256 *SEED);

#endif /* !XMSS_INDEX_PERMUTATION_H_INCLUDED */
