/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Pepijn Westen
 */

/**
 * @file
 * @brief
 * XMSS randomized tree hashing primitive.
 */

#pragma once

#ifndef XMSS_XMSS_RAND_HASH_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_XMSS_RAND_HASH_H_INCLUDED

#include "libxmss.h"
#include "xmss_hashes.h"

/**
 * @brief
 * Implementation of Randomized Tree Hashing (RFC 8391 section 4.1.4).
 *
 * @warning The caller is responsible for providing valid pointers. For performance reasons these will not be checked.
 *
 * @param[in]       hash_functions  The hash functions to use.
 * @param[out]      digest_out      The randomized hash digest.
 * @param[in,out]   rand_hash_state Structure containing the SEED and the ADRS for this operation.
 *                                  The keyAndMask of the address is written by this function.
 * @param[in]       left            The left input node. May alias with digest_out but not with right.
 * @param[in]       right           The right input node. May alias with digest_out but not with left.
 */
LIBXMSS_STATIC
void rand_hash(HASH_FUNCTIONS_PARAMETER XmssNativeValue256 *digest_out, Input_PRF *rand_hash_state,
    const XmssNativeValue256 *left, const XmssNativeValue256 *right);

#endif /* !XMSS_XMSS_RAND_HASH_H_INCLUDED */
