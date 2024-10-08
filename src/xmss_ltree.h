/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Pepijn Westen
 */

/**
 * @file
 * @brief
 * XMSS L-Tree hashing.
 */

#pragma once

#ifndef XMSS_XMSS_LTREE_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_XMSS_LTREE_H_INCLUDED

#include "libxmss.h"
#include "types.h"
#include "wotsp.h"
#include "xmss_hashes.h"


/**
 * @brief
 * Compresses WOTS+ public key. Implementation of L-Tree function from RFC 8391 section 4.1.5.
 *
 * @warning The caller is responsible for providing valid pointers. For performance reasons these will not be checked.
 * @warning the compression is done in-place to conserve memory, so the public key is mangled by this function.
 *
 * @param[in]       hash_functions  The hash functions to use.
 * @param[out]      output          The result of the L-tree computation.
 * @param[in,out]   pk              The public key, which will be overwritten during compression.
 * @param[in,out]   adrs            The adrs structure for this ltree operation. Address type must be set by caller.
 * @param[in]       seed            The public seed in native-endian form.
 */
LIBXMSS_STATIC
void xmss_ltree(HASH_FUNCTIONS_PARAMETER XmssNativeValue256 *output, WotspPublicKey *pk, ADRS *adrs,
    const XmssNativeValue256 *seed);

#endif /* !XMSS_XMSS_LTREE_H_INCLUDED */
