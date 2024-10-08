/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Max Fillinger
 */

/**
 * @file
 * @brief
 * WOTS+ common functionality.
 */

#pragma once

#ifndef XMSS_WOTSP_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_WOTSP_H_INCLUDED

#include <stdint.h>

#include "libxmss.h"
#include "types.h"
#include "xmss_hashes.h"

/**
 * @brief
 * The number of digests in a WOTS+ private or uncompressed public key.
 *
 * @details
 * This holds for all supported parameter sets, see RFC 8391, Section 5.2 and NIST SP 800-208, Section 5.1 and 5.3.
 */
#define XMSS_WOTSP_LEN 67

/**
 * @brief
 * A WOTS+ public key.
 *
 * @details
 * See RFC 8391, Section 3.1.4.
 */
typedef struct WotspPublicKey {
    /** @brief The hash values that make up the WOTS+ public key. */
    XmssNativeValue256 hashes[XMSS_WOTSP_LEN];
} WotspPublicKey;

/**
 * @brief
 * A WOTS+ signature.
 *
 * @details
 * See RFC 8391, Section 3.1.5.
 */
typedef struct WotspSignature {
    /** @brief The hash values that make up the WOTS+ signature. */
    XmssNativeValue256 hashes[XMSS_WOTSP_LEN];
} WotspSignature;

/**
 * @brief
 * Chaining function for WOTS+ signatures and verification.
 *
 * @details
 * Based on RFC-8391, Section 3.1.2. (Algorithm 2) with the following changes:
 *  - for-loop instead of recursive calls
 *  - instead of SEED and ADRS, pass an Input_PRF struct pre-filled with these values, because most of it does not
 *    change between chain calls within one public key generation, signing or verification process.
 *
 * @param[in]     hash_functions    The hash functions to use.
 * @param[out]    output        Output.
 * @param[in,out] input_prf     Input_PRF struct filled with the PRF seed and ADRS.
 *                              At the end of this function, the values of the hash_address and keyAndMask fields in
 *                              ADRS are unspecified. The Input_PRF can still be used for further calls to chain(),
 *                              since it initializes those fields to the correct values.
 * @param[in]     input         Input. (Corresponds to X in Algorithm 2.)
 * @param[in]     start_index   Starting index for the chain. (Corresponds to i in Algorithm 2.)
 * @param[in]     num_steps     Number of chain steps to perform. (Corresponds to s in Algorithm 2.)
 *
 * @returns the number of chain steps performed, used for detecting faults. Must equal num_steps.
 */
LIBXMSS_STATIC
uint_fast8_t chain(HASH_FUNCTIONS_PARAMETER XmssNativeValue256 *output, Input_PRF *input_prf,
    const XmssNativeValue256 *input, uint32_t start_index, uint_fast8_t num_steps);

#endif /* !XMSS_WOTSP_H_INCLUDED */
