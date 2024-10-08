/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Max Fillinger
 */

/**
 * @file
 * @brief
 * WOTS+ verification.
 */

#pragma once

#ifndef XMSS_WOTSP_VERIFICATION_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_WOTSP_VERIFICATION_H_INCLUDED

#include <stdint.h>

#include "libxmss.h"
#include "types.h"
#include "wotsp.h"
#include "xmss_hashes.h"

/**
 * @brief
 * Calculates the WOTS+ public key that is consistent with the given message, signature, seed and OTS address.
 *
 * @details
 * Based on RFC-8391, Section 3.1.6., Algorithm 6. If a message was signed with a given secret key and this algorithm
 * is applied to the message and signature, it outputs the public key that corresponds to that secret key, i.e., the
 * one that would be output by Algorithm 4 / wotsp_gen_public_key().
 *
 * A proper verification function for WOTS+ is not needed in XMSS. If the output of this function does not match the
 * WOTS+ public key that was used in the XMSS hash tree, xmss_verification_check() will fail.
 *
 * We only pass the OTS address from ADRS because all other parts of ADRS are either known or set during the
 * verification process.
 *
 * @param[in]  hash_functions       The hash functions to use.
 * @param[out] expected_public_key  The location to write the public key that is consistent with the given parameters.
 * @param[in]  message_digest       The message digest to verify.
 * @param[in]  signature            The (purported) signature on the message digest.
 * @param[in]  public_seed          The public seed for PRF.
 * @param[in]  ots_address          Index of the OTS key pair in the larger XMSS scheme. (Part of ADRS in the RFC.)
 *
 * @retval XMSS_OKAY                Expected public key was calculated successfully.
 * @retval XMSS_ERR_FAULT_DETECTED  A fault was detected.
 */
LIBXMSS_STATIC
XmssError wotsp_calculate_expected_public_key(HASH_FUNCTIONS_PARAMETER WotspPublicKey *expected_public_key,
    const XmssNativeValue256 *message_digest, const WotspSignature *signature, const XmssNativeValue256 *public_seed,
    uint32_t ots_address);

#endif /* !XMSS_WOTSP_VERIFICATION_H_INCLUDED */
