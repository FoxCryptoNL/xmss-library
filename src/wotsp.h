/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Max Fillinger
 */

/**
 * @file
 * @brief
 * WOTS+ signatures and verification.
 */

#pragma once

#ifndef XMSS_WOTSP_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_WOTSP_H_INCLUDED

#include <stdint.h>

#include "config.h"

#include "private.h"
#include "xmss_hashes.h"

/**
 * @brief
 * A WOTS+ public key.
 *
 * @details
 * See RFC 8391, Section 3.1.4.
 */
typedef struct {
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
typedef struct {
    /** @brief The hash values that make up the WOTS+ signature. */
    XmssNativeValue256 hashes[XMSS_WOTSP_LEN];
} WotspSignature;

/**
 * @brief
 * Generates the WOTS+ public key for the given seeds.
 *
 * @details
 * Based on NIST SP 800-208, Section 7.2.1, Algorithm 10' for the private key generation from the seeds,
 * and on RFC-8391, Section 3.1.4, Algorithm 4 for generating the public key from the private key.
 *
 * We only pass the OTS address from ADRS because all other parts of ADRS are either known or set during the
 * public key generation process.
 *
 * @param[in]  context      The signing context.
 * @param[out] public_key   The location to write the public key.
 * @param[in]  secret_seed  The secret seed for PRFkeygen.
 * @param[in]  public_seed  The public seed for PRF and PRFkeygen.
 * @param[in]  ots_address  Index of the OTS key pair in the larger XMSS scheme. (Part of ADRS in the RFC.)
*/
void wotsp_gen_public_key(const struct XmssSigningContext *restrict context,
    WotspPublicKey *restrict public_key,
    const XmssNativeValue256 *restrict secret_seed,
    const XmssNativeValue256 *restrict public_seed,
    uint32_t ots_address);

/**
 * @brief
 * Generates a WOTS+ signature for the given message digest.
 *
 * @details
 * Based on NIST SP 800-208, Section 7.2.1, Algorithm 10' for the private key generation from the seeds,
 * and on RFC-8391, Section 3.1.5, Algorithm 5 for the actual signing procedure.
 *
 * We only pass the OTS address from ADRS because all other parts of ADRS are either known or set during the
 * signing process.
 *
 * @param[in]  context      The signing context.
 * @param[out] signature    The location to write the signature.
 * @param[in]  message_digest   The message digest to sign.
 * @param[in]  secret_seed  The secret seed for PRFkeygen.
 * @param[in]  public_seed  The public seed for PRF and PRFkeygen.
 * @param[in]  ots_address  Index of the OTS key pair in the larger XMSS scheme. (Part of ADRS in the RFC.)
 */
void wotsp_sign(const struct XmssSigningContext *restrict context,
    WotspSignature *restrict signature,
    const XmssNativeValue256 *restrict message_digest,
    const XmssNativeValue256 *restrict secret_seed,
    const XmssNativeValue256 *restrict public_seed,
    uint32_t ots_address);

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
 * WOTS+ public key that was used in the XMSS hash tree, xmss_calculate_expected_public_key() will produce an output
 * that does not match the XMSS public key.
 *
 * We only pass the OTS address from ADRS because all other parts of ADRS are either known or set during the
 * verification process.
 *
 * @param[in]  hashes               The hash functions to use.
 * @param[out] expected_public_key  The location to write the public key that is consistent with the given parameters.
 * @param[in]  message_digest       The message digest to verify.
 * @param[in]  signature            The (purported) signature on the message digest.
 * @param[in]  public_seed          The public seed for PRF.
 * @param[in]  ots_address          Index of the OTS key pair in the larger XMSS scheme. (Part of ADRS in the RFC.)
 */
void wotsp_calculate_expected_public_key(HASH_ABSTRACTION(const xmss_hashes *restrict hashes)
    WotspPublicKey *restrict expected_public_key,
    const XmssNativeValue256 *restrict message_digest,
    const WotspSignature *restrict signature,
    const XmssNativeValue256 *restrict public_seed,
    uint32_t ots_address);

#endif /* !XMSS_WOTSP_H_INCLUDED */
