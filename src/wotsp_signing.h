/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Max Fillinger
 */

/**
 * @file
 * @brief
 * WOTS+ signatures.
 */

#pragma once

#ifndef XMSS_WOTSP_SIGNING_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_WOTSP_SIGNING_H_INCLUDED

#include <stdint.h>

#include "config.h"

#include "libxmss.h"
#include "signing_private.h"
#include "wotsp.h"
#include "xmss_hashes.h"

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
LIBXMSS_STATIC
void wotsp_gen_public_key(const XmssSigningContext *context, WotspPublicKey *public_key,
    const XmssNativeValue256 *secret_seed, const XmssNativeValue256 *public_seed, uint32_t ots_address);

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
 *
 * @retval XMSS_OKAY                The message was signed successfully.
 * @retval XMSS_ERR_FAULT_DETECTED  A fault was detected.
 */
LIBXMSS_STATIC
XmssError wotsp_sign(const XmssSigningContext *context, WotspSignature *signature,
    const XmssNativeValue256 *message_digest, const XmssNativeValue256 *secret_seed,
    const XmssNativeValue256 *public_seed, uint32_t ots_address);

#endif /* !XMSS_WOTSP_SIGNING_H_INCLUDED */
