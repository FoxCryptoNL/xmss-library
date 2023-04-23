/*
 * SPDX-FileCopyrightText: 2022 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Thomas Schaap
 */

/**
 * @file
 * @brief
 * Public API for the XMSS verification library.
 */

#pragma once

#ifndef XMSS_VERIFICATION_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_VERIFICATION_H_INCLUDED

#include "structures.h"
#include "types.h"

/**
 * @brief
 * Calculate the expected public key for a given message and signature.
 *
 * @details
 * This does not verify the correctness of the public key. Returning a single value to indicate 'good' or 'bad' is not
 * resilient enough for many use cases. Implementations can use the expected public key in a verification algorithm
 * that provides the level of resilience that meets their needs, ranging from a simple entirely non-resilient
 * memcmp() to a fully fault injection-proof check with multiple redundancies.
 *
 * The public key is still passed to this function, but only for the additional public data it contains. This data is
 * used to calculate both part of the signature and part of the public key that would verify the signature's
 * correctness.
 *
 * @param[out]  expected_public_key The 32-byte public key that would be calculated from the signature and the message.
 *                                  If and only if this matches the actual public key, then the signature is valid.
 * @param[in]   msg                 The arbitrary-length message to calculate the expected public key for.
 * @param[in]   pub_key             The public key to verify against. This is *not* used to actually verify the
 *                                  signature but contains (public) data that is needed to calculate the expected public
 *                                  key from the message.
 * @param[in]   signature           The signature over the message that needs to be verified.
 * @retval XMSS_OKAY    The calculation was successful. Note that this does not necessarily mean that the signature is
 *                      valid.
 * @retval XMSS_ERR_NULL_POINTER    A NULL pointer was passed.
 * @retval XMSS_ERR_INVALID_ARGUMENT    The scheme identifier in pub_key is not supported or invalid.
 * @retval XMSS_ERR_INVALID_BLOB        The data in pub_key or signature is not valid.
 */
XmssError xmss_calculate_expected_public_key(
    XmssValue256 *restrict expected_public_key, const XmssBuffer *restrict msg,
    const XmssPublicKeyBlob *restrict pub_key, const XmssSignatureBlob *restrict signature);

#endif /* !XMSS_VERIFICATION_H_INCLUDED */
