/*
 * SPDX-FileCopyrightText: 2022 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Thomas Schaap
 * SPDX-FileContributor: Frans van Dorsselaer
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

#include "opaque_structures.h"
#include "structures.h"
#include "types.h"

/**
 * @brief
 * Initialize a context for signature verification.
 *
 * @details
 * The context stores the pointers to the public key and the signature. It is the caller's responsibility to keep the
 * pointed-to objects available and constant for every call that uses the context.
 * To reduce memory usage, the objects themselves are not copied into the context.
 *
 * @param[out]  context     The context for the signature verification.
 * @param[in]   public_key  The public key to verify `signature` against.
 * @param[in]   signature   The signature over the message that needs to be verified.
 * @param[in]   signature_length    The length of `signature` in bytes.
 * @retval #XMSS_OKAY   `context` was initialized successfully.
 * @retval #XMSS_ERR_NULL_POINTER       A NULL pointer was passed.
 * @retval #XMSS_ERR_INVALID_ARGUMENT   The parameter set of `public_key` is not supported.
 * @retval #XMSS_ERR_INVALID_SIGNATURE  `signature` cannot be valid, either because the parameter set of `signature`
 *                                      does not match `public_key`, or `signature_length` is incorrect.
 */
XmssError xmss_verification_init(XmssVerificationContext *context, const XmssPublicKey *public_key,
    const XmssSignature *signature, size_t signature_length);

/**
 * @brief
 * Update the verification context with the next chunk of the message.
 *
 * @details
 * When it isn't practical to hold the entire message in memory, this function can be used to process the message in
 * chunks.
 *
 * When fault injection tolerance is required, provide a non-NULL `part_verify` parameter. After this function
 * completes successfully, compare the value returned in `*part_verify` with the original message `part` pointer.
 *
 * @param[in,out] context       The context for the verification.
 * @param[in]     part          The next part of the message. May be NULL if part_length is 0.
 * @param[in]     part_length   The length of `part` in bytes. For optimal performance, this should be a multiple of the
 *                              hash function's block size (64 bytes for SHA256, 136 for SHAKE256_256) if possible,
 *                              but this is not required.
 * @param[out]    part_verify   (optional, may be NULL) Outputs a copy of `part` to verify the correct message was
 *                              processed. This can be used to mitigate fault injections.
 * @retval #XMSS_OKAY   `context` was updated successfully.
 * @retval #XMSS_ERR_NULL_POINTER   A NULL pointer was passed.
 * @retval #XMSS_ERR_BAD_CONTEXT    Either `context` was not initialized correctly, or xmss_verification_check() was
 *                                  already called.
 * @retval #XMSS_ERR_FAULT_DETECTED A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
XmssError xmss_verification_update(XmssVerificationContext *context, const uint8_t *part, size_t part_length,
    const uint8_t *volatile *part_verify);

/**
 * @brief
 * Perform a single validation of the message signature.
 *
 * @details
 * When all message parts have been processed with xmss_verification_update(), this function performs a single
 * (non-redundant) validation of the signature. This function may be called multiple times to provide fault injection
 * tolerance.
 *
 * Provide the same pointer to the public key that was also provided to xmss_verification_init(). This function will
 * verify that the two copies of the pointer value match, such that a single pointer manipulation cannot be used by an
 * attacker to spoof the public key.
 *
 * @param[out]  context     The context for the signature verification.
 * @param[in]   public_key  The public key to verify the signature against. This is used to mitigate fault injection.
 * @retval #XMSS_OKAY   The signature is valid.
 * @retval #XMSS_ERR_NULL_POINTER       A NULL pointer was passed.
 * @retval #XMSS_ERR_BAD_CONTEXT        `context` was not initialized correctly.
 * @retval #XMSS_ERR_INVALID_SIGNATURE  The signature did not pass the verification.
 * @retval #XMSS_ERR_FAULT_DETECTED     A bit error was detected, or `public_key` does not match the public key provided
 *                                      to xmss_verification_init().
 *                                      (Note that bit errors can also cause different errors or segfaults.)
 */
XmssError xmss_verification_check(XmssVerificationContext *context, const XmssPublicKey *public_key);

#endif /* !XMSS_VERIFICATION_H_INCLUDED */
