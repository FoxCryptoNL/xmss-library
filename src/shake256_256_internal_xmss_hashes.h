/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * XMSS hash functions for SHAKE256/256 using the internal interface.
*/

#pragma once

#ifndef XMSS_SHAKE256_256_INTERNAL_XMSS_HASHES_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_SHAKE256_256_INTERNAL_XMSS_HASHES_H_INCLUDED

#include "config.h"

#if !XMSS_ENABLE_SHAKE256_256
#   error "SHAKE256/256 is disabled, so SHAKE256/256 related headers must not be included."
#endif
#if XMSS_ENABLE_SHAKE256_256_GENERIC
#   error "SHAKE256/256 uses generic interface, so SHAKE256/256 related internal headers must not be included."
#endif

#include "libxmss.h"
#include "xmss_hashes_base.h"

/**
 * @copydoc prototype_F
 * @see prototype_F
 *
 * @details
 * This is the specialization for the SHAKE256/256 algorithm using the internal interface.
 */
LIBXMSS_STATIC
void shake256_256_F(XmssNativeValue256 *native_digest, const Input_F *input);

/**
 * @copydoc prototype_H
 * @see prototype_H
 *
 * @details
 * This is the specialization for the SHAKE256/256 algorithm using the internal interface.
 */
LIBXMSS_STATIC
void shake256_256_H(XmssNativeValue256 *native_digest, const Input_H *input);

/**
 * @copydoc prototype_H_msg_init
 * @see prototype_H_msg_init
 *
 * @details
 * This is the specialization for the SHAKE256/256 algorithm using the internal interface.
 */
LIBXMSS_STATIC
void shake256_256_H_msg_init(XmssHMsgCtx *ctx, const Input_H_msg *input);

/**
 * @copydoc prototype_H_msg_update
 * @see prototype_H_msg_update
 *
 * @details
 * This is the specialization for the SHAKE256/256 algorithm using the internal interface.
 */
LIBXMSS_STATIC
void shake256_256_H_msg_update(XmssHMsgCtx *ctx, const uint8_t *part, size_t part_length,
    const uint8_t *volatile *part_verify);

/**
 * @copydoc prototype_H_msg_finalize
 * @see prototype_H_msg_finalize
 *
 * @details
 * This is the specialization for the SHAKE256/256 algorithm using the internal interface.
 */
LIBXMSS_STATIC
void shake256_256_H_msg_finalize(XmssNativeValue256 *native_digest, XmssHMsgCtx *ctx);

/**
 * @copydoc prototype_PRF
 * @see prototype_PRF
 *
 * @details
 * This is the specialization for the SHAKE256/256 algorithm using the internal interface.
 */
LIBXMSS_STATIC
void shake256_256_PRF(XmssNativeValue256 *native_digest, const Input_PRF *input);

#if XMSS_ENABLE_SIGNING

/**
 * @copydoc prototype_PRFkeygen
 * @see prototype_PRFkeygen
 *
 * @details
 * This is the specialization for the SHAKE256/256 algorithm using the internal interface.
 */
LIBXMSS_STATIC
void shake256_256_PRFkeygen(XmssNativeValue256 *native_digest, const Input_PRFkeygen *input);

/**
 * @copydoc prototype_PRFindex
 * @see prototype_PRFindex
 *
 * @details
 * This is the specialization for the SHAKE256/256 algorithm using the internal interface.
 */
LIBXMSS_STATIC
void shake256_256_PRFindex(XmssNativeValue256 *native_digest, const Input_PRFindex *input);

/**
 * @copydoc prototype_digest
 * @see prototype_digest
 *
 * @details
 * This is the specialization for the SHAKE256/256 algorithm using the internal interface.
 *
 * This function implements the SHAKE256($M$, 256) function as defined by NIST FIPS 202, Section 6.2.
 */
LIBXMSS_STATIC
void shake256_256_digest(XmssValue256 *digest, const uint8_t *message, size_t message_length);

/**
 * @copydoc prototype_native_digest
 * @see prototype_native_digest
 *
 * @details
 * This is the specialization for the SHAKE256/256 algorithm using the internal interface.
 */
LIBXMSS_STATIC
void shake256_256_native_digest(XmssNativeValue256 *native_digest, const uint32_t *words, size_t word_count);

#endif /* XMSS_ENABLE_SIGNING */

#endif /* !XMSS_SHAKE256_256_INTERNAL_XMSS_HASHES_H_INCLUDED */
