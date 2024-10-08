/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * XMSS hash functions for SHA-256 using the generic interface.
 */

#pragma once

#ifndef XMSS_SHA256_GENERIC_XMSS_HASHES_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_SHA256_GENERIC_XMSS_HASHES_H_INCLUDED

#include "config.h"

#if !XMSS_ENABLE_SHA256
#   error "SHA-256 is disabled, so SHA-256 related headers must not be included."
#endif
#if !XMSS_ENABLE_SHA256_GENERIC
#   error "SHA-256 uses internal interface, so SHA-256 related generic headers must not be included."
#endif

#include <stddef.h>
#include <stdint.h>

#include "generic_xmss_hashes.h"
#include "override_sha256_generic.h"
#include "types.h"

/**
 * @copydoc prototype_F
 * @see prototype_F
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the generic interface.
 */
static inline void sha256_F(XmssNativeValue256 *const native_digest, const Input_F *const input)
{
    generic_F(xmss_sha256_init, xmss_sha256_update, xmss_sha256_finalize, native_digest, input);
}

/**
 * @copydoc prototype_H
 * @see prototype_H
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the generic interface.
 */
static inline void sha256_H(XmssNativeValue256 *const native_digest, const Input_H *const input)
{
    generic_H(xmss_sha256_init, xmss_sha256_update, xmss_sha256_finalize, native_digest, input);
}

/**
 * @copydoc prototype_H_msg_init
 * @see prototype_H_msg_init
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the generic interface.
 */
static inline void sha256_H_msg_init(XmssHMsgCtx *const ctx, const Input_H_msg *const input)
{
    generic_H_msg_init(xmss_sha256_init, xmss_sha256_update, ctx, input);
}

/**
 * @copydoc prototype_H_msg_update
 * @see prototype_H_msg_update
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the generic interface.
 */
static inline void sha256_H_msg_update(XmssHMsgCtx *const ctx, const uint8_t *const part, const size_t part_length,
    const uint8_t *volatile *const part_verify)
{
    generic_H_msg_update(xmss_sha256_update, ctx, part, part_length, part_verify);
}

/**
 * @copydoc prototype_H_msg_finalize
 * @see prototype_H_msg_finalize
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the generic interface.
 */
static inline void sha256_H_msg_finalize(XmssNativeValue256 *const native_digest, XmssHMsgCtx *const ctx)
{
    generic_H_msg_finalize(xmss_sha256_finalize, native_digest, ctx);
}

/**
 * @copydoc prototype_PRF
 * @see prototype_PRF
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the generic interface.
 */
static inline void sha256_PRF(XmssNativeValue256 *const native_digest, const Input_PRF *const input)
{
    generic_PRF(xmss_sha256_init, xmss_sha256_update, xmss_sha256_finalize, native_digest, input);
}

#if XMSS_ENABLE_SIGNING

/**
 * @copydoc prototype_PRFkeygen
 * @see prototype_PRFkeygen
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the generic interface.
 */
static inline void sha256_PRFkeygen(XmssNativeValue256 *const native_digest, const Input_PRFkeygen *const input)
{
    generic_PRFkeygen(xmss_sha256_init, xmss_sha256_update, xmss_sha256_finalize, native_digest, input);
}

/**
 * @copydoc prototype_PRFindex
 * @see prototype_PRFindex
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the generic interface.
 */
static inline void sha256_PRFindex(XmssNativeValue256 *const native_digest, const Input_PRFindex *const input)
{
    generic_PRFindex(xmss_sha256_init, xmss_sha256_update, xmss_sha256_finalize, native_digest, input);
}

/**
 * @copydoc prototype_digest
 * @see prototype_digest
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the generic interface.
 *
 * This function implements the SHA-256($M$) function as defined by NIST FIPS 180-4, Section 6.2.
 */
static inline void sha256_digest(XmssValue256 *const digest, const uint8_t *const message, const size_t message_length)
{
    generic_digest(xmss_sha256_init, xmss_sha256_update, xmss_sha256_finalize, digest, message, message_length);
}

/**
 * @copydoc prototype_native_digest
 * @see prototype_native_digest
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the generic interface.
 */
static inline void sha256_native_digest(XmssNativeValue256 *const native_digest, const uint32_t *const words,
    const size_t word_count)
{
    generic_native_digest(xmss_sha256_init, xmss_sha256_update, xmss_sha256_finalize, native_digest, words, word_count);
}

#endif /* XMSS_ENABLE_SIGNING */

#endif /* !XMSS_SHA256_GENERIC_XMSS_HASHES_H_INCLUDED */
