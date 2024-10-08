/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * XMSS hash functions for SHA-256 using the internal interface.
 */

#pragma once

#ifndef XMSS_SHA256_INTERNAL_XMSS_HASHES_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_SHA256_INTERNAL_XMSS_HASHES_H_INCLUDED

#include "config.h"

#if !XMSS_ENABLE_SHA256
#   error "SHA-256 is disabled, so SHA-256 related headers must not be included."
#endif
#if XMSS_ENABLE_SHA256_GENERIC
#   error "SHA-256 uses generic interface, so SHA-256 related internal headers must not be included."
#endif

#include <string.h>

#include "endianness.h"
#include "libxmss.h"
#include "override_sha256_internal.h"
#include "sha256_internal_H0.h"
#include "utils.h"
#include "xmss_hashes_base.h"

/**
 * @brief
 * Completes the intermediate hash value by processing the final message.
 *
 * @details
 * The input intermediate hash value may be
 * the result of processing complete message blocks (prefixes). The byte length of all previously processed blocks
 * must be provided, as the finalization of the SHA-256 digest requires the total input length.
 *
 * Input validation is omitted for performance reasons.
 *
 * @param[in,out] native_digest   On input, constains the intermediate hash value; on output contains the final
 *                                digest.
 * @param[in]   message   Input message; may be NULL if and only if message_length is 0.
 * @param[in]   message_length   Input message length in bytes.
 * @param[in]   prefix_length    Number of bytes already processed before calling this function; must be a multiple
 *                               of the block size (64 bytes).
 */
LIBXMSS_STATIC
void sha256_process_message_final(XmssNativeValue256 *native_digest, const uint8_t *message, size_t message_length,
    uint64_t prefix_length);

/**
 * @brief
 * Internal helper function for F(), H_msg(), and PRF().
 *
 * @details
 * Defined within this header file to enable inlining, if the compiler chooses to do so.
 *
 * @param[out] native_digest   Output of the (possibly intermediate) native hash value.
 * @param[in] input   Points to 32 uint32_t values, 2 SHA-256 blocks.
 */
static inline void sha256_2_blocks(XmssNativeValue256 *const native_digest, const uint32_t *const input)
{
    *native_digest = sha256_H0;
    xmss_sha256_process_block(native_digest, input);
    xmss_sha256_process_block(native_digest, input + TO_WORDS(SHA256_BLOCK_SIZE));
}

/**
 * @brief
 * Internal helper function for H(), PRFkeygen(), and PRFindex().
 *
 * @details
 * Defined within this header file to enable inlining, if the compiler chooses to do so.
 *
 * @param[out] native_digest   Output of the (possibly intermediate) native hash value.
 * @param[in] input   Points to 48 uint32_t values, 3 SHA-256 blocks.
 */
static inline void sha256_3_blocks(XmssNativeValue256 *const native_digest, const uint32_t *const input)
{
    *native_digest = sha256_H0;
    xmss_sha256_process_block(native_digest, input);
    xmss_sha256_process_block(native_digest, input + TO_WORDS(SHA256_BLOCK_SIZE));
    xmss_sha256_process_block(native_digest, input + 2 * TO_WORDS(SHA256_BLOCK_SIZE));
}

/**
 * @copydoc prototype_F
 * @see prototype_F
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the internal interface.
 */
static inline void sha256_F(XmssNativeValue256 *const native_digest, const Input_F *const input)
{
    sha256_2_blocks(native_digest, (const uint32_t *)input);
}

/**
 * @copydoc prototype_H
 * @see prototype_H
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the internal interface.
 */
static inline void sha256_H(XmssNativeValue256 *const native_digest, const Input_H *const input)
{
    sha256_3_blocks(native_digest, (const uint32_t *)input);
}

/**
 * @copydoc prototype_H_msg_init
 * @see prototype_H_msg_init
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the internal interface.
 */
static inline void sha256_H_msg_init(XmssHMsgCtx *const ctx, const Input_H_msg *const input)
{
    sha256_2_blocks(&ctx->sha256_ctx.intermediate_hash, (const uint32_t *)input);
    ctx->sha256_ctx.bytes_in_partial_block.value = 0;
    ctx->sha256_ctx.bytes_hashed = sizeof(Input_H_msg);
}

/**
 * @copydoc prototype_H_msg_update
 * @see prototype_H_msg_update
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the internal interface.
 */
LIBXMSS_STATIC
void sha256_H_msg_update(XmssHMsgCtx *ctx, const uint8_t *part, size_t part_length,
    const uint8_t *volatile *part_verify);

/**
 * @copydoc prototype_H_msg_finalize
 * @see prototype_H_msg_finalize
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the internal interface.
 */
static inline void sha256_H_msg_finalize(XmssNativeValue256 *const native_digest, XmssHMsgCtx *const ctx)
{
    sha256_process_message_final(&ctx->sha256_ctx.intermediate_hash, ctx->sha256_ctx.partial_block,
        ctx->sha256_ctx.bytes_in_partial_block.value, ctx->sha256_ctx.bytes_hashed);
    *native_digest = ctx->sha256_ctx.intermediate_hash;
}

/**
 * @copydoc prototype_PRF
 * @see prototype_PRF
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the internal interface.
 */
static inline void sha256_PRF(XmssNativeValue256 *const native_digest, const Input_PRF *const input)
{
    sha256_2_blocks(native_digest, (const uint32_t *)input);
}

#if XMSS_ENABLE_SIGNING

/**
 * @copydoc prototype_PRFkeygen
 * @see prototype_PRFkeygen
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the internal interface.
 */
static inline void sha256_PRFkeygen(XmssNativeValue256 *const native_digest, const Input_PRFkeygen *const input)
{
    sha256_3_blocks(native_digest, (const uint32_t *)input);
}

/**
 * @copydoc prototype_PRFindex
 * @see prototype_PRFindex
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the internal interface.
 */
static inline void sha256_PRFindex(XmssNativeValue256 *const native_digest, const Input_PRFindex *const input)
{
    sha256_3_blocks(native_digest, (const uint32_t *)input);
}

/**
 * @copydoc prototype_digest
 * @see prototype_digest
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the internal interface.
 *
 * This function implements the SHA-256($M$) function as defined by NIST FIPS 180-4, Section 6.2.
 */
static inline void sha256_digest(XmssValue256 *digest, const uint8_t *const message, const size_t message_length)
{
    /*
     * See: NIST FIPS 180-4, Section 6.2
     *
     * This function handles:
     *   - NIST FIPS 180-4, Section 6.2.1: SHA-256 Preprocessing
     *   - NIST FIPS 180-4, Section 6.2.2: SHA-256 Hash Computation (outer loop)
     */

    /* initialization postponed for performance reasons */
    XmssNativeValue256 native_digest;

    /* See NIST FIPS 180-4, Section 6.2.1, Step 1 */
    native_digest = sha256_H0;

    sha256_process_message_final(&native_digest, message, message_length, 0);

    /* See NIST FIPS 180-4, Section 6.2.2. */
    native_to_big_endian_256(digest, &native_digest);
}

/**
 * @copydoc prototype_native_digest
 * @see prototype_native_digest
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the internal interface.
 */
LIBXMSS_STATIC
void sha256_native_digest(XmssNativeValue256 *native_digest, const uint32_t *words, size_t word_count);

#endif /* XMSS_ENABLE_SIGNING */

#endif /* !XMSS_SHA256_INTERNAL_XMSS_HASHES_H_INCLUDED */
