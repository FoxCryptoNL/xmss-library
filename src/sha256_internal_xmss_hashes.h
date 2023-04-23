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
#include "override_sha256_internal.h"
#include "utils.h"
#include "xmss_hashes_base.h"

/**
 * @brief
 * The initial native SHA-256 hash value as defined by the standard.
 *
 * @details
 * See NIST FIPS 180-4, Section 5.3.3.
 */
extern const XmssNativeValue256 sha256_H0;

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
void sha256_process_message_final(XmssNativeValue256 *restrict native_digest, const uint8_t *restrict message,
    size_t message_length, uint_fast16_t prefix_length);

/**
 * @copydoc prototype_digest
 * @see prototype_digest
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the internal interface.
 *
 * This function implements the SHA-256($M$) function as defined by NIST FIPS 180-4, Section 6.2.
 */
static inline void sha256_digest(XmssValue256 *restrict digest, const uint8_t *restrict const message,
    const size_t message_length)
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
    native_256_copy(&native_digest, &sha256_H0);

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
void sha256_native_digest(XmssNativeValue256 *restrict native_digest, const uint32_t *restrict words,
    size_t word_count);

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
static inline void sha256_2_blocks(XmssNativeValue256 *restrict const native_digest,
    const uint32_t *restrict const input)
{
    native_256_copy(native_digest, &sha256_H0);
    sha256_process_block(native_digest, input);
    sha256_process_block(native_digest, input + TO_WORDS(SHA256_BLOCK_SIZE));
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
static inline void sha256_3_blocks(XmssNativeValue256 *restrict const native_digest,
    const uint32_t *restrict const input)
{
    native_256_copy(native_digest, &sha256_H0);
    sha256_process_block(native_digest, input);
    sha256_process_block(native_digest, input + TO_WORDS(SHA256_BLOCK_SIZE));
    sha256_process_block(native_digest, input + 2 * TO_WORDS(SHA256_BLOCK_SIZE));
}

/**
 * @copydoc prototype_F
 * @see prototype_F
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the internal interface.
 */
static inline void sha256_F(XmssNativeValue256 *restrict const native_digest, const Input_F *restrict const input)
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
static inline void sha256_H(XmssNativeValue256 *restrict const native_digest, const Input_H *restrict const input)
{
    sha256_3_blocks(native_digest, (const uint32_t *)input);
}

/**
 * @copydoc prototype_H_msg
 * @see prototype_H_msg
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the internal interface.
 */
static inline void sha256_H_msg(XmssNativeValue256 *restrict const native_digest, const Input_H_msg *restrict const input,
    const uint8_t *restrict const message, const size_t message_length)
{
    sha256_2_blocks(native_digest, (const uint32_t *)input);
    sha256_process_message_final(native_digest, message, message_length, sizeof(Input_H_msg));
}

/**
 * @copydoc prototype_PRF
 * @see prototype_PRF
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the internal interface.
 */
static inline void sha256_PRF(XmssNativeValue256 *restrict const native_digest, const Input_PRF *restrict const input)
{
    sha256_2_blocks(native_digest, (const uint32_t *)input);
}

/**
 * @copydoc prototype_PRFkeygen
 * @see prototype_PRFkeygen
 *
 * @details
 * This is the specialization for the SHA-256 algorithm using the internal interface.
 */
static inline void sha256_PRFkeygen(XmssNativeValue256 *restrict const native_digest,
    const Input_PRFkeygen *restrict const input)
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
static inline void sha256_PRFindex(XmssNativeValue256 *restrict const native_digest,
    const Input_PRFindex *restrict const input)
{
    sha256_3_blocks(native_digest, (const uint32_t *)input);
}

#endif /* !XMSS_SHA256_INTERNAL_XMSS_HASHES_H_INCLUDED */
