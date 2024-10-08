/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * XMSS hash functions using the generic interface.
 */

#pragma once

#ifndef XMSS_GENERIC_XMSS_HASHES_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_GENERIC_XMSS_HASHES_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "endianness.h"
#include "generic_digest.h"
#include "xmss_hashes_base.h"

/**
 * @copydoc prototype_F
 * @param[in] init       The initialize function for the digest.
 * @param[in] update     The update function for the digest.
 * @param[in] finalize   The finalize function for the digest.
 *
 * @see prototype_digest
 *
 * @details
 * This is the specialization using the generic interface.
 */
static inline void generic_F(const XmssGenericDigestInit init, const XmssGenericDigestUpdate update,
    const XmssGenericDigestFinalize finalize, XmssNativeValue256 *const native_digest, const Input_F *const input)
{
    void *context = init();
    uint8_t input_big_endian[96];
    native_to_big_endian(input_big_endian, (const uint32_t *)input, 24);
    update(context, input_big_endian, 96);
    finalize(context, (XmssValue256 *)native_digest);
    inplace_big_endian_to_native_256(native_digest);
}

/**
 * @copydoc prototype_H
 * @param[in] init       The initialize function for the digest.
 * @param[in] update     The update function for the digest.
 * @param[in] finalize   The finalize function for the digest.
 *
 * @see prototype_digest
 *
 * @details
 * This is the specialization using the generic interface.
 */
static inline void generic_H(const XmssGenericDigestInit init, const XmssGenericDigestUpdate update,
    const XmssGenericDigestFinalize finalize, XmssNativeValue256 *const native_digest, const Input_H *const input)
{
    void *context = init();
    uint8_t input_big_endian[128];
    native_to_big_endian(input_big_endian, (const uint32_t *)input, 32);
    update(context, input_big_endian, 128);
    finalize(context, (XmssValue256 *)native_digest);
    inplace_big_endian_to_native_256(native_digest);
}

/**
 * @copydoc prototype_H_msg_init
 * @param[in] init       The initialize function for the digest.
 * @param[in] update     The update function for the digest.
 *
 * @see prototype_H_msg_init
 *
 * @details
 * This is the specialization using the generic interface.
 */
static inline void generic_H_msg_init(const XmssGenericDigestInit init, const XmssGenericDigestUpdate update,
    XmssHMsgCtx *const ctx, const Input_H_msg *const input)
{
    ctx->generic_ctx = init();
    uint8_t input_big_endian[128];
    native_to_big_endian(input_big_endian, (const uint32_t *)input, 32);
    update(ctx->generic_ctx, input_big_endian, 128);
}

/**
 * @copydoc prototype_H_msg_update
 * @param[in] update     The update function for the digest.
 *
 * @see prototype_H_msg_update
 *
 * @details
 * This is the specialization using the generic interface.
 */
static inline void generic_H_msg_update(const XmssGenericDigestUpdate update, XmssHMsgCtx *const ctx,
    const uint8_t *const part, const size_t part_length, const uint8_t *volatile *const part_verify)
{
    const uint8_t *volatile const volatile_part = part;
    update(ctx->generic_ctx, volatile_part, part_length);
    if (part_verify != NULL)
    {
        *part_verify = volatile_part;
    }
}

/**
 * @copydoc prototype_H_msg_finalize
 * @param[in] finalize   The finalize function for the digest.
 *
 * @see prototype_H_msg_finalize
 *
 * @details
 * This is the specialization using the generic interface.
 */
static inline void generic_H_msg_finalize(const XmssGenericDigestFinalize finalize,
    XmssNativeValue256 *const native_digest, XmssHMsgCtx *const ctx)
{
    /* We place the big-endian digest in native_digest, then reorder it in-place. */
    finalize(ctx->generic_ctx, (XmssValue256 *)native_digest);
    inplace_big_endian_to_native_256(native_digest);
}

/**
 * @copydoc prototype_PRF
 * @param[in] init       The initialize function for the digest.
 * @param[in] update     The update function for the digest.
 * @param[in] finalize   The finalize function for the digest.
 *
 * @see prototype_digest
 *
 * @details
 * This is the specialization using the generic interface.
 */
static inline void generic_PRF(const XmssGenericDigestInit init, const XmssGenericDigestUpdate update,
    const XmssGenericDigestFinalize finalize, XmssNativeValue256 *const native_digest, const Input_PRF *const input)
{
    void *context = init();
    uint8_t input_big_endian[96];
    native_to_big_endian(input_big_endian, (const uint32_t *)input, 24);
    update(context, input_big_endian, 96);
    finalize(context, (XmssValue256 *)native_digest);
    inplace_big_endian_to_native_256(native_digest);
}

#if XMSS_ENABLE_SIGNING

/**
 * @copydoc prototype_PRFkeygen
 * @param[in] init       The initialize function for the digest.
 * @param[in] update     The update function for the digest.
 * @param[in] finalize   The finalize function for the digest.
 *
 * @see prototype_digest
 *
 * @details
 * This is the specialization using the generic interface.
 */
static inline void generic_PRFkeygen(const XmssGenericDigestInit init, const XmssGenericDigestUpdate update,
    const XmssGenericDigestFinalize finalize, XmssNativeValue256 *const native_digest,
    const Input_PRFkeygen *const input)
{
    void *context = init();
    uint8_t input_big_endian[128];
    native_to_big_endian(input_big_endian, (const uint32_t *)input, 32);
    update(context, input_big_endian, 128);
    finalize(context, (XmssValue256 *)native_digest);
    inplace_big_endian_to_native_256(native_digest);
}

/**
 * @copydoc prototype_PRFindex
 * @param[in] init       The initialize function for the digest.
 * @param[in] update     The update function for the digest.
 * @param[in] finalize   The finalize function for the digest.
 *
 * @see prototype_digest
 *
 * @details
 * This is the specialization using the generic interface.
 */
static inline void generic_PRFindex(const XmssGenericDigestInit init, const XmssGenericDigestUpdate update,
    const XmssGenericDigestFinalize finalize, XmssNativeValue256 *const native_digest,
    const Input_PRFindex *const input)
{
    void *context = init();
    uint8_t input_big_endian[128];
    native_to_big_endian(input_big_endian, (const uint32_t *)input, 32);
    update(context, input_big_endian, 128);
    finalize(context, (XmssValue256 *)native_digest);
    inplace_big_endian_to_native_256(native_digest);
}

/**
 * @copydoc prototype_digest
 * @param[in] init       The initialize function for the digest.
 * @param[in] update     The update function for the digest.
 * @param[in] finalize   The finalize function for the digest.
 *
 * @see prototype_digest
 *
 * @details
 * This is the specialization using the generic interface.
 */
static inline void generic_digest(const XmssGenericDigestInit init, const XmssGenericDigestUpdate update,
    const XmssGenericDigestFinalize finalize, XmssValue256 *const digest, const uint8_t *const message,
    const size_t message_length)
{
    void *context = init();
    update(context, message, message_length);
    finalize(context, digest);
}

/**
 * @copydoc prototype_native_digest
 * @param[in] init       The initialize function for the digest.
 * @param[in] update     The update function for the digest.
 * @param[in] finalize   The finalize function for the digest.
 *
 * @see prototype_native_digest
 *
 * @details
 * This is the specialization using the generic interface.
 */
static inline void generic_native_digest(const XmssGenericDigestInit init, const XmssGenericDigestUpdate update,
    const XmssGenericDigestFinalize finalize, XmssNativeValue256 *const native_digest, const uint32_t *words,
    size_t word_count)
{
    void *context = init();
    /* Optimized for SHA-256 block size, but also works for SHAKE256/256. */
    uint8_t block[64];
    /* full blocks */
    while (word_count >= 16) {
        native_to_big_endian(block, words, 16);
        update(context, block, 64);
        word_count -= 16;
        words += 16;
    }
    /* remainder */
    native_to_big_endian(block, words, word_count);
    update(context, block, word_count * 4);
    finalize(context, (XmssValue256 *)native_digest);
    inplace_big_endian_to_native_256(native_digest);
}

#endif /* XMSS_ENABLE_SIGNING */

#endif /* !XMSS_GENERIC_XMSS_HASHES_H_INCLUDED */
