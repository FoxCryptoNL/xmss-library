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

#include <stdio.h>
#include "config.h"

#if !XMSS_ENABLE_SHAKE256_256
#   error "SHAKE256/256 is disabled, so SHAKE256/256 related source files must not be compiled."
#endif
#if XMSS_ENABLE_SHAKE256_256_GENERIC
#   error "SHAKE256/256 uses generic interface, so SHAKE256/256 related internal source files must not be compiled."
#endif

#include <stdint.h>
#include <string.h>

#include "shake256_256_internal_xmss_hashes.h"

#include "override_shake256_256_internal.h"
#include "utils.h"

/**
 * @brief
 * The width in bits of a $\\Keccak$-$p$ permutation.
 *
 * @details
 * See: NIST FIPS 202, Table 1.
 */
#define b (1600)

/**
 * @brief
 * The capacity in bits of the sponge function for SHAKE256.
 *
 * @details
 * See: NIST FIPS 202, Section 6.2.
 */
#define c (512)

/**
 * @brief
 * The rate in bits of a sponge function.
 *
 * @details
 * See: NIST FIPS 202, Section 5.2.
 */
#define r (b - c)

/** @brief Block size of SHAKE256-256. */
#define SHAKE256_256_BLOCK_SIZE (r / 8)

/** @private */
XMSS_STATIC_ASSERT(b / 8 == KECCAK_STATE_ARRAY_SIZE, "Incorrect Keccak state array size.");

/**
 * @brief
 * Padding start byte for SHA-3 XOF.
 *
 * @details
 * See NIST FIPS 202, Section B.2.
 */
static const uint8_t pad_xof = 0x1f;

/**
 * @brief
 * Padding end byte for SHA-3.
 *
 * @details
 * See NIST FIPS 202, Section B.2.
 */
static const uint8_t pad_end = 0x80;

/**
 * @brief
 * Completes the sponge function by absorbing the final message and padding.
 *
 * @details
 * Input validation is omitted for performance reasons.
 *
 * @param[in,out] A   The state matrix.
 * @param[in]   offset   The offset (in the range [0,135]) where to start absorbing the message.
 * @param[in]   message   Input message; may be NULL if and only if message_length is 0.
 * @param[in]   message_length   Input message length in bytes.
 */
static void shake256_256_process_message_final(uint64_t *const A, uint_fast8_t offset, const uint8_t *message,
    size_t message_length)
{
    /* NIST FIPS 202, Section 4, Step 2 & 4 & 6 and Section 3.1.2 */
    if (offset > 0 && offset + message_length >= r / 8) {
        xmss_sponge_absorb(A, offset, message, r / 8 - offset);
        xmss_keccak_p_1600_24(A);
        message += SHAKE256_256_BLOCK_SIZE - offset;
        message_length -= SHAKE256_256_BLOCK_SIZE - offset;
        offset = 0;
    }
    for (; message_length >= SHAKE256_256_BLOCK_SIZE;
            message += SHAKE256_256_BLOCK_SIZE , message_length -= SHAKE256_256_BLOCK_SIZE ) {
        xmss_sponge_absorb(A, 0, message, SHAKE256_256_BLOCK_SIZE);
        xmss_keccak_p_1600_24(A);
    }

    /* NIST FIPS 202, Section 4, Step 1 & 3 & 6 */
    if (message_length > 0)
    {
        xmss_sponge_absorb(A, offset, message, (uint_fast8_t)message_length);
    }
    xmss_sponge_absorb(A, offset + (uint_fast8_t)message_length, &pad_xof, sizeof(pad_xof));
    xmss_sponge_absorb(A, SHAKE256_256_BLOCK_SIZE - sizeof(pad_end), &pad_end, sizeof(pad_end));
    xmss_keccak_p_1600_24(A);
}

void shake256_256_F(XmssNativeValue256 *const native_digest, const Input_F *const input)
{
    uint64_t A[KECCAK_STATE_ARRAY_SIZE / sizeof(uint64_t)] = { 0 };
    xmss_sponge_absorb_native(A, (const uint32_t *)input, TO_WORDS(INPUT_F_DATA_SIZE));
    xmss_sponge_absorb(A, 96, &pad_xof, sizeof(pad_xof));
    xmss_sponge_absorb(A, SHAKE256_256_BLOCK_SIZE - sizeof(pad_end), &pad_end, sizeof(pad_end));
    xmss_keccak_p_1600_24(A);
    xmss_sponge_squeeze_native(native_digest, A);
}

void shake256_256_H(XmssNativeValue256 *const native_digest, const Input_H *const input)
{
    uint64_t A[KECCAK_STATE_ARRAY_SIZE / sizeof(uint64_t)] = { 0 };
    xmss_sponge_absorb_native(A, (const uint32_t *)input, TO_WORDS(INPUT_H_DATA_SIZE));
    xmss_sponge_absorb(A, 128, &pad_xof, sizeof(pad_xof));
    xmss_sponge_absorb(A, SHAKE256_256_BLOCK_SIZE - sizeof(pad_end), &pad_end, sizeof(pad_end));
    xmss_keccak_p_1600_24(A);
    xmss_sponge_squeeze_native(native_digest, A);
}

void shake256_256_H_msg_init(XmssHMsgCtx *const ctx, const Input_H_msg *const input)
{
    memset(ctx->shake256_256_ctx.shake256_256_state_array, 0, sizeof(ctx->shake256_256_ctx.shake256_256_state_array));
    xmss_sponge_absorb_native(ctx->shake256_256_ctx.shake256_256_state_array, (const uint32_t *)input,
        TO_WORDS(sizeof(Input_H_msg)));
    ctx->shake256_256_ctx.offset.value = sizeof(Input_H_msg);
}

void shake256_256_H_msg_update(XmssHMsgCtx *const ctx, const uint8_t *const part, size_t part_length,
    const uint8_t *volatile *const part_verify)
{
    const uint8_t *volatile const volatile_part = part;
    size_t offset = 0;
    uint_fast8_t remaining_space_in_block = SHAKE256_256_BLOCK_SIZE - ctx->shake256_256_ctx.offset.value;
    if (remaining_space_in_block < SHAKE256_256_BLOCK_SIZE && part_length >= remaining_space_in_block) {
        xmss_sponge_absorb(ctx->shake256_256_ctx.shake256_256_state_array, ctx->shake256_256_ctx.offset.value,
            volatile_part + offset, remaining_space_in_block);
        xmss_keccak_p_1600_24(ctx->shake256_256_ctx.shake256_256_state_array);
        offset += remaining_space_in_block;
        part_length -= remaining_space_in_block;
        ctx->shake256_256_ctx.offset.value = 0;
    }
    while (part_length >= SHAKE256_256_BLOCK_SIZE) {
        xmss_sponge_absorb(ctx->shake256_256_ctx.shake256_256_state_array, 0, volatile_part + offset,
            SHAKE256_256_BLOCK_SIZE);
        xmss_keccak_p_1600_24(ctx->shake256_256_ctx.shake256_256_state_array);
        offset += SHAKE256_256_BLOCK_SIZE;
        part_length -= SHAKE256_256_BLOCK_SIZE;
    }
    if (part_length > 0)
    {
        xmss_sponge_absorb(ctx->shake256_256_ctx.shake256_256_state_array, ctx->shake256_256_ctx.offset.value,
            volatile_part + offset, (uint_fast8_t)part_length);
        ctx->shake256_256_ctx.offset.value += (uint_fast8_t)part_length;
    }

    if (part_verify != NULL)
    {
        *part_verify = volatile_part;
    }
}

void shake256_256_H_msg_finalize(XmssNativeValue256 *const native_digest, XmssHMsgCtx *const ctx)
{
    shake256_256_process_message_final(ctx->shake256_256_ctx.shake256_256_state_array,
        ctx->shake256_256_ctx.offset.value, NULL, 0);
    xmss_sponge_squeeze_native(native_digest, ctx->shake256_256_ctx.shake256_256_state_array);
}

void shake256_256_PRF(XmssNativeValue256 *const native_digest, const Input_PRF *const input)
{
    uint64_t A[KECCAK_STATE_ARRAY_SIZE / sizeof(uint64_t)] = { 0 };
    xmss_sponge_absorb_native(A, (const uint32_t *)input, TO_WORDS(INPUT_PRF_DATA_SIZE));
    xmss_sponge_absorb(A, INPUT_PRF_DATA_SIZE, &pad_xof, sizeof(pad_xof));
    xmss_sponge_absorb(A, SHAKE256_256_BLOCK_SIZE - sizeof(pad_end), &pad_end, sizeof(pad_end));
    xmss_keccak_p_1600_24(A);
    xmss_sponge_squeeze_native(native_digest, A);
}

#if XMSS_ENABLE_SIGNING

void shake256_256_PRFkeygen(XmssNativeValue256 *const native_digest, const Input_PRFkeygen *const input)
{
    uint64_t A[KECCAK_STATE_ARRAY_SIZE / sizeof(uint64_t)] = { 0 };
    xmss_sponge_absorb_native(A, (const uint32_t *)input, TO_WORDS(INPUT_PRF_KEYGEN_DATA_SIZE));
    xmss_sponge_absorb(A, INPUT_PRF_KEYGEN_DATA_SIZE, &pad_xof, sizeof(pad_xof));
    xmss_sponge_absorb(A, SHAKE256_256_BLOCK_SIZE - sizeof(pad_end), &pad_end, sizeof(pad_end));
    xmss_keccak_p_1600_24(A);
    xmss_sponge_squeeze_native(native_digest, A);
}

void shake256_256_PRFindex(XmssNativeValue256 *const native_digest, const Input_PRFindex *const input)
{
    uint64_t A[KECCAK_STATE_ARRAY_SIZE / sizeof(uint64_t)] = { 0 };
    xmss_sponge_absorb_native(A, (const uint32_t *)input, TO_WORDS(INPUT_PRF_INDEX_DATA_SIZE));
    xmss_sponge_absorb(A, INPUT_PRF_INDEX_DATA_SIZE, &pad_xof, sizeof(pad_xof));
    xmss_sponge_absorb(A, SHAKE256_256_BLOCK_SIZE - sizeof(pad_end), &pad_end, sizeof(pad_end));
    xmss_keccak_p_1600_24(A);
    xmss_sponge_squeeze_native(native_digest, A);
}

void shake256_256_digest(XmssValue256 *const digest, const uint8_t *const message, const size_t message_length)
{
    /*
     * See: NIST FIPS 202
     *
     * shake256_256_digest
     * == SHAKE256 (M, d=256)
     * == KECCAK[c=512] (M || 1111, d=256)
     * == SPONGE[KECCAK-p[b=1600, nr=24], pad10*1, r=b-c=1600-512] (M, d=256)
     */

    /* NIST FIPS 202, Section 4, Step 5 and Section 3.1.2 */
    uint64_t A[KECCAK_STATE_ARRAY_SIZE / sizeof(uint64_t)] = { 0 };

    shake256_256_process_message_final(A, 0, message, message_length);

    /* NIST FIPS 202, Section 4, Step 7 & 8 & 9; we do not need Step 10 */
    xmss_sponge_squeeze(digest, A);
}

void shake256_256_native_digest(XmssNativeValue256 *const  native_digest, const uint32_t *words, size_t word_count)
{
    /* NIST FIPS 202, Section 4, Step 5 and Section 3.1.2 */
    uint64_t A[KECCAK_STATE_ARRAY_SIZE / sizeof(uint64_t)] = { 0 };

    /* NIST FIPS 202, Section 4, Step 2 & 4 & 6 and Section 3.1.2 */
    for (; word_count >= TO_WORDS(SHAKE256_256_BLOCK_SIZE);
            words += TO_WORDS(SHAKE256_256_BLOCK_SIZE), word_count -= TO_WORDS(SHAKE256_256_BLOCK_SIZE)) {
        xmss_sponge_absorb_native(A, words, TO_WORDS(SHAKE256_256_BLOCK_SIZE));
        xmss_keccak_p_1600_24(A);
    }

    /* NIST FIPS 202, Section 4, Step 1 & 3 & 6 */
    if (word_count > 0)
    {
        xmss_sponge_absorb_native(A, words, (uint_fast8_t)word_count);
    }
    xmss_sponge_absorb(A, (uint_fast8_t)(word_count * sizeof(uint32_t)), &pad_xof, sizeof(pad_xof));
    xmss_sponge_absorb(A, SHAKE256_256_BLOCK_SIZE - sizeof(pad_end), &pad_end, sizeof(pad_end));
    xmss_keccak_p_1600_24(A);

    /* NIST FIPS 202, Section 4, Step 7 & 8 & 9; we do not need Step 10 */
    xmss_sponge_squeeze_native(native_digest, A);
}

#endif /* XMSS_ENABLE_SIGNING */

#ifndef DOXYGEN
#undef b
#undef c
#undef r
#undef SHAKE256_256_BLOCK_SIZE
#undef KECCAK_STATE_ARRAY_SIZE
#endif
