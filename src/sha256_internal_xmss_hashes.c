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

#include "config.h"

#if !XMSS_ENABLE_SHA256
#   error "SHA-256 is disabled, so SHA-256 related source files must not be compiled."
#endif
#if XMSS_ENABLE_SHA256_GENERIC
#   error "SHA-256 uses generic interface, so SHA-256 related internal source files must not be compiled."
#endif

#include <string.h>

#include "sha256_internal_xmss_hashes.h"

#include "endianness.h"
#include "override_sha256_internal.h"
#include "sha256_internal_H0.h"
#include "xmss_hashes_base.h"


void sha256_process_message_final(XmssNativeValue256 *const native_digest, const uint8_t *message,
    size_t message_length, const uint64_t prefix_length)
{
    /* See: NIST FIPS 180-4, Section 6.2
     *
     * This function handles:
     *   - NIST FIPS 180-4, Section 6.2.1: SHA-256 Preprocessing
     *   - NIST FIPS 180-4, Section 6.2.2: SHA-256 Hash Computation (outer loop)
     */

    /* message block i = [1..N]; initialization postponed for performance reasons */
    uint32_t Mi[TO_WORDS(SHA256_BLOCK_SIZE)];
    /* index into Mi; initialization postponed for performance reasons */
    uint_fast8_t t;
    /* the total number of bytes in the message */
    uint64_t total = prefix_length + message_length;

    /* a) First we handle the complete message blocks (64 bytes each) */
    /* See NIST FIPS 180-4, Section 6.2.2, outer loop */
    for (; message_length >= SHA256_BLOCK_SIZE; message += SHA256_BLOCK_SIZE, message_length -= SHA256_BLOCK_SIZE) {
        big_endian_to_native(Mi, message, TO_WORDS(SHA256_BLOCK_SIZE));
        xmss_sha256_process_block(native_digest, Mi);
    }

    /* b) Next we handle the remainder (if any). */

    /* b.1) First the multiples of uint32_t. */
    t = (uint_fast8_t)(message_length / sizeof(uint32_t));
    big_endian_to_native(Mi, message, t);
    message += t * sizeof(uint32_t);

    /* b.2) Next the final uint32_t of the message including padding bit; see NIST FIPS 180-4, Section 5.1.1 */
    switch (message_length % sizeof(uint32_t)) {
    case 0:
        Mi[t] = 0x80000000;
        break;
    case 1:
        Mi[t] = ((uint32_t)message[0] << 24) | 0x00800000;
        break;
    case 2:
        Mi[t] = ((uint32_t)message[0] << 24) | ((uint32_t)message[1] << 16) | 0x00008000;
        break;
    case 3:
        Mi[t] = ((uint32_t)message[0] << 24) | ((uint32_t)message[1] << 16) | ((uint32_t)message[2] << 8) | 0x00000080;
        break;
    }
    ++t;
    /* We do not update message and message_length as they are no longer needed. */

    /* b.3) Add the total length; see NIST FIPS 180-4, Section 5.1.1. */
    if (t > TO_WORDS(SHA256_BLOCK_SIZE) - sizeof(uint64_t) / sizeof(uint32_t)) {
        /* The length of the message must be stored in the last 64 bits of a block, so we need another block. */
        memset(&Mi[t], 0, (TO_WORDS(SHA256_BLOCK_SIZE) - t) * sizeof(uint32_t));
        xmss_sha256_process_block(native_digest, Mi);
        t = 0;
    }
    memset(&Mi[t], 0, ((size_t)14 - t) * sizeof(uint32_t));
    /* Note that 'total' represents number of bytes, whereas SHA-256 requires number of bits. */
    Mi[14] = (uint32_t)(total >> 29);
    Mi[15] = (uint32_t)(total << 3);
    xmss_sha256_process_block(native_digest, Mi);
}


void sha256_H_msg_update(XmssHMsgCtx *const ctx, const uint8_t *const part, const size_t part_length,
    const uint8_t *volatile *const part_verify)
{
    const uint8_t *volatile const volatile_part = part;
    size_t remaining_part_length = part_length;
    size_t offset = 0;

    /* If there is a partial block in ctx, complete it. */
    if (ctx->sha256_ctx.bytes_in_partial_block.value > 0) {
        size_t bytes_free_in_partial_block = SHA256_BLOCK_SIZE - ctx->sha256_ctx.bytes_in_partial_block.value;

        if (bytes_free_in_partial_block > part_length) {
            /* We don't have enough new data for a whole block, so we add it all to the partial block. */
            memcpy(ctx->sha256_ctx.partial_block + ctx->sha256_ctx.bytes_in_partial_block.value, volatile_part + offset,
                part_length);
            ctx->sha256_ctx.bytes_in_partial_block.value += part_length;
            if (part_verify != NULL)
            {
                *part_verify = volatile_part;
            }
            return;
        } else {
            /* Complete the partial block and update the intermediate hash in ctx. */
            memcpy(ctx->sha256_ctx.partial_block + ctx->sha256_ctx.bytes_in_partial_block.value, volatile_part + offset,
                bytes_free_in_partial_block);
            inplace_big_endian_to_native((uint32_t *)ctx->sha256_ctx.partial_block,
                sizeof(ctx->sha256_ctx.partial_block) / sizeof(uint32_t));
            xmss_sha256_process_block(&ctx->sha256_ctx.intermediate_hash, (uint32_t *)ctx->sha256_ctx.partial_block);
            ctx->sha256_ctx.bytes_hashed += SHA256_BLOCK_SIZE;
            ctx->sha256_ctx.bytes_in_partial_block.value = 0;
            remaining_part_length -= bytes_free_in_partial_block;
            offset += bytes_free_in_partial_block;
        }
    }

    /* Process whole blocks in the input. */
    while (remaining_part_length >= SHA256_BLOCK_SIZE) {
        /* The partial_block in ctx is empty right now, so let's reuse the memory. */
        uint32_t *block = (uint32_t *)ctx->sha256_ctx.partial_block;
        big_endian_to_native(block, volatile_part + offset, TO_WORDS(SHA256_BLOCK_SIZE));
        xmss_sha256_process_block(&ctx->sha256_ctx.intermediate_hash, block);
        ctx->sha256_ctx.bytes_hashed += SHA256_BLOCK_SIZE;
        remaining_part_length -= SHA256_BLOCK_SIZE;
        offset += SHA256_BLOCK_SIZE;
    }

    /* Put the remainder as a partial block in ctx. */
    if (remaining_part_length > 0) {
        ctx->sha256_ctx.bytes_in_partial_block.value = remaining_part_length;
        memcpy(ctx->sha256_ctx.partial_block, volatile_part + offset, remaining_part_length);
    }

    if (part_verify != NULL)
    {
        *part_verify = volatile_part;
    }
}


#if XMSS_ENABLE_SIGNING

void sha256_native_digest(XmssNativeValue256 *native_digest, const uint32_t *words, size_t word_count)
{
    /* See: NIST FIPS 180-4, Section 6.2
     *
     * This function handles:
     *   - NIST FIPS 180-4, Section 6.2.1: SHA-256 Preprocessing
     *   - NIST FIPS 180-4, Section 6.2.2: SHA-256 Hash Computation
     */

    /* message block i = [1..N]; initialization postponed for performance reasons */
    uint32_t Mi[TO_WORDS(SHA256_BLOCK_SIZE)];
    /* index into Mi; initialization postponed for performance reasons */
    uint_fast8_t t;
    /* the total number of bytes in the message */
    uint64_t total = word_count * sizeof(uint32_t);

    /* See NIST FIPS 180-4, Section 6.2.1, Step 1 */
    *native_digest = sha256_H0;

    /* a) First we handle the complete message blocks (64 bytes each) */
    /* See NIST FIPS 180-4, Section 6.2.2, outer loop */
    for (; word_count >= TO_WORDS(SHA256_BLOCK_SIZE);
            words += TO_WORDS(SHA256_BLOCK_SIZE), word_count -= TO_WORDS(SHA256_BLOCK_SIZE)) {
        xmss_sha256_process_block(native_digest, words);
    }

    /* b) Next we handle the remainder (if any). */
    t = (uint_fast8_t)(word_count);
    memcpy(Mi, words, word_count * sizeof(uint32_t));
    Mi[t] = 0x80000000;
    ++t;
    /* We do not update words and word_count as they are no longer needed. */

    /* b.3) Add the total length; see NIST FIPS 180-4, Section 5.1.1. */
    if (t > TO_WORDS(SHA256_BLOCK_SIZE) - sizeof(uint64_t) / sizeof(uint32_t)) {
        /* The length of the message must be stored in the last 64 bits of a block, so we need another block. */
        memset(&Mi[t], 0, (TO_WORDS(SHA256_BLOCK_SIZE) - t) * sizeof(uint32_t));
        xmss_sha256_process_block(native_digest, Mi);
        t = 0;
    }
    memset(&Mi[t], 0, ((size_t)14 - t) * sizeof(uint32_t));
    /* Note that 'total' represents number of bytes, whereas SHA-256 requires number of bits. */
    Mi[14] = (uint32_t)(total >> 29);
    Mi[15] = (uint32_t)(total << 3);
    xmss_sha256_process_block(native_digest, Mi);
}

#endif /* XMSS_ENABLE_SIGNING */
