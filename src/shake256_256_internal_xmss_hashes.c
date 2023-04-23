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

/** @brief Size of the Keccak state array. */
#define KECCAK_STATE_ARRAY_SIZE (b / 8)

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
static void shake256_256_process_message_final(uint64_t *restrict const A, uint_fast16_t offset,
    const uint8_t *restrict message, size_t message_length)
{
    /* NIST FIPS 202, Section 4, Step 2 & 4 & 6 and Section 3.1.2 */
    if (offset > 0 && offset + message_length >= r / 8) {
        sponge_absorb(A, offset, message, r / 8 - offset);
        keccak_p_1600_24(A);
        message += SHAKE256_256_BLOCK_SIZE - offset;
        message_length -= SHAKE256_256_BLOCK_SIZE - offset;
        offset = 0;
    }
    for (; message_length >= SHAKE256_256_BLOCK_SIZE;
            message += SHAKE256_256_BLOCK_SIZE , message_length -= SHAKE256_256_BLOCK_SIZE ) {
        sponge_absorb(A, 0, message, SHAKE256_256_BLOCK_SIZE);
        keccak_p_1600_24(A);
    }

    /* NIST FIPS 202, Section 4, Step 1 & 3 & 6 */
    sponge_absorb(A, offset, message, (uint_fast16_t)message_length);
    sponge_absorb(A, offset + (uint_fast16_t)message_length, &pad_xof, sizeof(pad_xof));
    sponge_absorb(A, SHAKE256_256_BLOCK_SIZE - sizeof(pad_end), &pad_end, sizeof(pad_end));
    keccak_p_1600_24(A);
}

void shake256_256_digest(XmssValue256 *const restrict digest, const uint8_t *const restrict message,
    const size_t message_length)
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
    sponge_squeeze(digest, A);
}

void shake256_256_native_digest(XmssNativeValue256 *restrict native_digest, const uint32_t *restrict words,
    size_t word_count)
{
    /* NIST FIPS 202, Section 4, Step 5 and Section 3.1.2 */
    uint64_t A[KECCAK_STATE_ARRAY_SIZE / sizeof(uint64_t)] = { 0 };

    /* NIST FIPS 202, Section 4, Step 2 & 4 & 6 and Section 3.1.2 */
    for (; word_count >= TO_WORDS(SHAKE256_256_BLOCK_SIZE);
            words += TO_WORDS(SHAKE256_256_BLOCK_SIZE), word_count -= TO_WORDS(SHAKE256_256_BLOCK_SIZE)) {
        sponge_absorb_native(A, words, TO_WORDS(SHAKE256_256_BLOCK_SIZE));
        keccak_p_1600_24(A);
    }

    /* NIST FIPS 202, Section 4, Step 1 & 3 & 6 */
    sponge_absorb_native(A, words, (uint_fast16_t)word_count);
    sponge_absorb(A, (uint_fast16_t)(word_count * sizeof(uint32_t)), &pad_xof, sizeof(pad_xof));
    sponge_absorb(A, SHAKE256_256_BLOCK_SIZE - sizeof(pad_end), &pad_end, sizeof(pad_end));
    keccak_p_1600_24(A);

    /* NIST FIPS 202, Section 4, Step 7 & 8 & 9; we do not need Step 10 */
    sponge_squeeze_native(native_digest, A);
}

void shake256_256_F(XmssNativeValue256 *restrict const native_digest, const Input_F *restrict const input)
{
    uint64_t A[KECCAK_STATE_ARRAY_SIZE / sizeof(uint64_t)] = { 0 };
    sponge_absorb_native(A, (const uint32_t *)input, TO_WORDS(INPUT_F_DATA_SIZE));
    sponge_absorb(A, 96, &pad_xof, sizeof(pad_xof));
    sponge_absorb(A, SHAKE256_256_BLOCK_SIZE - sizeof(pad_end), &pad_end, sizeof(pad_end));
    keccak_p_1600_24(A);
    sponge_squeeze_native(native_digest, A);
}

void shake256_256_H(XmssNativeValue256 *restrict const native_digest, const Input_H *restrict const input)
{
    uint64_t A[KECCAK_STATE_ARRAY_SIZE / sizeof(uint64_t)] = { 0 };
    sponge_absorb_native(A, (const uint32_t *)input, TO_WORDS(INPUT_H_DATA_SIZE));
    sponge_absorb(A, 128, &pad_xof, sizeof(pad_xof));
    sponge_absorb(A, SHAKE256_256_BLOCK_SIZE - sizeof(pad_end), &pad_end, sizeof(pad_end));
    keccak_p_1600_24(A);
    sponge_squeeze_native(native_digest, A);
}

void shake256_256_H_msg(XmssNativeValue256 *restrict const native_digest, const Input_H_msg *restrict const input,
    const uint8_t *restrict message, size_t message_length)
{
    uint64_t A[KECCAK_STATE_ARRAY_SIZE / sizeof(uint64_t)] = { 0 };
    /* We can directly use the size of Input_H_msg because it never contains any SHA-256 padding. */
    sponge_absorb_native(A, (const uint32_t *)input, TO_WORDS(sizeof(Input_H_msg)));
    shake256_256_process_message_final(A, sizeof(Input_H_msg), message, message_length);
    sponge_squeeze_native(native_digest, A);
}

void shake256_256_PRF(XmssNativeValue256 *restrict const native_digest, const Input_PRF *restrict const input)
{
    uint64_t A[KECCAK_STATE_ARRAY_SIZE / sizeof(uint64_t)] = { 0 };
    sponge_absorb_native(A, (const uint32_t *)input, TO_WORDS(INPUT_PRF_DATA_SIZE));
    sponge_absorb(A, INPUT_PRF_DATA_SIZE, &pad_xof, sizeof(pad_xof));
    sponge_absorb(A, SHAKE256_256_BLOCK_SIZE - sizeof(pad_end), &pad_end, sizeof(pad_end));
    keccak_p_1600_24(A);
    sponge_squeeze_native(native_digest, A);
}

void shake256_256_PRFkeygen(XmssNativeValue256 *restrict const native_digest,
    const Input_PRFkeygen *restrict const input)
{
    uint64_t A[KECCAK_STATE_ARRAY_SIZE / sizeof(uint64_t)] = { 0 };
    sponge_absorb_native(A, (const uint32_t *)input, TO_WORDS(INPUT_PRF_KEYGEN_DATA_SIZE));
    sponge_absorb(A, INPUT_PRF_KEYGEN_DATA_SIZE, &pad_xof, sizeof(pad_xof));
    sponge_absorb(A, SHAKE256_256_BLOCK_SIZE - sizeof(pad_end), &pad_end, sizeof(pad_end));
    keccak_p_1600_24(A);
    sponge_squeeze_native(native_digest, A);
}

void shake256_256_PRFindex(XmssNativeValue256 *restrict const native_digest, const Input_PRFindex *restrict const input)
{
    uint64_t A[KECCAK_STATE_ARRAY_SIZE / sizeof(uint64_t)] = { 0 };
    sponge_absorb_native(A, (const uint32_t *)input, TO_WORDS(INPUT_PRF_INDEX_DATA_SIZE));
    sponge_absorb(A, INPUT_PRF_INDEX_DATA_SIZE, &pad_xof, sizeof(pad_xof));
    sponge_absorb(A, SHAKE256_256_BLOCK_SIZE - sizeof(pad_end), &pad_end, sizeof(pad_end));
    keccak_p_1600_24(A);
    sponge_squeeze_native(native_digest, A);
}
