/*
 * SPDX-FileCopyrightText: 2015 Markku-Juhani O. Saarinen
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * Default implementation of SHAKE256/256.
 *
 * @details
 * The default implementation of $\\Keccak$ is based on https://github.com/mjosaarinen/tiny_sha3.
 *
 * The default implementation is optimized for 64-bit little-endian targets; it works on all targets.
 *
 * The state array **A** is organized as 25 (5 by 5) lanes of 64 bits each, and a lane is a 64-bit little-endian number.
 * Bit operations on the 64-bit lanes is such that a byte stream message can be absorbed without swapping, i.e.,
 * directly into the memory occupied by the little-endian 64-bit lanes.
 *
 * This means that xmss_sponge_absorb() can simply XOR the message (in chunks of 136 bytes, the block size of SHAKE256)
 * into the memory pointed to by the state array **A**, whereas xmss_sponge_absorb_native() requires byte swapping
 * for little-endian platforms. This is not a performance issue; SHA-3 requires read-read-modify-write
 * memory access, and byte swapping aligned data is free on most architectures.
 *
 * Big-endian systems require byte swapping the state array **A** before and after every $\\Keccak$ operation, which
 * could be optimized by overriding the implementation.
 *
 * On 32-bit systems, the $\\Keccak$ bit operations require emulated 64-bit shifts and rotates, which could be
 * optimized by overriding the implementation.
 *
 * All in all, the default implementation has a good balance between performance and size.
 * It works on all platforms; optimization for 32-bit and/or big-endian systems is possible, but probably not
 * worthwhile.
 */

#include <assert.h>
#include <string.h>

#include "config.h"

#if !XMSS_ENABLE_SHAKE256_256
#   error "SHAKE256/256 is disabled, so SHAKE256/256 related source files must not be compiled."
#endif
#if XMSS_ENABLE_SHAKE256_256_GENERIC
#   error "SHAKE256/256 uses generic interface, so SHAKE256/256 related internal source files must not be compiled."
#endif

#include "libxmss.h"
#if LIBXMSS
#   include <stdint.h>
#   include "types.h"
    // Forward-declare our implementation as static before including the public header.
    LIBXMSS_STATIC
    void xmss_sponge_absorb(uint64_t *A, uint_fast8_t offset, const uint8_t *bytes, uint_fast8_t byte_count);
    LIBXMSS_STATIC
    void xmss_sponge_absorb_native(uint64_t *A, const uint32_t *words, uint_fast8_t word_count);
#   if XMSS_ENABLE_SIGNING
    LIBXMSS_STATIC
    void xmss_sponge_squeeze(XmssValue256 *digest, const uint64_t *A);
#   endif
    LIBXMSS_STATIC
    void xmss_sponge_squeeze_native(XmssNativeValue256 *native_digest, const uint64_t *A);
    LIBXMSS_STATIC
    void xmss_keccak_p_1600_24(uint64_t *A);
#endif

#include "override_shake256_256_internal.h"

LIBXMSS_STATIC
void xmss_sponge_absorb(uint64_t *const A, const uint_fast8_t offset, const uint8_t *bytes, uint_fast8_t byte_count)
{
    /* Block size of SHAKE256/256 is 136 bytes. */
    assert(A != NULL);
    assert(offset < 136);
    assert(bytes != NULL);
    assert(byte_count >= 1);
    assert(byte_count <= 136);
    assert((size_t)offset + byte_count <= 136);

    uint8_t *S = (uint8_t *)A + offset;
    for (; byte_count > 0; --byte_count, ++bytes) {
        *S++ ^= *bytes;
    }
}

LIBXMSS_STATIC
void xmss_sponge_absorb_native(uint64_t *const A, const uint32_t *words, uint_fast8_t word_count)
{
    /* Block size of SHAKE256/256 is 136 bytes == 34 words. */
    assert(A != NULL);
    assert(words != NULL);
    assert(word_count >= 1);
    assert(word_count <= 34);

    uint8_t *S = (uint8_t *)A;
    for (; word_count > 0; --word_count, ++words) {
        *S++ ^= (uint8_t)(*words >> 24);
        *S++ ^= (uint8_t)(*words >> 16);
        *S++ ^= (uint8_t)(*words >> 8);
        *S++ ^= (uint8_t)*words;
    }
}

#if XMSS_ENABLE_SIGNING

LIBXMSS_STATIC
void xmss_sponge_squeeze(XmssValue256 *const digest, const uint64_t *const A)
{
    assert(digest != NULL);
    assert(A != NULL);

    /*
     * NIST FIPS 202, Section 4, Step 7 & 8 & 9; we do not need Step 10.
     *
     * Note that sizeof(XmssValue256) == d / 8 == 32 < r / 8 == 136.
     */
    memcpy(digest, A, sizeof(XmssValue256));
}

#endif

LIBXMSS_STATIC
void xmss_sponge_squeeze_native(XmssNativeValue256 *const native_digest, const uint64_t *const A)
{
    assert(native_digest != NULL);
    assert(A != NULL);

    uint8_t *S = (uint8_t *)A;
    uint32_t *digest_word = native_digest->data;
    for (unsigned int i = 0; i < XMSS_VALUE_256_WORDS; ++i, ++digest_word, S += 4) {
        *digest_word = ((uint32_t)S[0] << 24) | ((uint32_t)S[1] << 16) | ((uint32_t)S[2] << 8) | S[3];
    }
}

/**
 * @brief
 * For a $\\Keccak$-$p$ permutation, the binary logarithm of the lane size, i.e., $log_{2}(w)$.
 *
 * @details
 * See: NIST FIPS 202, Table 1.
 *
 * NOTE: The NIST symbol is $l$, but we use `log2w` for better readability.
 */
#define log2w (6)

/**
 * @brief
 * The number of rounds $n_r$ for a $\\Keccak$-$p$ permutation.
 *
 * @details
 * See: NIST FIPS 202, Section 5.2.
 */
#define nr (12 + 2 * log2w)

/**
 * @brief
 * The number of lanes in the state array **A**.
 *
 * @details
 * See: NIST FIPS 202, Section 3.1.1.
 */
#define LANES (5 * 5)

/**
 * @brief
 * The relocation counts used in $\\rho$ and $\\pi$.
 *
 * @details
 * See: NIST FIPS 202, Section 3.2.2 and 3.2.3.
 *
 * Lane (0,0) is not rotated.
 */
static const unsigned int keccak_f_rotation_count[LANES - 1] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

/**
 * @brief
 * The lane selector used in $\\pi$.
 *
 * @details
 * See: NIST FIPS 202, Section 3.2.3.
 *
 * Lane (0,0) is not swapped.
 */
static const unsigned int keccak_f_pi_lane[LANES - 1] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

/**
 * @brief
 * The round constants used in $\\iota$.
 *
 * @details
 * See: NIST FIPS 202, Section 3.2.5, Algorithm 5.
 */
static const uint64_t keccak_f_round_constants[nr] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

/**
 * @brief
 * Left bit rotation operation.
 *
 * @param[in] value   The value to rotate.
 * @param[in] bits    The number of bits to left rotate; must be in the range [0,63].
 *
 * @returns The result of the rotate operation.
 */
static inline uint64_t rotate_left(const uint64_t value, const unsigned int bits)
{
    return (value << bits) | (value >> (64 - bits));
}

/**
 * @brief
 * Ensure little-endian. Modern compilers will optimize this away for little-endian targets (no-op).
 *
 * @param[in] A   The state array **A**.
 */
static void byte_swap_if_required(uint64_t *const A)
{
    for (unsigned int i = 0; i < 25; ++i) {
        uint64_t src = A[i];
        uint8_t *const dst = (uint8_t *)&A[i];
        dst[0] = (uint8_t)src;
        dst[1] = (uint8_t)(src >> 8);
        dst[2] = (uint8_t)(src >> 16);
        dst[3] = (uint8_t)(src >> 24);
        dst[4] = (uint8_t)(src >> 32);
        dst[5] = (uint8_t)(src >> 40);
        dst[6] = (uint8_t)(src >> 48);
        dst[7] = (uint8_t)(src >> 56);
    }
}

LIBXMSS_STATIC
void xmss_keccak_p_1600_24(uint64_t *const A)
{
    assert(A != NULL);

    /* For performance reasons, the local variables are defined uninitialized and not explicitly set to 0. */

    /* Working variables, reused for different parts of the algorithm. */
    uint64_t tmp;
    uint64_t tmpA[5];

    byte_swap_if_required(A);

    /* See NIST FIPS 202, Section 3.3, Algorithm 7, Step 2 */
    for (unsigned int ir = 0; ir < nr; ++ir) {

        /* See NIST FIPS 202, Section 3.2.1, Algorithm 1, theta */
#ifndef DOXYGEN
#define C tmpA
#define D tmp
#endif
        for (unsigned int i = 0; i < 5; ++i) {
            C[i] = A[i] ^ A[i + 5] ^ A[i + 10] ^ A[i + 15] ^ A[i + 20];
        }
        for (unsigned int i = 0; i < 5; ++i) {
            D = C[(i + 4) % 5] ^ rotate_left(C[(i + 1) % 5], 1);
            for (unsigned int j = 0; j < 25; j += 5) {
                A[j + i] ^= D;
            }
        }

        /* See NIST FIPS 202, Section 3.2.2 and 3.2.3, Algorithm 2 and 3, rho and pi */
        tmp = A[1];
        for (unsigned int i = 0; i < LANES - 1; ++i) {
            unsigned int j = keccak_f_pi_lane[i];
            uint64_t swap = A[j];
            A[j] = rotate_left(tmp, keccak_f_rotation_count[i]);
            tmp = swap;
        }

        /* See NIST FIPS 202, Section 3.2.4, Algorithm 4, chi */
        for (unsigned int j = 0; j < LANES; j += 5) {
            for (unsigned int i = 0; i < 5; ++i) {
                tmpA[i] = A[j + i];
            }
            for (unsigned int i = 0; i < 5; ++i) {
                A[j + i] ^= (~tmpA[(i + 1) % 5]) & tmpA[(i + 2) % 5];
            }
        }

        /* See NIST FIPS 202, Section 3.2.5, Algorithm 6, iota */
        A[0] ^= keccak_f_round_constants[ir];
    }

    byte_swap_if_required(A);
}
