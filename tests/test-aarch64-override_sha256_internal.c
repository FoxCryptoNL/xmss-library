/*
 * SPDX-FileCopyrightText: 2024 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * ARMv8 Cryptography Extensions implementation of SHA-256.
 */

#include <arm_neon.h>

#include "override_sha256_internal.h"


/**
 * @brief
 * The constant values K[t] to be used for the iteration t of the hash computation.
 *
 * @details
 * See NIST FIPS 180-4, Section 4.2.2.
 *
 * These values represent the first thirty-two bits of the fractional parts of the cube roots of the first
 * sixty-four prime numbers.
 */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


void xmss_sha256_process_block(XmssNativeValue256 *const Hi, const uint32_t *const Mi)
{
    /*
     * See: NIST FIPS 180-4, Section 6.2.2.
     *
     * This is the part inside the outer loop.
     */

    /* For performance reasons, some local variables are defined uninitialized and are not explicitly set to 0. */

    /* The ARM intrinsics operate on SIMD vectors (uint32x4_t) instead of plain uint32_t, so we need to load/store. */
    uint32x4_t Hi_SIMD[2] = { vld1q_u32(Hi->data), vld1q_u32(Hi->data + 4) };

    /* The ARM intrinsics handle the message 4 words at a time, so t = [0..15] instead of [0..63]. */

    /* 1. Prepare the message schedule, {Wt} */
    uint32x4_t W[16];
    for (uint_fast8_t t = 0; t <= 3; ++t) {
        W[t] = vld1q_u32(Mi + t * 4);
    }
    for (uint_fast8_t t = 4; t <= 15; ++t) {
        W[t] = vsha256su1q_u32(vsha256su0q_u32(W[t - 4], W[t - 3]), W[t - 2], W[t - 1]);
    }

    /* 2. Initialize the working variables */
    uint32x4_t abcd = Hi_SIMD[0];
    uint32x4_t efgh = Hi_SIMD[1];

    /* 3. <NIST does not provide a description for this step> */
    for (uint_fast8_t t = 0; t <= 15; ++t) {
        uint32x4_t round_input = vaddq_u32(W[t], vld1q_u32(K + t * 4));
        uint32x4_t tmp_abcd = vsha256hq_u32(abcd, efgh, round_input);
        efgh = vsha256h2q_u32(efgh, abcd, round_input);
        abcd = tmp_abcd;
    }

    /* 4. Compute the next iteration of the intermediate hash value */
    vst1q_u32(Hi->data, vaddq_u32(Hi_SIMD[0], abcd));
    vst1q_u32(Hi->data + 4, vaddq_u32(Hi_SIMD[1], efgh));
}
