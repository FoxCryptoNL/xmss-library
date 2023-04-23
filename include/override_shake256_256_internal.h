/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief Prototypes for the SHAKE256/256 hash function override using the internal interface.
 *
 * @details
 * Include this file in your override implementation for SHAKE256/256 using the internal interface.
 *
 * The library allows to override its internal implementation for SHAKE256/256.
 * The main use case is hardware acceleration. However, unlike SHA-256, the performance of software implementations
 * of SHAKE256/256 is strongly dependent on the bitness and byte ordering of the platform.
 * The default implementation is optimized for 64-bit little-endian. For other types of platforms a software override
 * can improve performance.
 *
 * If your platform is compatible with the internal format of the library, then it is preferred to use the internal
 * interface specified here rather than the generic interface.
 *
 * The internal interface has the following properties:
 * - Allocation free
 * - The internal state array is 64-bit aligned.
 *
 * The implementation is free to choose the layout of the state array **A** such that it optimizes performance for the
 * target platform. The state array is 1600 bits (200 bytes) in size; i.e., 5x5 lanes of $w$=64. The library treats the
 * state array as opaque; it is only passed as uint64_t to ensure memory alignment; there are no restrictions on how
 * the 1600 bits are organized within the uint64_t[25] data block.
 *
 * The library handles the high level SHAKE256/256 algorithm: absorption, padding, and the final squeeze by calling the
 * low level functions that the override implementation provides.
 *
 * This interface prevents unnecessary copying of memory, unnecessary byte swapping, and alignment issues.
 *
 * Compile the library with CMake as follows:
 * ```
 * cmake -DXMSS_SHAKE256_256=OverrideInternal
 * ```
 */

#pragma once

#ifndef XMSS_OVERRIDE_SHAKE256_256_INTERNAL_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_OVERRIDE_SHAKE256_256_INTERNAL_H_INCLUDED

#include <stdint.h>

#include "types.h"

/**
 * @brief
 * Absorbs additional bytes into the state array **A**.
 *
 * @details
 * offset + byte_count does not extend beyond the block size of 136 bytes for SHAKE256/256.
 * This function XORs the additional bytes into the internal layout of the state array.
 *
 * @param[in,out] A            The state array.
 * @param[in]     offset       The offset into the 136-byte block where to start absorbing the bytes.
 * @param[in]     bytes        Input bytes; may be NULL if and only if byte_count is 0.
 * @param[in]     byte_count   Length in bytes of the input.
 */
void sponge_absorb(uint64_t *restrict A, uint_fast16_t offset, const uint8_t *restrict bytes,
    uint_fast16_t byte_count);

/**
 * @brief
 * Absorbs additional native words into the state array **A**.
 *
 * @details
 * Absorption starts at the beginning of the 136 bytes block for SHAKE256/256.
 * word_count does not extend beyond the block size of 136 bytes for SHAKE256/256; i.e., word_count <= 34.
 * This function XORs the words into the internal layout of the state array.
 *
 * @param[in,out] A            The state array.
 * @param[in]     words        Input words; may be NULL if and only if byte_count is 0.
 * @param[in]     word_count   Length in 32-bit words of the input.
 */
void sponge_absorb_native(uint64_t *restrict A, const uint32_t *restrict words, uint_fast16_t word_count);

/**
 * @brief
 * Extracts the digest from the state array **A**.
 *
 * @param[out] digest   The output digest.
 * @param[in]  A        The final state array.
 */
void sponge_squeeze(XmssValue256 *restrict digest, const uint64_t *restrict const A);

/**
 * @brief
 * Extracts the digest from the state array **A**.
 *
 * @param[out] native_digest   The output digest.
 * @param[in]  A               The final state array.
 */
void sponge_squeeze_native(XmssNativeValue256 *restrict native_digest, const uint64_t *restrict const A);

/**
 * @brief
 * Perform an in-place $\\Keccak$-$p[1600,24]$ transform of the state array **A**.
 *
 * @details
 * This function implements $\\Keccak$-$p[b=1600,n_{r}=24]$ as defined by NIST FIPS 202, Section 3.3.
 *
 * Note that instead of accepting a string $S$, this function accepts a state array **A**,
 *      see NIST FIPS 202, Section 3.1.2.
 *
 * Note that instead of returning the result, this function transforms the input state array in-place.
 *
 * @param[in,out] A   The state array.
*/
void keccak_p_1600_24(uint64_t *A);

#endif /* !XMSS_OVERRIDE_SHAKE256_256_INTERNAL_H_INCLUDED */
