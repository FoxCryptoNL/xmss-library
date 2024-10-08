/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief Prototype for the SHA-256 hash function override using the internal interface.
 *
 * @details
 * Include this file in your override implementation for SHA-256 using the internal interface.
 *
 * The library allows to override its internal implementation for SHA-256.
 * The main use case is hardware acceleration.
 *
 * If your platform is compatible with the internal format of the library, then it is preferred to use the internal
 * interface specified here rather than the generic interface.
 *
 * The internal interface has the following properties:
 * - Allocation free
 * - The intermediate hash value $H_i$ is 32-bit aligned.
 * - The intermediate hash value $H_i$ consists of 8 uint32_t values, each in native byte ordering.
 * - The block $M_i$ is 32-bit aligned.
 * - The block $M_i$ consists of 16 uint32_t values, each in native byte ordering.
 * - The intermediate hash value $H_i$ is modified in-place.
 *
 * This interface prevents unnecessary copying of memory, unnecessary byte swapping, and alignment issues.
 *
 * Compile the library with CMake as follows:
 * ```
 * cmake -DXMSS_SHA256=OverrideInternal
 * ```
 */

#pragma once

#ifndef XMSS_OVERRIDE_SHA256_INTERNAL_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_OVERRIDE_SHA256_INTERNAL_H_INCLUDED

#include <stdint.h>

#include "types.h"

/**
 * @brief
 * Update the intermediate SHA-256 hash value $H_i$ by processing a single, additional message block $M_i$.
 *
 * @details
 * This function implements the loop body of the SHA-256($M$) function as defined by NIST FIPS 180-4, Section 6.2.2,
 * Steps 1, 2, 3, and 4.
 *
 * For performance reasons, it is recommended not to validate the input. This function is guaranteed to be called by the
 * library with valid input.
 *
 * @param[in,out] Hi   Intermediate hash value $H_i$ in native form.
 * @param[in] Mi       Message block $M_i$ in native form (uint32_t[16] == 64 bytes).
 */
void xmss_sha256_process_block(XmssNativeValue256 *Hi, const uint32_t *Mi);

#endif /* !XMSS_OVERRIDE_SHA256_INTERNAL_H_INCLUDED */
