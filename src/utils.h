/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Max Fillinger
 */

/**
 * @file
 * @brief
 * Utility and convenience functions.
 */

#pragma once

#ifndef XMSS_UTILS_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_UTILS_H_INCLUDED

#include <stdint.h>
#include <string.h>

#include "types.h"

/** @brief Convert a size in bytes to a size in bits. */
#define TO_BITS(size) ((size) * 8u)

/** @brief Convert a size in bytes to a size in 32-bit words, rounding down. */
#define TO_WORDS(size) ((size) / sizeof(uint32_t))

/**
 * @copydoc XmssZeroizeFunction
 * @see XmssZeroizeFunction
 *
 * @details
 * In pure C99, there is no way to implement a zeroize function that cannot be optimized away. This implementation is a
 * best-effort solution that is known to work on almost all compilers.
 */
void xmss_zeroize(void * const ptr, const size_t size);

/**
 * @brief
 * Copies a 256-bit value.
 *
 * @param[out]   dst The destination value.
 * @param[in]    src The source value.
 */
static inline void value_256_copy(XmssValue256 *const restrict dst, const XmssValue256 *const restrict src)
{
    memcpy(dst, src, sizeof(XmssValue256));
}

/**
 * @brief
 * Copies a 256-bit native value.
 *
 * @param[out]   dst The destination value.
 * @param[in]    src The source value.
 */
static inline void native_256_copy(XmssNativeValue256 *const restrict dst, const XmssNativeValue256 *const restrict src)
{
    memcpy(dst, src, sizeof(XmssNativeValue256));
}

#endif /* !XMSS_UTILS_H_INCLUDED */
