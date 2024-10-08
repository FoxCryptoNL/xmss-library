/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Max Fillinger
 * SPDX-FileContributor: Frans van Dorsselaer
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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "compat.h"
#include "libxmss.h"
#include "types.h"

/** @brief Convert a size in bytes to a size in bits. */
#define TO_BITS(size) ((size) * 8u)

/** @brief Convert a size in bytes to a size in 32-bit words, rounding down. */
#define TO_WORDS(size) ((size) / sizeof(uint32_t))

/**
 * @brief
 * Return values for bit-error resilient comparison functions.
 *
 * @details
 * The values are chosen to be both non-zero and with large hamming distance to be resilient to bit errors.
 */
typedef enum ValueCompareResult {
    /** @brief Values are equal. */
    VALUES_ARE_EQUAL = XMSS_DISTANT_VALUE_1,
    /** @brief Values are not equal. */
    VALUES_ARE_NOT_EQUAL = XMSS_DISTANT_VALUE_2
} ValueCompareResult;

/**
 * @brief
 * Compare two distinct arrays of 32 bytes each in a bit-error resilient way. The comparison is performed in
 * constant-time in the sense that the execution time does not depend on the actual values; however, the execution time
 * may be affected by bit errors. Note that when the pointers `value1` and `value2` point to the same array, this
 * function returns #VALUES_ARE_NOT_EQUAL.
 *
 * @details
 * compare_32_bytes() is intended to compare cryptographically secure digests; the byte ordering of the digests does not
 * matter, but they should match for both arguments. Use of the more strongly typed compare_values_256() or
 * compare_native_values_256() is preferred.
 *
 * The #VALUES_ARE_EQUAL result indicates that two independently calculated digests are identical. The function requires
 * distinct pointers for `value1` and `value2`; i.e., a value cannot be compared to itself. The default return value
 * in case of contract violations (as the result of either bit errors or fault injections) is #VALUES_ARE_NOT_EQUAL.
 *
 * This function is written in such a way that a single random bit error cannot cause the function to return
 * #VALUES_ARE_EQUAL when the values are not equal. If the return value of this function is checked, it should be stored
 * in a volatile variable which is then checked twice for strict (in)equality against #VALUES_ARE_EQUAL (not against
 * #VALUES_ARE_NOT_EQUAL), to ensure that a bit error cannot skip the check.
 *
 * Although this function helps fault injection mitigation, the caller should also add redundancy to the calculation of
 * the digests themselves and, as a consequence, call this function multiple times.
 *
 * @param[in] value1        The first value; must not be a NULL pointer.
 * @param[in] value2        The (distinct) second value; must not be a NULL pointer.
 * @retval #VALUES_ARE_EQUAL        The values are equal.
 * @retval #VALUES_ARE_NOT_EQUAL    The values are not equal, a bit error was detected, or a NULL pointer was passed.
 */
LIBXMSS_STATIC
ValueCompareResult compare_32_bytes(const uint8_t *value1, const uint8_t *value2);

/**
 * @copydoc compare_32_bytes
 * @see compare_32_bytes
 * @details
 * This is the specialization for XmssValue256.
 */
static inline ValueCompareResult compare_values_256(const XmssValue256 *const value1, const XmssValue256 *const value2)
{
    XMSS_STATIC_ASSERT(sizeof(XmssValue256) == 32, "XmssValue256 expected to be 32 bytes");
    return compare_32_bytes((const uint8_t *)value1, (const uint8_t *)value2);
}

/**
 * @copydoc compare_32_bytes
 * @see compare_32_bytes
 * @details
 * This is the specialization for XmssNativeValue256.
 */
static inline ValueCompareResult compare_native_values_256(const XmssNativeValue256 *const value1,
    const XmssNativeValue256 *const value2)
{
    XMSS_STATIC_ASSERT(sizeof(XmssNativeValue256) == 32, "XmssNativeValue256 expected to be 32 bytes");
    return compare_32_bytes((const uint8_t *)value1, (const uint8_t *)value2);
}

#endif /* !XMSS_UTILS_H_INCLUDED */
