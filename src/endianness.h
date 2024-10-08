/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * Endianness conversions between native 32-words and big-endian byte streams.
 */

#pragma once

#ifndef XMSS_ENDIANNESS_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_ENDIANNESS_H_INCLUDED

#include <stdint.h>

#include "types.h"

/**
 * @brief
 * Convert a big-endian (possibly unaligned) byte stream uint8_t[] to a native uint32_t array.
 *
 * @details
 * Our XMSS-specialized hash functions work on aligned native uint32_t arrays, and produce a native uint32_t[] digest.
 * XMSS and SHA-256 specify all opaque data in big-endian order, and those byte streams are not necessarily aligned on
 * uint32_t boundaries.
 *
 * This takes care of endianness (when needed) and/or alignment (when needed);
 * modern compilers will optimize unneeded operations away.
 *
 * @param[out] dst     The destination native uint32_t array.
 * @param[in]  src     The big-endian source byte stream.
 * @param[in]  count   The number of uint32_t in dst.
 */
static inline void big_endian_to_native(uint32_t *dst, const uint8_t *src, uint_fast32_t count)
{
    for (; count > 0; --count, ++dst, src += 4) {
        *dst = ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) | ((uint32_t)src[2] << 8) | src[3];
    }
}

/**
 * @brief
 * Convert a big-endian (possibly unaligned) 256-bit value to a native value.
 *
 * @see big_endian_to_native
 *
 * @param[out] dst     The destination native value.
 * @param[in]  src     The big-endian source value byte stream.
 */
static inline void big_endian_to_native_256(XmssNativeValue256 *dst, const XmssValue256 *src)
{
    big_endian_to_native(dst->data, src->data, XMSS_VALUE_256_WORDS);
}

/**
 * @brief
 * Convert a big-endian byte stream uint8_t[] to a native uint32_t array, in-place.
 * This means the input/output array must be uint32_t aligned, even though the input is byte oriented.
 *
 * @details
 * Our XMSS-specialized hash functions work on aligned native uint32_t arrays, and produce a native uint32_t[] digest.
 * XMSS and SHA-256 specify all opaque data in big-endian order.
 *
 * This takes care of endianness (when needed); modern compilers will optimize unneeded operations away.
 *
 * @param[in,out] data   The buffer containing a big-endian byte stream on input, and a native uint32_t array on output.
 * @param[in]  count   The number of uint32_t in buf.
 */
static inline void inplace_big_endian_to_native(uint32_t *data, uint_fast32_t count)
{
    for (; count > 0; --count, ++data) {
        const uint8_t *const bytes = (const uint8_t *)data;
        *data = ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | bytes[3];
    }
}

/**
 * @brief
 * Convert a big-endian 256-bit value to a native value, in-place.
 *
 * @see inplace_big_endian_to_native
 *
 * @param[in,out] value   The big-endian byte stream on input, and a native value on output.
 */
static inline void inplace_big_endian_to_native_256(XmssNativeValue256 *value)
{
    inplace_big_endian_to_native(value->data, XMSS_VALUE_256_WORDS);
}

/**
 * @brief
 * Convert a native-endian uint32_t array to big-endian, in-place.
 *
 * This takes care of endianness (when needed); modern compilers will optimize unneeded operations away.
 *
 * @param[in,out] data   The buffer containing a native uint32_t array on input, and a big-endian byte stream on output.
 * @param[in]  count   The number of uint32_t in buf.
 */
static inline void inplace_native_to_big_endian(uint32_t *data, uint_fast32_t count)
{
    /* The operation is the same in either direction, so use the native to big-endian implementation. */
    inplace_big_endian_to_native(data, count);
}

/**
 * @brief
 * Convert a native-endian 256-bit value to big-endian, in-place.
 *
 * @see inplace_big_endian_to_native
 *
 * @param[in,out] value   The native value on input, and a big-endian byte stream on output.
 */
static inline void inplace_native_to_big_endian_256(XmssNativeValue256 *value)
{
    inplace_big_endian_to_native(value->data, XMSS_VALUE_256_WORDS);
}

/**
 * @brief
 * Convert a native uint32_t array to a big-endian (possibly unaligned) byte stream uint8_t[].
 *
 * @details
 * Our XMSS-specialized hash functions work on aligned native uint32_t arrays, and produce a native uint32_t[] digest.
 * XMSS and SHA-256 specify all opaque data in big-endian order, and those byte streams are not necessarily aligned on
 * uint32_t boundaries.
 *
 * This takes care of endianness (when needed) and/or alignment (when needed);
 * modern compilers will optimize unneeded operations away.
 *
 * @param[out] dst     The destination big-endian byte stream.
 * @param[in]  src     The native uint32_t source array.
 * @param[in]  count   The number of uint32_t in src.
 */
static inline void native_to_big_endian(uint8_t *dst, const uint32_t *src, uint_fast32_t count)
{
    for (; count; --count, dst += 4, ++src) {
        dst[0] = (uint8_t)(*src >> 24);
        dst[1] = (uint8_t)(*src >> 16);
        dst[2] = (uint8_t)(*src >> 8);
        dst[3] = (uint8_t)*src;
    }
}

/**
 * @brief
 * Convert a native-endian 256-bit value to big-endian.
 *
 * @see native_to_big_endian
 *
 * @param[out] dst     The destination big-endian byte stream.
 * @param[in]  src     The native source value.
 */
static inline void native_to_big_endian_256(XmssValue256 *const dst, const XmssNativeValue256 *const src)
{
    native_to_big_endian(dst->data, src->data, XMSS_VALUE_256_WORDS);
}

/**
 * @brief
 * Convert a 32 bit word between native-endian and big-endian.
 *
 * @details
 * Can be used to convert a native word to big-endian and vice versa.
 * The conversion is a NO-OP on big-endian architectures.
 *
 * @param[in]   word    The input word.
 * @returns the byte-swapped word on little-endian architectures, or the unchanged word on big-endian architectures.
*/
static inline uint32_t convert_big_endian_word(const uint32_t word) {
    const uint8_t *const bytes = (const uint8_t *)&word;
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | bytes[3];
}

#endif /* !XMSS_ENDIANNESS_H_INCLUDED */
