/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * Abstraction layer for XMSS the hash functions.
 *
 * @details
 * This header handles the "hash-abstraction" for XMSS, allowing the XMSS code to not care about whether SHA-256
 * or SHAKE256/256 is being used as the underlying hash primitive.
 *
 * There are 2 options:
 *
 * 1. The library is compiled to support both SHA-256 *and* SHAKE256/256. The context variable for the XMSS key is
 *    supposed to contain an xmss_hashes (or pointer to) variable that either equals (or points to) `sha256_xmss_hashes`
 *    or `shake256_256_xmss_hashes`.
 *
 *    You call the XMSS `F(...)` hash function by writing: `xmss_F(HASH_ABSTRACTION(context->xmss_hashes) ...)`.
 *
 *    This will then call the right function. Note that in this case there is always a function call; it cannot be
 *    inlined.
 *
 * 2. The library is compiled to support either SHA-256 *or* SHAKE256/256. In this case there is no context variable,
 *    but the syntax is still `xmss_F(HASH_ABSTRACTION(context->xmss_hashes) ...)`. The macro will expand directly to
 *    the implementing function, without using the parameter. This allows the compiler to inline the call, without
 *    unnecessary dereferencing. In fact, neither `sha256_xmss_hashes` nor `shake256_256_xmss_hashes` will be defined,
 *    so the addresses of the functions are never taken. If all calls are inlined, the 'function' will not even exist.
 *    Of course, this is up to the compiler and its optimization settings.
 *
 * Usage:
 *
 * - Always include just `xmss_hashes.h`
 * - Guard your hash abstraction context variable with `#if XMSS_ENABLE_HASH_ABSTRACTION`
 * - Call the hash function as `xmss_xxx(HASH_ABSTRACTION(context->xmss_hashes) ...)`.
 *
 *   NOTE: There is no comma between `HASH_ABSTRACTION()` and the next argument.
 */

#pragma once

#ifndef XMSS_XMSS_HASHES_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_XMSS_HASHES_H_INCLUDED

#include "config.h"
#include "structures.h"
#include "xmss_hashes_base.h"

#if XMSS_ENABLE_HASH_ABSTRACTION

/*
 * This is the implementation of the XMSS_xxx() specialized hash functions for:
 * - SHA-256 support
 * - SHAKE256/256 support
 *
 * The functions are relayed to the corresponding algorithm.
 */

/**
 * @copydoc prototype_digest
 * @param[in]  hashes   The hash algorithm abstraction; provide this parameter with `HASH_ABSTRACTION(context->hashes)`.
 *
 * @see prototype_digest
 */
static inline void xmss_digest(const xmss_hashes *restrict const hashes, XmssValue256 *restrict const digest,
    const uint8_t *restrict const message, const size_t message_length)
{
    (hashes->digest)(digest, message, message_length);
}

/**
 * @copydoc prototype_native_digest
 * @param[in]  hashes   The hash algorithm abstraction; provide this parameter with `HASH_ABSTRACTION(context->hashes)`.
 *
 * @see prototype_native_digest
 */
static inline void xmss_native_digest(const xmss_hashes *restrict const hashes,
    XmssNativeValue256 *restrict const native_digest, const uint32_t *restrict const words, const size_t word_count)
{
    (hashes->native_digest)(native_digest, words, word_count);
}

/**
 * @copydoc prototype_F
 * @param[in]  hashes   The hash algorithm abstraction; provide this parameter with `HASH_ABSTRACTION(context->hashes)`.
 *
 * @see prototype_F
 */
static inline void xmss_F(const xmss_hashes *restrict const hashes, XmssNativeValue256 *restrict const native_digest,
    const Input_F *restrict const input)
{
    (hashes->F)(native_digest, input);
}

/**
 * @copydoc prototype_H
 * @param[in]  hashes   The hash algorithm abstraction; provide this parameter with `HASH_ABSTRACTION(context->hashes)`.
 *
 * @see prototype_H
 */
static inline void xmss_H(const xmss_hashes *restrict const hashes, XmssNativeValue256 *restrict const native_digest,
    const Input_H *restrict const input)
{
    (hashes->H)(native_digest, input);
}

/**
 * @copydoc prototype_H_msg
 * @param[in]  hashes   The hash algorithm abstraction; provide this parameter with `HASH_ABSTRACTION(context->hashes)`.
 *
 * @see prototype_H_msg
 */
static inline void xmss_H_msg(const xmss_hashes *restrict const hashes, XmssNativeValue256 *restrict const native_digest,
    const Input_H_msg *restrict const input, const uint8_t *restrict const message, const size_t message_length)
{
    (hashes->H_msg)(native_digest, input, message, message_length);
}

/**
 * @copydoc prototype_PRF
 * @param[in]  hashes   The hash algorithm abstraction; provide this parameter with `HASH_ABSTRACTION(context->hashes)`.
 *
 * @see prototype_PRF
 */
static inline void xmss_PRF(const xmss_hashes *restrict const hashes, XmssNativeValue256 *restrict const native_digest,
    const Input_PRF *restrict const input)
{
    (hashes->PRF)(native_digest, input);
}

/**
 * @copydoc prototype_PRFkeygen
 * @param[in]  hashes   The hash algorithm abstraction; provide this parameter using the HASH_ABSTRACTION() macro.
 *
 * @see prototype_PRFkeygen
 */
static inline void xmss_PRFkeygen(const xmss_hashes *restrict const hashes,
    XmssNativeValue256 *restrict const native_digest, const Input_PRFkeygen *restrict const input)
{
    (hashes->PRFkeygen)(native_digest, input);
}

/**
 * @copydoc prototype_PRFindex
 * @param[in]  hashes   The hash algorithm abstraction; provide this parameter using the HASH_ABSTRACTION() macro.
 *
 * @see prototype_PRFindex
 */
static inline void xmss_PRFindex(const xmss_hashes *restrict const hashes,
    XmssNativeValue256 *restrict const native_digest, const Input_PRFindex *restrict const input)
{
    (hashes->PRFindex)(native_digest, input);
}

/**
 * @brief
 * Used as the first parameter to any of the XMSS hash functions.
 *
 * @param[in] hashes   A pointer to the xmss_hashes structure for a specific hash algorithm.
 */
#   define HASH_ABSTRACTION(hashes) hashes,

#elif XMSS_ENABLE_SHA256

/*
 * This is the implementation of the XMSS specialized hash functions if only SHA-256 is enabled.
 *
 * At this level of "abstraction" there really is no abstraction.
 * The specialized functions are macros that directly expand to the corresponding SHA-256 implementation,
 *      which is even inlined for the internal implementation (default).
 *
 * This optimizes both performance *and* code size.
 */

#   include "sha256_xmss_hashes.h"

#   define xmss_digest sha256_digest
#   define xmss_native_digest sha256_native_digest
#   define xmss_F sha256_F
#   define xmss_H sha256_H
#   define xmss_H_msg sha256_H_msg
#   define xmss_PRF sha256_PRF
#   define xmss_PRFkeygen sha256_PRFkeygen
#   define xmss_PRFindex sha256_PRFindex

#   define HASH_ABSTRACTION(hashes)

#elif XMSS_ENABLE_SHAKE256_256

/*
 * This is the implementation of the XMSS specialized hash functions if only SHAKE256/256 is enabled.
 *
 * At this level of "abstraction" there really is no abstraction.
 * The specialized functions are macros that directly expand to the corresponding SHAKE256/256 implementation
 *      However, the SHAKE256/256 implementation is more complex than the SHA-256 implementation
 *      and therefore the SHAKE256/256 implementation is not inlined.
 *
 * This optimizes both performance *and* code size, but less than for SHA-256.
 */

#   include "shake256_256_xmss_hashes.h"

#   define xmss_digest shake256_256_digest
#   define xmss_native_digest shake256_256_native_digest
#   define xmss_F shake256_256_F
#   define xmss_H shake256_256_H
#   define xmss_H_msg shake256_256_H_msg
#   define xmss_PRF shake256_256_PRF
#   define xmss_PRFkeygen shake256_256_PRFkeygen
#   define xmss_PRFindex shake256_256_PRFindex

#   define HASH_ABSTRACTION(hashes)

#else

#   error Invalid hash configuration.

#endif

/**
 * @brief
 * Returns the hash functions for the specified parameter set.
 *
 * @details
 * When compiled without hash abstraction support, this function still verifies that the required hash function for this
 * parameter_set is compiled in.
 *
 * @param[out] hash_functions   Location to put the hash function pointers.
 * @param[in]  parameter_set    The parameter set.
 * @retval XMSS_OKAY    Success.
 * @retval XMSS_ERR_INVALID_ARGUMENT    parameter_set is unsupported or invalid.
 * @retval XMSS_ERR_NULL_POINTER        hash_functions was NULL.
 */
XmssError xmss_get_hash_functions(HASH_ABSTRACTION(xmss_hashes *restrict hash_functions)
    XmssParameterSetOID parameter_set);

#endif /* !XMSS_XMSS_HASHES_H_INCLUDED */
