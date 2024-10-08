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
 *    supposed to contain an `xmss_hashes *hash_functions` member that either points to `sha256_xmss_hashes` or to
 *    `shake256_256_xmss_hashes`.
 *
 *    You call the XMSS `F(...)` hash function by writing: `xmss_F(HASH_FUNCTIONS_FROM(*context) ...)`.
 *
 *    This will then call the right function. Note that in this case there is always a function call; it cannot be
 *    inlined.
 *
 * 2. The library is compiled to support either SHA-256 *or* SHAKE256/256. In this case there is no context member,
 *    but the syntax is still `xmss_F(HASH_FUNCTIONS_FROM(*context) ...)`. The macro will expand directly to
 *    the implementing function, without using the parameter. This allows the compiler to inline the call, without
 *    unnecessary dereferencing. In fact, neither `sha256_xmss_hashes` nor `shake256_256_xmss_hashes` will be defined,
 *    so the addresses of the functions are never taken. If all calls are inlined, the 'function' will not even exist.
 *    Of course, this is up to the compiler and its optimization settings.
 *
 * Usage:
 *
 * - Always include just `xmss_hashes.h`
 * - Guard your hash abstraction context variable with `#if XMSS_ENABLE_HASH_ABSTRACTION`
 * - Call the hash function as `xmss_xxx(HASH_FUNCTIONS_FROM(*context) ...)`.
 *
 *   NOTE: There is no comma between `HASH_FUNCTIONS_FROM(*context)` and the next argument.
 *
 * Functions that accept the hash functions as a parameter should use #HASH_FUNCTIONS_PARAMETER *without a comma*
 * before the next argument. When hash abstractions are disabled, this becomes a no-op.
 *
 * Functions that need the hash functions based on a given parameter_set should use #DEFINE_HASH_FUNCTIONS and
 * #INITIALIZE_HASH_FUNCTIONS.
 *
 * Functions that need to forward the hash functions from either their parameter (#HASH_FUNCTIONS_PARAMETER) or from
 * their local variable (#DEFINE_HASH_FUNCTIONS), can simply call for example `xmss_F(HASH_FUNCTIONS ...)`.
 * Note again the absence of a comma between #HASH_FUNCTIONS and the next argument.
 */

#pragma once

#ifndef XMSS_XMSS_HASHES_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_XMSS_HASHES_H_INCLUDED

#include "config.h"
#include "libxmss.h"
#include "structures.h"
#include "xmss_hashes_base.h"

#if XMSS_ENABLE_HASH_ABSTRACTION

/**
 * @brief
 * Used as the first parameter in the signature of functions that use the XMSS hash functions.
 *
 * @remarks
 * When hash abstractions are disabled, this is a no-op.
 */
#   define HASH_FUNCTIONS_PARAMETER const xmss_hashes *const hash_functions,

/**
 * @brief
 * Function-like macro to assert that the #HASH_FUNCTIONS_PARAMETER is not NULL.
 *
 * @remarks
 * When hash abstractions are disabled, this is a no-op.
 */
#   define ASSERT_HASH_FUNCTIONS() assert(hash_functions != NULL); do { } while(0)

/**
 * @brief
 * Used within functions that require the XMSS hash functions.
 *
 * Use #INITIALIZE_HASH_FUNCTIONS to initialize the defined hash_functions variable.
 *
 * @remarks
 * When hash abstractions are disabled, this is a no-op.
 */
#   define DEFINE_HASH_FUNCTIONS const xmss_hashes *hash_functions = NULL

/**
 * @brief
 * Used to initialize the hash_functions variable define with #DEFINE_HASH_FUNCTIONS.
 *
 * @remarks
 * When hash abstractions are disabled, this still validates whether the given parameter set is supported.
 *
 * @param[in] parameter_set   The #XmssParameterSetOID that determines the hash algorithm.
 */
#   define INITIALIZE_HASH_FUNCTIONS(parameter_set) xmss_get_hash_functions(&hash_functions, parameter_set)

/**
 * @brief
 * Used as the first argument to any function that require the XMSS hash functions.
 * Use this only when referring #HASH_FUNCTIONS_PARAMETER or #DEFINE_HASH_FUNCTIONS.
 * Use #HASH_FUNCTIONS_FROM in other cases.
 *
 * @remarks
 * When hash abstractions are disabled, this is a no-op.
 */
#   define HASH_FUNCTIONS hash_functions,

/**
 * @brief
 * Used as the first argument to any function that uses the XMSS hash functions.
 * Use this only when referring to an xmss_hashes pointer stored in a structure.
 * When referring to #HASH_FUNCTIONS_PARAMETER or #DEFINE_HASH_FUNCTIONS, use #HASH_FUNCTIONS instead.
 *
 * @remarks
 * When hash abstractions are disabled, this is a no-op.
 *
 * @param[in] container   A container object with an xmss_hashes *hash_functions member.
 */
#   define HASH_FUNCTIONS_FROM(container) (container).hash_functions,

/*
 * This is the implementation of the XMSS_xxx() specialized hash functions for:
 * - SHA-256 support
 * - SHAKE256/256 support
 *
 * The functions are relayed to the corresponding algorithm.
 */

/**
 * @copydoc prototype_F
 * @param[in]   hash_functions  The hash function to use.
 *
 * @see prototype_F
 */
static inline void xmss_F(HASH_FUNCTIONS_PARAMETER XmssNativeValue256 *const native_digest, const Input_F *const input)
{
    (hash_functions->F)(native_digest, input);
}

/**
 * @copydoc prototype_H
 * @param[in]   hash_functions  The hash function to use.
 *
 * @see prototype_H
 */
static inline void xmss_H(HASH_FUNCTIONS_PARAMETER XmssNativeValue256 *const native_digest, const Input_H *const input)
{
    (hash_functions->H)(native_digest, input);
}

/**
 * @copydoc prototype_H_msg_init
 * @param[in]   hash_functions  The hash function to use.
 *
 * @see prototype_H_msg_init
 */
static inline void xmss_H_msg_init(HASH_FUNCTIONS_PARAMETER XmssHMsgCtx *const ctx, const Input_H_msg *const input)
{
    (hash_functions->H_msg_init)(ctx, input);
}

/**
 * @copydoc prototype_H_msg_update
 * @param[in]   hash_functions  The hash function to use.
 *
 * @see prototype_H_msg_update
 */
static inline void xmss_H_msg_update(HASH_FUNCTIONS_PARAMETER XmssHMsgCtx *const ctx, const uint8_t *const part,
    const size_t part_length, const uint8_t *volatile *const part_verify)
{
    (hash_functions->H_msg_update)(ctx, part, part_length, part_verify);
}

/**
 * @copydoc prototype_H_msg_finalize
 * @param[in]   hash_functions  The hash function to use.
 *
 * @see prototype_H_msg_finalize
 */
static inline void xmss_H_msg_finalize(HASH_FUNCTIONS_PARAMETER XmssNativeValue256 *const native_digest,
    XmssHMsgCtx *const ctx)
{
    (hash_functions->H_msg_finalize)(native_digest, ctx);
}

/**
 * @copydoc prototype_PRF
 * @param[in]   hash_functions  The hash function to use.
 *
 * @see prototype_PRF
 */
static inline void xmss_PRF(HASH_FUNCTIONS_PARAMETER XmssNativeValue256 *const native_digest,
    const Input_PRF *const input)
{
    (hash_functions->PRF)(native_digest, input);
}

#if XMSS_ENABLE_SIGNING

/**
 * @copydoc prototype_PRFkeygen
 * @param[in]   hash_functions  The hash function to use.
 *
 * @see prototype_PRFkeygen
 */
static inline void xmss_PRFkeygen(HASH_FUNCTIONS_PARAMETER XmssNativeValue256 *const native_digest,
    const Input_PRFkeygen *const input)
{
    (hash_functions->PRFkeygen)(native_digest, input);
}

/**
 * @copydoc prototype_PRFindex
 * @param[in]   hash_functions  The hash function to use.
 *
 * @see prototype_PRFindex
 */
static inline void xmss_PRFindex(HASH_FUNCTIONS_PARAMETER XmssNativeValue256 *const native_digest,
    const Input_PRFindex *const input)
{
    (hash_functions->PRFindex)(native_digest, input);
}

/**
 * @copydoc prototype_digest
 * @param[in]   hash_functions  The hash function to use.
 *
 * @see prototype_digest
 */
static inline void xmss_digest(HASH_FUNCTIONS_PARAMETER XmssValue256 *const digest, const uint8_t *const message,
    const size_t message_length)
{
    (hash_functions->digest)(digest, message, message_length);
}

/**
 * @copydoc prototype_native_digest
 * @param[in]   hash_functions  The hash function to use.
 *
 * @see prototype_native_digest
 */
static inline void xmss_native_digest(HASH_FUNCTIONS_PARAMETER XmssNativeValue256 *const native_digest,
    const uint32_t *const words, const size_t word_count)
{
    (hash_functions->native_digest)(native_digest, words, word_count);
}

#endif /* XMSS_ENABLE_SIGNING */

#else /* !XMSS_ENABLE_HASH_ABSTRACTION */

/* This removes the entire abstraction layer, in case only a single hashing algorithm is enabled. */

#   define HASH_FUNCTIONS_PARAMETER
#   define ASSERT_HASH_FUNCTIONS() do { } while(0)
#   define DEFINE_HASH_FUNCTIONS do { } while(0)
#   define INITIALIZE_HASH_FUNCTIONS(parameter_set) xmss_get_hash_functions(parameter_set)
#   define HASH_FUNCTIONS
#   define HASH_FUNCTIONS_FROM(container)

#   if XMSS_ENABLE_SHA256

/*
 * This is the implementation of the XMSS specialized hash functions if only SHA-256 is enabled.
 *
 * At this level of "abstraction" there really is no abstraction.
 * The specialized functions are macros that directly expand to the corresponding SHA-256 implementation,
 *      which is even inlined for the internal implementation (default).
 *
 * This optimizes both performance *and* code size.
 */

#       include "sha256_xmss_hashes.h"

#       define xmss_F sha256_F
#       define xmss_H sha256_H
#       define xmss_H_msg sha256_H_msg
#       define xmss_H_msg_init sha256_H_msg_init
#       define xmss_H_msg_update sha256_H_msg_update
#       define xmss_H_msg_finalize sha256_H_msg_finalize
#       define xmss_PRF sha256_PRF
#       if XMSS_ENABLE_SIGNING
#           define xmss_PRFkeygen sha256_PRFkeygen
#           define xmss_PRFindex sha256_PRFindex
#           define xmss_digest sha256_digest
#           define xmss_native_digest sha256_native_digest
#       endif

#   elif XMSS_ENABLE_SHAKE256_256

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

#       include "shake256_256_xmss_hashes.h"

#       define xmss_F shake256_256_F
#       define xmss_H shake256_256_H
#       define xmss_H_msg shake256_256_H_msg
#       define xmss_H_msg_init shake256_256_H_msg_init
#       define xmss_H_msg_update shake256_256_H_msg_update
#       define xmss_H_msg_finalize shake256_256_H_msg_finalize
#       define xmss_PRF shake256_256_PRF
#       if XMSS_ENABLE_SIGNING
#           define xmss_PRFkeygen shake256_256_PRFkeygen
#           define xmss_PRFindex shake256_256_PRFindex
#           define xmss_digest shake256_256_digest
#           define xmss_native_digest shake256_256_native_digest
#       endif

#   else

#       error Invalid hash configuration.

#   endif

#endif /* !XMSS_ENABLE_HASH_ABSTRACTION */

/**
 * @brief
 * Returns the hash functions for the specified parameter set.
 *
 * Do not call this function directly, instead use #INITIALIZE_HASH_FUNCTIONS.
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
LIBXMSS_STATIC
XmssError xmss_get_hash_functions(
#if XMSS_ENABLE_HASH_ABSTRACTION
    const xmss_hashes **hash_functions,
#endif
    XmssParameterSetOID parameter_set);

#endif /* !XMSS_XMSS_HASHES_H_INCLUDED */
