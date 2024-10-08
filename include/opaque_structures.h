/*
 * SPDX-FileCopyrightText: 2022 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Thomas Schaap
 */

/**
 * @file
 * @brief
 * Public definitions of opaque structures and memory management calls for those.
 *
 * @details
 * There is no need to include this header explicitly. Instead, include either verification.h or signing.h.
 */

#pragma once

#ifndef XMSS_OPAQUE_STRUCTURES_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_OPAQUE_STRUCTURES_H_INCLUDED

#include "types.h"
#include "compat.h"

/**
 * @brief
 * The context of an instantiation of the signing library.
 *
 * @details
 * The signing context defines the parameter set and the hash functions to use.
 *
 * When creating an XmssSigningContext, the #XMSS_SIGNING_CONTEXT_SIZE macro can be used to allocate the correct size.
 *
 * XmssSigningContext is an opaque type, do not access its members.
 */
typedef struct XmssSigningContext XmssSigningContext;

/**
 * @brief
 * The size in bytes of an XmssSigningContext.
 */
#define XMSS_SIGNING_CONTEXT_SIZE (4u + 4u + 4u + 4u + 4u * sizeof(void(*)(void)))

/**
 * @brief
 * Deallocate an XmssSigningContext structure.
 *
 * @details
 * Note that the signing context will be deallocated using the memory deallocation function that is contained inside the
 * initialized structure itself. Deallocating a partially initialized signing context, which is impossible to obtain,
 * would not work.
 *
 * @param[in] signing_context The structure to deallocate. May be NULL.
 */
void xmss_free_signing_context(XmssSigningContext *signing_context);

/**
 * @brief
 * In-memory representation of a loaded cache.
 *
 * @details
 * When creating an XmssInternalCache, the #XMSS_INTERNAL_CACHE_SIZE() macro can be used to allocate the correct size.
 *
 * XmssInternalCache is an opaque type, do not access its members.
 */
typedef struct XmssInternalCache XmssInternalCache;

/**
 * @brief
 * The number of cached entries for a specific cache configuration.
 *
 * @note The arguments to #XMSS_CACHE_ENTRY_COUNT() will be evaluated multiple times.
 *
 * @param[in] cache_type    The cache type that is used.
 * @param[in] cache_level   The cache level that is to be held.
 * @param[in] param_set     The parameter set of the key for which the cache will be used.
 * @see xmss_generate_public_key() for more information about the cache type and level.
 */
#define XMSS_CACHE_ENTRY_COUNT(cache_type, cache_level, param_set) \
    ((cache_type) == XMSS_CACHE_NONE ? 0u : \
        ((cache_level) >= XMSS_TREE_DEPTH(param_set) ? 0u : \
            ((cache_type) == XMSS_CACHE_SINGLE_LEVEL ? (1u << (XMSS_TREE_DEPTH(param_set) - (cache_level))) : \
                ((cache_type) == XMSS_CACHE_TOP ? ((1u << ((XMSS_TREE_DEPTH(param_set) - (cache_level)) + 1u)) - 1u) : \
                    0u /* Garbage in, 0 out. */ \
                ) \
            ) \
        ) \
    )

/**
 * @brief
 * The size in bytes of an XmssInternalCache.
 *
 * @note The arguments to #XMSS_INTERNAL_CACHE_SIZE() will be evaluated multiple times.
 *
 * @param[in] cache_type    The cache type that is used.
 * @param[in] cache_level   The cache level that is to be held.
 * @param[in] param_set     The parameter set of the key for which the cache will be used.
 * @see xmss_generate_public_key() for more information about the cache type and level.
 */
#define XMSS_INTERNAL_CACHE_SIZE(cache_type, cache_level, param_set) \
    (4 + 4 + sizeof(XmssValue256) * XMSS_CACHE_ENTRY_COUNT((cache_type), (cache_level), (param_set)))

/**
 * @brief
 * The size in bytes of the XmssInternalCache public key generation cache.
 *
 * @param[in] number_of_partitions  The number of partitions in which to perform the public key generation.
*/
#define XMSS_PUBLIC_KEY_GENERATION_CACHE_SIZE(number_of_partitions) \
    (4 + 4 + sizeof(XmssValue256) * (number_of_partitions))

/**
 * @brief
 * Context for using the signature generation part of the library, with a loaded private key partition.
 *
 * @details
 * When creating an XmssKeyContext, the #XMSS_KEY_CONTEXT_SIZE macro can be used to allocate the correct size.
 *
 * XmssKeyContext is an opaque type, do not access its members.
 */
typedef struct XmssKeyContext XmssKeyContext;

/**
 * @brief
 * The size in bytes of the stateful part of a private key.
 *
 * @details
 * For internal library use only.
 */
#define XMSS_PRIVATE_KEY_STATEFUL_PART_SIZE (4u + 4u)

/**
 * @brief
 * The size in bytes of the stateless part of a private key.
 *
 * @details
 * For internal library use only.
 */
#define XMSS_PRIVATE_KEY_STATELESS_PART_SIZE (32u + 32u + 4u + 4u + 32u + sizeof(XmssValue256) + 32u)

/**
 * @brief
 * The size in bytes of an XmssKeyContext.
 *
 * @note The `param_set` argument will be evaluated multiple times.
 *
 * @param[in] param_set             The #XmssParameterSetOID that is to be used for the private key.
 * @param[in] obfuscation_setting   The #XmssIndexObfuscationSetting that is to be used with the private key.
 */
#define XMSS_KEY_CONTEXT_SIZE(param_set, obfuscation_setting) \
    (4u + 4u + XMSS_SIGNING_CONTEXT_SIZE + XMSS_PRIVATE_KEY_STATELESS_PART_SIZE + \
     2u * XMSS_PRIVATE_KEY_STATEFUL_PART_SIZE + 3 * sizeof(XmssValue256) + sizeof(void*) + 4u + 4u + \
     4u * (1u << XMSS_TREE_DEPTH(param_set)) * ((obfuscation_setting) == XMSS_INDEX_OBFUSCATION_ON ? 1u : 0u))

/**
 * @brief
 * Deallocate an XmssKeyContext structure.
 *
 * @details
 * All secret data is securely erased.
 *
 * @param[in] key_context   The structure to deallocate. May be NULL.
 */
void xmss_free_key_context(XmssKeyContext *key_context);

/**
 * @brief
 * The temporary context to gather all the results of generating a public key.
 *
 * @details
 * When creating an XmssKeyGenerationContext, the #XMSS_KEY_GENERATION_CONTEXT_SIZE macro may be used to allocate the
 * correct size.
 *
 * The elements of an XmssKeyGenerationContext are generally to be considered invalid outside of their specific use in
 * the public key generation process.
 *
 * XmssKeyGenerationContext is an opaque type, do not access its members.
 */
typedef struct XmssKeyGenerationContext XmssKeyGenerationContext;

/**
 * @brief
 * The size in bytes of XmssKeyGenerationContext.
 *
 * @param[in] generation_partitions The number of calculation partitions that will divide the work.
 * @see xmss_generate_public_key() for more information about generation_partitions.
 */
#define XMSS_KEY_GENERATION_CONTEXT_SIZE(generation_partitions) \
    (sizeof(void*) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(void*) + sizeof(void*) + \
        sizeof(uint32_t) * (generation_partitions))

/**
 * @brief
 * Deallocate an XmssKeyGenerationContext structure.
 *
 * @details
 * Deallocate the key generation context structure and the associated caches that have not been transferred
 * to other structures.
 *
 * @param[in] key_generation_context    The structure the deallocate. May be NULL.
 */
void xmss_free_key_generation_context(XmssKeyGenerationContext *key_generation_context);

#endif /* !XMSS_OPAQUE_STRUCTURES_H_INCLUDED */
