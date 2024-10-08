/*
 * SPDX-FileCopyrightText: 2022 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Pepijn Westen
 * SPDX-FileContributor: Max Fillinger
 */

/**
 * @file
 * @brief
 * XMSS signature library.
 */

#include "config.h"

#if !XMSS_ENABLE_SIGNING
#   error "Signing support is disabled, so this source file must not be compiled."
#endif

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "signing.h"

#include "compat_stdatomic.h"
#include "endianness.h"
#include "fault_detection_helpers.h"
#include "index_permutation.h"
#include "signing_private.h"
#include "structures.h"
#include "types.h"
#include "utils.h"
#include "wotsp_signing.h"
#include "xmss_hashes.h"
#include "xmss_tree.h"
#include "zeroize.h"

XmssError xmss_context_initialize(XmssSigningContext **const context, const XmssParameterSetOID parameter_set,
    const XmssReallocFunction custom_realloc, const XmssFreeFunction custom_free, const XmssZeroizeFunction zeroize)
{
    XmssSigningContext *reallocated_context = NULL;
    XmssError err_code = XMSS_UNINITIALIZED;

    if (context == NULL || custom_realloc == NULL || custom_free == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    reallocated_context = custom_realloc((void *)*context, sizeof(XmssSigningContext));

    if (reallocated_context == NULL) {
        /* Do not free, as it's the user's resource. */
        *context = NULL;
        return XMSS_ERR_ALLOC_ERROR;
    }

    *context = reallocated_context;
    /* Since realloc may return partially uninitialized memory, memset the entire struct to 0. */
    memset(*context, 0, sizeof(XmssSigningContext));

    (*context)->parameter_set = (uint32_t)parameter_set;
    (*context)->redundant_parameter_set = (uint32_t)parameter_set;
    (*context)->realloc = custom_realloc;
    (*context)->free = custom_free;
    (*context)->pad_ = 0;
    (*context)->zeroize = (zeroize != NULL) ? zeroize : xmss_zeroize;

    DEFINE_HASH_FUNCTIONS;
    err_code = INITIALIZE_HASH_FUNCTIONS(parameter_set);
    if (err_code != XMSS_OKAY) {
        (*context)->free(*context);
        *context = NULL;
        return err_code;
    }
#if XMSS_ENABLE_HASH_ABSTRACTION
    (*context)->hash_functions = hash_functions;
#else
    (*context)->pad_hash_functions = NULL;
#endif
    if ((*context)->parameter_set != (*context)->redundant_parameter_set) {
        (*context)->free(*context);
        *context = NULL;
        return XMSS_ERR_FAULT_DETECTED;
    }

    (*context)->initialized = (uint32_t)XMSS_INITIALIZATION_INITIALIZED;

    return err_code;
}

XmssError xmss_load_public_key(XmssInternalCache **const cache, XmssKeyContext *const key_context,
    const XmssPublicKeyInternalBlob *const public_key)
{
    /* To protect against bit errors in the CPU's flag register, we execute some if-statements in this function twice.
     * The variables being checked are volatile, so the compiler is not allowed to optimize away the redundant if. */

    /* No redundant NULL pointer checks because a bit error here can only cause a segfault. */
    if (cache == NULL || key_context == NULL || public_key == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }
    XmssPublicKeyInternal *pub_key_internal = NULL;
    volatile XmssError err_code = XMSS_UNINITIALIZED;
    XmssCacheType cache_type = XMSS_CACHE_NONE;

    /* xmss_verify_public_key() also checks that key_context is initialized. */
    err_code = xmss_verify_public_key(public_key, NULL, key_context);
    /* Double-check this result so a single bit error cannot cause us to ignore a failed integrity check. */
    REDUNDANT_RETURN_ERR(err_code);

    pub_key_internal = (XmssPublicKeyInternal *)public_key->data;
    cache_type = (XmssCacheType)convert_big_endian_word(pub_key_internal->cache_type);

    if (cache_type == XMSS_CACHE_NONE) {
        key_context->cache = NULL;
    }
    else {
        uint32_t cache_level = convert_big_endian_word(pub_key_internal->cache_level);
        XmssInternalCache *reallocated_cache = key_context->context.realloc(
            *cache, XMSS_INTERNAL_CACHE_SIZE(cache_type, cache_level, key_context->context.parameter_set));

        if (reallocated_cache == NULL) {
            return XMSS_ERR_ALLOC_ERROR;
        }
        reallocated_cache->cache_type = (uint32_t)cache_type;
        reallocated_cache->cache_level = cache_level;
        big_endian_to_native(reallocated_cache->cache[0].data, pub_key_internal->cache[0].data,
            XMSS_VALUE_256_WORDS * XMSS_CACHE_ENTRY_COUNT(cache_type, cache_level, key_context->context.parameter_set));
        key_context->cache = reallocated_cache;
        *cache = NULL;
    }

    big_endian_to_native_256(&key_context->public_key_root, &pub_key_internal->root);
    key_context->initialized = (uint32_t)XMSS_INITIALIZATION_WITH_PUBLIC_KEY;

    return err_code;
}

void xmss_free_signing_context(XmssSigningContext *signing_context) {
    if (signing_context != NULL && signing_context->initialized == XMSS_INITIALIZATION_INITIALIZED) {
        signing_context->free(signing_context);
    }
}

/**
 * @brief
 * Check that the XmssSigningContext is initialized and complete.
 *
 * @details
 * This function only checks for bit errors where they could cause loading invalid keys.
 *
 * @param[in] signing_context   The signing context to check.
 *
 * @retval XMSS_OKAY    The structure is correct.
 * @retval XMSS_ERR_BAD_CONTEXT The structure is incomplete or not initialized.
 * @retval XMSS_ERR_FAULT_DETECTED  A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
static XmssError check_signing_context(const XmssSigningContext *signing_context)
{
    if (signing_context == NULL) {
        return XMSS_ERR_BAD_CONTEXT;
    }
    /* signing_context is not concerned with the public key, so XMSS_INITIALIZATION_INITIALIZED is the only valid value.
     */
    if (signing_context->initialized != XMSS_INITIALIZATION_INITIALIZED) {
        return XMSS_ERR_BAD_CONTEXT;
    }
#if XMSS_ENABLE_HASH_ABSTRACTION
    if (signing_context->hash_functions == NULL) {
        return XMSS_ERR_BAD_CONTEXT;
    }
#else
    if (signing_context->pad_hash_functions != NULL) {
        return XMSS_ERR_BAD_CONTEXT;
    }
#endif
    if (signing_context->free == NULL || signing_context->realloc == NULL || signing_context->zeroize == NULL) {
        return XMSS_ERR_BAD_CONTEXT;
    }
    if (signing_context->parameter_set != signing_context->redundant_parameter_set) {
        return XMSS_ERR_FAULT_DETECTED;
    }

    return XMSS_OKAY;
}

/**
 * @brief
 * Get the size of the index space for the given parameter set.
 *
 * @details
 * Should only be used for supported parameter sets.
 *
 * @param[in] parameter_set The parameter set for which to get the index space size.
 *
 * @returns The size of the index space for the given parameter set, or 0 if parameter set is unsupported.
 */
static inline uint32_t index_space_size(const XmssParameterSetOID parameter_set)
{
    switch  (parameter_set) {
        case XMSS_PARAM_SHA2_10_256:
        case XMSS_PARAM_SHAKE256_10_256:
            return 1 << 10;
        case XMSS_PARAM_SHA2_16_256:
        case XMSS_PARAM_SHAKE256_16_256:
            return 1 << 16;
        case XMSS_PARAM_SHA2_20_256:
        case XMSS_PARAM_SHAKE256_20_256:
            return 1 << 20;
        default:
            assert(0);
            return 0;
    }
}

/**
 * @brief
 * Calculate the height in the parameter set to get the desired number of partitions.
 *
 * @param[out]  height_out              The height to determine.
 * @param[in]   number_of_partitions    The number of partitions, must be an integer power of 2.
 * @param[in]   parameter_set           The parameter set of the tree.
 * @retval XMSS_OKAY    Success.
 * @retval XMSS_ERR_NULL_POINTER    A NULL pointer was passed.
 * @retval XMSS_ERR_INVALID_ARGUMENT    The number_of_partitions is not an integer power of 2.
 */
static XmssError partitions_to_tree_height(uint32_t *height_out, uint32_t number_of_partitions,
        XmssParameterSetOID parameter_set)
{
    /* The index space of the tree at height 0. */
    const uint32_t index_space = index_space_size(parameter_set);
    /* The total height of the entire tree. */
    const uint_fast8_t tree_height = XMSS_TREE_DEPTH(parameter_set);
    if (height_out == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }
    for (uint_fast8_t height = 0; height <= tree_height; height++) {
        if ((index_space >> height) == number_of_partitions) {
            *height_out = height;
            return XMSS_OKAY;
        }
    }
    return XMSS_ERR_INVALID_ARGUMENT;
}

/**
 * @brief
 * Perform a shallow check that the key_context is well-formed, and that the enclosed signing_context is complete.
 *
 * @warning this is not a full validation of a key context, it assumes that validation is already done as part of the
 * generation or import of a private key.
 *
 * @param[in] key_context The key context to check.
 * @retval XMSS_OKAY    The check passed.
 * @retval XMSS_ERR_NULL_POINTER    A NULL pointer was passed.
 * @retval XMSS_ERR_BAD_CONTEXT     The key_context is uninitialized.
 */
static XmssError check_key_context_well_formed(const XmssKeyContext *const key_context)
{
    if (key_context == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }
    if (key_context->initialized != XMSS_INITIALIZATION_INITIALIZED &&
            key_context->initialized != XMSS_INITIALIZATION_WITH_PUBLIC_KEY) {
        return XMSS_ERR_BAD_CONTEXT;
    }
    if (key_context->private_stateful.partition_start != key_context->redundant_private_stateful.partition_start
            || key_context->private_stateful.partition_end != key_context->redundant_private_stateful.partition_end
            || memcmp(key_context->private_key_digest.data, key_context->redundant_private_key_digest.data,
                sizeof(XmssValue256)) != 0) {
        return XMSS_ERR_FAULT_DETECTED;
    }

    return check_signing_context(&key_context->context);
}

void xmss_free_key_context(XmssKeyContext *key_context)
{
    if (key_context == NULL) {
        return;
    }

    /* In case context points into key_context, copy the relevant functions. */
    XmssFreeFunction free_function = key_context->context.free;
    XmssZeroizeFunction zeroize_function = key_context->context.zeroize;

    if (zeroize_function == (XmssZeroizeFunction)NULL) {
        zeroize_function = xmss_zeroize;
    }

    /* Copy the pointer to the cache before zeroizing the key context, so it can be freed. */
    XmssInternalCache *cache = key_context->cache;
    /* Depending on the parameter set and index_obfuscation_setting, the key_context's size might be larger than the
     * size of the XmssKeyContext type, so we first determine those parameters. */
    XmssParameterSetOID parameter_set = (XmssParameterSetOID)key_context->context.parameter_set;
    XmssIndexObfuscationSetting index_obfuscation_setting =
            (XmssIndexObfuscationSetting)key_context->private_stateless.index_obfuscation_setting;

    /* XMSS_KEY_CONTEXT_SIZE will return the XmssKeyContext base size if either parameter_set or
     * index_obfuscation_setting is any unsupported value, so the resulting size will still be valid in case those
     * fields of the key_context are set to unsupported values. */
    const size_t key_context_size = XMSS_KEY_CONTEXT_SIZE(parameter_set, index_obfuscation_setting);
    zeroize_function(key_context, key_context_size);

    /* In the unexpected situation that no free function has been set, we don't know how to free the buffer, so we
     * only free the key_context if its context contained a non-NULL free function. */
    if (free_function != (XmssFreeFunction)NULL) {
        free_function(cache);
        free_function(key_context);
    }
}

/**
 * @brief
 * Check that the integrity digest of a blob matches the content.
 *
 * @details
 * This function is resilient against bit errors in the sense that a single random bit error cannot cause it to output
 * VALUES_ARE_EQUAL when the digests do not match. If the return value of this function is checked, it should be stored
 * in a volatile variable which is then checked twice, to ensure that a bit error cannot skip the check.
 *
 * @warning
 * The caller is responsible to ensure that all pointers are valid. This is not checked.
 *
 * @param[in] hash_functions    Hash functions to use for checking the integrity.
 * @param[in] integrity_digest  Integrity digest, found at the start of the struct.
 * @param[in] data              Content of the struct after the integrity digest.
 * @param[in] size              Size of data.
 * @retval VALUES_ARE_EQUAL     The digests match.
 * @retval VALUES_ARE_NOT_EQUAL The digests do not match.
 */
static inline ValueCompareResult check_integrity_digest(HASH_FUNCTIONS_PARAMETER
    const XmssValue256 *const integrity_digest, const uint8_t *const data, const size_t size)
{
    ASSERT_HASH_FUNCTIONS();
    assert(integrity_digest != NULL && data != NULL);

    XmssValue256 digest = { 0 };
    xmss_digest(HASH_FUNCTIONS &digest, data, size);
    /* A bit error in size could lead to undefined behavior. We do not check for it, because in practice, reading an
     * incorrect number of bytes will lead either to an incorrect integrity digest, or to a segfault due to an
     * out-of-bounds read. */
    return compare_values_256(integrity_digest, &digest);
}


/**
 * @brief
 * Check that the index obfuscation permutation in the key_context is in a consistent state.
 *
 * @details
 * This checks that if index obfuscation is enabled, the index obfuscation permutation has the expected sum, and has the
 * expected sum of squares.
 * After that, it computes a digest and checks that the digest matches the previously computed digest.
 *
 * @param[in]   key_context     The key context for which to check the index obfuscation permutation.
 * @retval XMSS_OKAY    The check passed.
 * @retval XMSS_ERR_NULL_POINTER    A NULL pointer was passed.
 * @retval XMSS_ERR_BAD_CONTEXT     Some part of the key_context did not match expectation.
 * @retval XMSS_ERR_FAULT_DETECTED  A bit error was detected.
 *                                      (Note that bit errors can also cause different errors or segfaults.)
*/
static XmssError index_permutation_check(const XmssKeyContext *const key_context)
{
    if (key_context == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    XmssError result = check_signing_context(&key_context->context);
    REDUNDANT_RETURN_ERR(result);

    if (key_context->private_stateless.index_obfuscation_setting == XMSS_INDEX_OBFUSCATION_OFF) {
        return result;
    }

    const uint32_t index_space_size = 1 << XMSS_TREE_DEPTH(key_context->context.parameter_set);
    /* Two check sums are computed, one of all the indexes, and one of all the squared indexes.
     * This should give reasonably strong protection against (accidentally) generating a range that does not include
     * each index exactly once.
     * These check sums are then checked against the known answers.
    */
    uint64_t check_sum = 0;
    uint64_t check_square_sum = 0;
    /*
     * As the largest supported tree height L is 20, 60 bits should be sufficient to store the check sum of the squares:
     * The square of the largest index  has a value < 2^(L*2), and there are exactly 2^L elements in the summation,
     * yielding a result that is < 2^(3*L).
     */
    assert(XMSS_TREE_DEPTH(key_context->context.parameter_set) * 3 <= 60);

    for (uint_fast32_t index = 0; index < index_space_size; index++) {
        check_sum += key_context->obfuscation[index];
        check_square_sum += ((uint64_t)key_context->obfuscation[index]) * key_context->obfuscation[index];
    }
    if (check_sum != (uint64_t)(index_space_size - 1) * (index_space_size / 2)) {
        return XMSS_ERR_FAULT_DETECTED;
     }
     if (check_square_sum !=
            (uint64_t)(index_space_size - 1) * (index_space_size) * (2 * (index_space_size - 1ull) + 1) / 6) {
        return XMSS_ERR_FAULT_DETECTED;
     }
     /* Recompute the digest to check if it matches the digest in the stateless key part.
      * This does not use the check_integrity_digest function as a native digest function is used.
      */
    XmssNativeValue256 check_digest = {0};
    xmss_native_digest(HASH_FUNCTIONS_FROM(key_context->context) &check_digest, key_context->obfuscation,
        index_space_size);

    volatile ValueCompareResult digest_comparison = compare_native_values_256(&check_digest,
        &key_context->private_stateless.obfuscation_integrity);
    REDUNDANT_RETURN_IF(digest_comparison != VALUES_ARE_EQUAL, XMSS_ERR_FAULT_DETECTED);

    /* All checks succeeded. */
    return result;
}

/**
 * @brief
 * Populates the obfuscation array in the key_context, provided that index_obfuscation is enabled for the private key.
 *
 * @details
 * This function populates the obfuscation array but does not do any error checking.
 *
 * @param[in,out]   key_context The key context in which to populate the obfuscation data.
 * @retval XMSS_OKAY    Success.
 * @retval XMSS_ERR_NULL_POINTER    A NULL pointer was passed.
 * @retval XMSS_ERR_BAD_CONTEXT     index_obfuscation_setting is invalid or the the key_context is in an unexpected
 *                                  state.
*/
static XmssError populate_index_obfuscation_permutation(XmssKeyContext *key_context) {
    if (key_context == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    if (key_context->initialized != XMSS_INITIALIZATION_UNINITIALIZED) {
        return XMSS_ERR_BAD_CONTEXT;
    }

    /* If index obfuscation is disabled, there is nothing to do. */
    if (key_context->private_stateless.index_obfuscation_setting == XMSS_INDEX_OBFUSCATION_OFF) {
        return XMSS_OKAY;
    }

    if (key_context->private_stateless.index_obfuscation_setting != XMSS_INDEX_OBFUSCATION_ON) {
        return XMSS_ERR_BAD_CONTEXT;
    }
    uint32_t index_space_size = 1 << XMSS_TREE_DEPTH(key_context->context.parameter_set);
    return generate_pseudorandom_permutation(HASH_FUNCTIONS_FROM(key_context->context)
        key_context->obfuscation, index_space_size, &key_context->private_stateless.index_obfuscation_random,
        &key_context->private_stateless.seed);
}

/**
 * @brief
 * Generates the appropriate index obfuscation permutation, according to the index_obfuscation version, and stores the
 * digest over the obfuscation in the key_context.
 *
 * @details
 * This generates a pseudo-random permutation based on the public seed and the index obfuscation seed in the
 * key_context.
 * This generation should result in the same array of 32-bit integers regardless of endianness.
 *
 * This implementation first generates the permutation, computes the digest, uses index_permutation_check to check the
 * checksum and checksum of the squares, and then checks the digest again.
 * For digest computation, a native digest function is used to be able to compute a digest over a sequence of words that
 * are in native-endian byte order.
 * After canonicalization from native to big-endian, the digest will be the same regardless of endianness, providing
 * that the input consisted of the same sequence of 32-bit words.
 *
 * @param[in,out] key_context   The key context in which to generate the permutation, this should be in
 *                              XMSS_INITIALIZATION_UNINITIALIZED state, and should be large enough to fit the
 *                              XmssKeyContext with the permutation array.
 * @retval XMSS_OKAY    Success.
 * @retval XMSS_ERR_NULL_POINTER    A NULL pointer was passed.
 * @retval XMSS_ERR_BAD_CONTEXT     The context did not match expectation.
 * @retval XMSS_ERR_FAULT_DETECTED  A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
static XmssError generate_index_obfuscation_permutation(XmssKeyContext *key_context)
{
    volatile XmssError result = populate_index_obfuscation_permutation(key_context);

    REDUNDANT_RETURN_ERR(result);

    if (key_context->private_stateless.index_obfuscation_setting == XMSS_INDEX_OBFUSCATION_ON) {
        /* Compute the native digest. This will result in a (native) digest that should match (after canonicalization)
         * one generated using the same 32-bit words on a system with different endianness.
         */
        uint32_t index_space_size = 1 << XMSS_TREE_DEPTH(key_context->context.parameter_set);
        xmss_native_digest(HASH_FUNCTIONS_FROM(key_context->context)
            &key_context->private_stateless.obfuscation_integrity, key_context->obfuscation, index_space_size);

        /* Re-run the permutation generation algorithm to ensure that if bit errors affect the deterministic nature of
         * the pseudo-random generation, an error will be returned.
         */
        result = XMSS_UNINITIALIZED;
        result = populate_index_obfuscation_permutation(key_context);
        REDUNDANT_RETURN_ERR(result);
    }

    /* Use index_permutation_check to verify the check-sums, and re-compute the digest and compare it. */
    return index_permutation_check(key_context);
}

/**
 * @brief
 * Loads the index obfuscation into the key context.
 *
 * @details
 * Loads the index obfuscation into the key context and checks that the digest of the generated permutation matches the
 * stored digest in the key_context.
 *
 * @param[in,out]   key_context   The key context that contains the index_obfuscation_setting and required seeds.
 * @retval XMSS_OKAY    Success.
 * @retval XMSS_ERR_NULL_POINTER    A NULL pointer was passed.
 * @retval XMSS_ERR_BAD_CONTEXT     The context did not match expectations.
 * @retval XMSS_ERR_FAULT_DETECTED  A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
*/
static XmssError load_index_obfuscation_permutation(XmssKeyContext *key_context) {
    volatile XmssError result = populate_index_obfuscation_permutation(key_context);
    REDUNDANT_RETURN_ERR(result);
    /* Use index_permutation_check to verify the check-sums, and re-compute the digest and compare it. */
    return index_permutation_check(key_context);
}


/**
 * @brief
 * Obfuscate the index using the permutation stored in the key context.
 *
 * @details
 * If index permutation is enabled for the private key, use a pseudorandom permutation on the index space in order to
 * obfuscate the number of signatures created.
 * The permutation is generated using a fisher-yates shuffle and a pseudo random generator based on the
 * private key's index_obfuscation_seed, and stored in ram when the private key is generated or when a private key is
 * loaded.
 * The permutation array is checked for bit errors each time this function is used.
 *
 * @note this function does NULL checking on the inputs, but only checks the parts of the key_context that are relevant
 * for the index obfuscation function.
 *
 * @param[out]  obfuscated_index    The obfuscated index output parameter.
 * @param[in]   key_context         The key context for which to perform the obfuscation.
 * @param[in]   index               The index to obfuscate.
 * @retval XMSS_OKAY    obfuscated_index was successfully set.
 * @retval XMSS_ERR_NULL_POINTER    A NULL pointer was passed.
 * @retval XMSS_ERR_BAD_CONTEXT     The permutation data wasn't correctly populated in the key_context.
 * @retval XMSS_ERR_FAULT_DETECTED  A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
*/
static XmssError obfuscate_index(volatile uint32_t *obfuscated_index, const XmssKeyContext *const key_context,
    const uint32_t index)
{
    if (key_context == NULL || obfuscated_index == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }
    volatile XmssError result = index_permutation_check(key_context);
    REDUNDANT_RETURN_ERR(result);

    if (key_context->private_stateless.index_obfuscation_setting == XMSS_INDEX_OBFUSCATION_OFF) {
        *obfuscated_index = index;
        return XMSS_OKAY;
    } else if (key_context->private_stateless.index_obfuscation_setting != XMSS_INDEX_OBFUSCATION_ON) {
        return XMSS_ERR_BAD_CONTEXT;
    }
    if (index >= index_space_size((XmssParameterSetOID)key_context->context.parameter_set)) {
        return XMSS_ERR_INVALID_ARGUMENT;
    }
    *obfuscated_index = key_context->obfuscation[index];
    return XMSS_OKAY;
}

/**
 * @brief
 * Verify the stateless part of a private key.
 *
 * @details
 * This function checks the size, integrity digest and version. It also checks that the scheme identifier matches.
 * It is resilient against a single random bit error in the sense that such an error cannot cause the function to
 * wrongly return XMSS_OKAY.
 *
 * @param[in] hash_functions                Hash functions to check the integrity digest.
 * @param[in] private_key                   Private key blob to check.
 * @param[in] expected_scheme_identifier    Scheme identifier that should be contained in the blob.
 * @param[in] redundant_scheme_identifier   Redundant copy of expected_scheme_identifier, for bit error resilience.
 * @retval XMSS_OKAY    The blob is valid.
 * @retval XMSS_ERR_NULL_POINTER    private_key is NULL.
 * @retval XMSS_ERR_INVALID_BLOB    The size, integrity digest or version are incorrect.
 * @retval XMSS_ERR_ARGUMENT_MISMATCH   expected_scheme_identifier does not match.
 * @retval XMSS_ERR_FAULT_DETECTED  A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
static XmssError verify_private_key_stateless_internal(HASH_FUNCTIONS_PARAMETER
    const XmssPrivateKeyStatelessBlob *const private_key, const uint32_t expected_scheme_identifier,
    const uint32_t redundant_scheme_identifier)
{
    /* To protect against bit errors in the CPU's flag register, we execute some if-statements in this function twice.
     * The variables being checked are volatile, so the compiler is not allowed to optimize away the redundant if. */
    volatile ValueCompareResult value_cmp = VALUES_ARE_NOT_EQUAL;
    XmssPrivateKeyStateless *private_key_inner = NULL;

    if (expected_scheme_identifier != redundant_scheme_identifier) {
        return XMSS_ERR_FAULT_DETECTED;
    }

    /* No redundant NULL pointer check because a bit error can only lead to a segfault here. */
    if (private_key == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    /* Check the blob size. */
    if (private_key->data_size != XMSS_PRIVATE_KEY_STATELESS_BLOB_SIZE - sizeof(XmssPrivateKeyStatelessBlob)) {
        return XMSS_ERR_INVALID_BLOB;
    }
    private_key_inner = (XmssPrivateKeyStateless *)private_key->data;
    /* Check the version. */
    if (private_key_inner->private_key_stateless_version !=
            convert_big_endian_word(XMSS_VERSION_CURRENT_PRIVATE_KEY_STATELESS_STORAGE)) {
        return XMSS_ERR_INVALID_BLOB;
    }
    if (private_key_inner->redundant_version !=
            convert_big_endian_word(XMSS_VERSION_CURRENT_PRIVATE_KEY_STATELESS_STORAGE)) {
        return XMSS_ERR_INVALID_BLOB;
    }
    value_cmp = check_integrity_digest(HASH_FUNCTIONS &private_key_inner->integrity,
        private_key->data + sizeof(private_key_inner->integrity),
        private_key->data_size - sizeof(private_key_inner->integrity));
    REDUNDANT_RETURN_IF(value_cmp != VALUES_ARE_EQUAL, XMSS_ERR_FAULT_DETECTED);

    if (convert_big_endian_word(private_key_inner->scheme_identifier) != expected_scheme_identifier) {
        return XMSS_ERR_ARGUMENT_MISMATCH;
    }
    if (convert_big_endian_word(private_key_inner->redundant_scheme_identifier) != redundant_scheme_identifier) {
        return XMSS_ERR_FAULT_DETECTED;
    }
    return XMSS_OKAY;
}

XmssError xmss_verify_private_key_stateless(const XmssPrivateKeyStatelessBlob *const private_key,
    const XmssSigningContext *const context)
{
    volatile XmssError result = check_signing_context(context);
    REDUNDANT_RETURN_ERR(result);
    return verify_private_key_stateless_internal(HASH_FUNCTIONS_FROM(*context) private_key, context->parameter_set,
        context->redundant_parameter_set);
}

/**
 * @brief
 * Verify the XmssPrivateKeyStatefulBlob using the provided XmssSigningContext.
 *
 * @details
 * This function is bit error resilient in that a single random bit error cannot cause it to wrongly return XMSS_OKAY.
 * If its return value is checked, it should be stored in a volatile variable which is then checked twice.
 *
 * @param[in]  key_stateful The blob containing the stateful key part.
 * @param[in]  context      The signing context.
 * @retval XMSS_OKAY    The verification passed.
 * @retval XMSS_ERR_NULL_POINTER    key_stateful or context is NULL.
 * @retval XMSS_ERR_ARGUMENT_MISMATCH   The signing context and the blob are incompatible.
 * @retval XMSS_ERR_INVALID_BLOB        The digest did not verify or the blob did not conform to expectations.
 * @retval XMSS_ERR_FAULT_DETECTED  A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
static XmssError xmss_verify_private_key_stateful_blob(const XmssPrivateKeyStatefulBlob *const key_stateful,
    const XmssSigningContext *const context)
{
    /* To protect against bit errors in the CPU's flag register, we execute some if-statements in this function twice.
     * The variables being checked are volatile, so the compiler is not allowed to optimize away the redundant if. */

    volatile ValueCompareResult value_cmp = VALUES_ARE_NOT_EQUAL;
    XmssError result = check_signing_context(context);
    REDUNDANT_RETURN_ERR(result);

    /* No redundant NULL pointer checks because a bit error here can only lead to a segfault. */
    if (key_stateful == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }
    /* Check the blob size. No redundant check because a wrong size leads to a wrong integrity digest or a segfault. */
    if (key_stateful->data_size != XMSS_PRIVATE_KEY_STATEFUL_BLOB_SIZE - sizeof(XmssPrivateKeyStatefulBlob)) {
        return XMSS_ERR_INVALID_BLOB;
    }

    /* Check the version. */
    XmssPrivateKeyStateful *key_stateful_inner = (XmssPrivateKeyStateful *)key_stateful->data;
    if (key_stateful_inner->private_key_stateful_version !=
        convert_big_endian_word(XMSS_VERSION_CURRENT_PRIVATE_KEY_STATEFUL_STORAGE)) {
        return XMSS_ERR_INVALID_BLOB;
    }
    if (key_stateful_inner->redundant_version !=
        convert_big_endian_word(XMSS_VERSION_CURRENT_PRIVATE_KEY_STATEFUL_STORAGE)) {
        return XMSS_ERR_FAULT_DETECTED;
    }

    /* Check the partition. */
    if (key_stateful_inner->contents.partition_start != key_stateful_inner->redundant_contents.partition_start) {
        return XMSS_ERR_FAULT_DETECTED;
    }
    if (key_stateful_inner->contents.partition_end != key_stateful_inner->redundant_contents.partition_end) {
        return XMSS_ERR_FAULT_DETECTED;
    }

    /* Check the scheme identifier. */
    if (key_stateful_inner->scheme_identifier != convert_big_endian_word(context->parameter_set)) {
        return XMSS_ERR_ARGUMENT_MISMATCH;
    }
    if (key_stateful_inner->redundant_scheme_identifier != convert_big_endian_word(context->redundant_parameter_set)) {
        return XMSS_ERR_FAULT_DETECTED;
    }
    if (key_stateful_inner->scheme_identifier != key_stateful_inner->redundant_scheme_identifier) {
        return XMSS_ERR_FAULT_DETECTED;
    }

    value_cmp = check_integrity_digest(HASH_FUNCTIONS_FROM(*context) &key_stateful_inner->integrity,
        key_stateful->data + sizeof(key_stateful_inner->integrity),
        key_stateful->data_size - sizeof(key_stateful_inner->integrity));
    REDUNDANT_RETURN_IF(value_cmp != VALUES_ARE_EQUAL, XMSS_ERR_FAULT_DETECTED);

    return XMSS_OKAY;
}

XmssError xmss_verify_private_key_stateful(const XmssPrivateKeyStatefulBlob *const key_usage,
    const XmssPrivateKeyStatelessBlob *const private_key, const XmssKeyContext *const key_context,
    const XmssSigningContext *const signing_context)
{
    /* To protect against bit errors in the CPU's flag register, we execute some if-statements in this function twice.
     * The variables being checked are volatile, so the compiler is not allowed to optimize away the redundant if. */

    const XmssSigningContext *context = NULL;
    volatile ValueCompareResult value_cmp = VALUES_ARE_NOT_EQUAL;

    /* No redundant NULL pointer checks because a bit error here can only lead to a segfault. */
    if (key_usage == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }
    if (key_context == NULL) {
        if (signing_context == NULL) {
            /* Either a key context or a signing context must be supplied. */
            return XMSS_ERR_NULL_POINTER;
        }
        context = signing_context;
    } else {
        context = &key_context->context;
        if (signing_context != NULL) {
            if (signing_context->parameter_set != context->parameter_set) {
                return XMSS_ERR_ARGUMENT_MISMATCH;
            }
        }
    }

    /* xmss_verify_private_key_stateful_blob performs a sanity check of the signing context AND verifies the key_usage.
     */
    volatile XmssError result = xmss_verify_private_key_stateful_blob(key_usage, context);
    REDUNDANT_RETURN_ERR(result);

    /* Blob has been verified to be a XmssPrivateKeyStateful with a valid digest and a recognized storage version. */
    const XmssPrivateKeyStateful *stateful = (XmssPrivateKeyStateful *)key_usage->data;
    volatile bool verified_against_key_ctx = false;
    volatile bool verified_against_private_key = false;
    if (key_context != NULL) {
        result = XMSS_UNINITIALIZED;
        result = check_key_context_well_formed(key_context);
        REDUNDANT_RETURN_ERR(result);

        /* Check if the stateless part included in the key context matches the stateful blob. */
        value_cmp = compare_values_256(&key_context->private_key_digest, &stateful->digest_of_private_key_static_blob);
        REDUNDANT_RETURN_IF(value_cmp != VALUES_ARE_EQUAL, XMSS_ERR_ARGUMENT_MISMATCH);
        verified_against_key_ctx = true;
    }
    if (private_key != NULL) {
        /* Separate size check, to ensure that we can access the digest of the private key stateless blob. */
        if (private_key->data_size != XMSS_PRIVATE_KEY_STATELESS_BLOB_SIZE - sizeof(XmssPrivateKeyStatelessBlob)) {
            return XMSS_ERR_INVALID_BLOB;
        }

        const XmssPrivateKeyStateless *const stateless = (const XmssPrivateKeyStateless *)private_key->data;
        /*
         * Check that this is the private key stateless blob that corresponds to the private key stateful blob.
         * This check is optimistically performed before verifying the integrity of the private key stateless blob,
         * since that will spuriously fail if it uses a different hash than the private key stateful blob being
         * verified.
         */
        value_cmp = compare_values_256(&stateless->integrity, &stateful->digest_of_private_key_static_blob);
        REDUNDANT_RETURN_IF(value_cmp != VALUES_ARE_EQUAL, XMSS_ERR_ARGUMENT_MISMATCH);

        result = XMSS_UNINITIALIZED;
        result = xmss_verify_private_key_stateless(private_key, context);
        REDUNDANT_RETURN_ERR(result);

        verified_against_private_key = true;
    }

    /* Verify that a bit error didn't cause us to skip a check. */
    if (verified_against_key_ctx != (key_context != NULL) || verified_against_private_key != (private_key != NULL)) {
        return XMSS_ERR_FAULT_DETECTED;
    }
    return result;
}

XmssError xmss_get_caching_in_public_key(XmssCacheType *const cache_type, uint32_t *const cache_level,
    const XmssPublicKeyInternalBlob *const pub_key)
{
    if (cache_type == NULL || cache_level == NULL || pub_key == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    volatile XmssError err_code = xmss_verify_public_key(pub_key, NULL, NULL);
    REDUNDANT_RETURN_ERR(err_code);
    XmssPublicKeyInternal *pub_key_data = (XmssPublicKeyInternal *)pub_key->data;
    *cache_type = (XmssCacheType)pub_key_data->cache_type;
    *cache_level = pub_key_data->cache_level;
    return err_code;
}

/**
 * @brief
 * Loads the content from stateless, stateful and context into the key_context without verification.
 *
 * @details
 * This function does not do verification of the integrity of stateful and stateless structs.
 * The stateful and stateless parts are assumed to point into the respective blobs, and as such they must be in
 * big-endian byte order.
 * This function is intended for initial loading of the key, and does assume that the key_context does not contain any
 * pointers to buffers that need to be de-allocated.
 *
 * @param[out]  key_context The structure to fill in, assumed to be empty.
 * @param[in]   stateless   The stateless key part, in big-endian byte order.
 * @param[in]   stateful    The stateful key part, in big-endian byte order.
 * @param[in]   context     The signing context.
 * @retval XMSS_OKAY    Success.
 * @retval XMSS_ERR_NULL_POINTER    key_context, stateless, stateless or context is NULL.
 * @retval XMSS_ERR_FAULT_DETECTED  A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
*/
static XmssError xmss_load_private_key_internal(XmssKeyContext *const key_context,
    const XmssPrivateKeyStateless *const stateless, const XmssPrivateKeyStateful *const stateful,
    const XmssSigningContext *const context)
{
    volatile ValueCompareResult digest_cmp = VALUES_ARE_NOT_EQUAL;
    XmssError err_code = XMSS_UNINITIALIZED;

    if (key_context == NULL || stateless == NULL || stateful == NULL || context == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    key_context->initialized = (uint32_t)XMSS_INITIALIZATION_UNINITIALIZED;
    key_context->pad_ = 0;
    key_context->context = *context;
    key_context->private_stateful.partition_start = convert_big_endian_word(stateful->contents.partition_start);
    key_context->private_stateful.partition_end = convert_big_endian_word(stateful->contents.partition_end);
    key_context->redundant_private_stateful.partition_start
        = convert_big_endian_word(stateful->redundant_contents.partition_start);
    key_context->redundant_private_stateful.partition_end
        = convert_big_endian_word(stateful->redundant_contents.partition_end);

    key_context->reserved_signatures_start = key_context->private_stateful.partition_start;
    key_context->redundant_reserved_signatures_start = key_context->redundant_private_stateful.partition_start;
    if (key_context->reserved_signatures_start != key_context->redundant_reserved_signatures_start) {
        return XMSS_ERR_FAULT_DETECTED;
    }
    {
        big_endian_to_native_256(&key_context->private_stateless.prf_seed,
            (const XmssValue256 *)&stateless->contents.prf_seed);
        big_endian_to_native_256(&key_context->private_stateless.private_key_seed,
            (const XmssValue256 *)&stateless->contents.private_key_seed);
        big_endian_to_native_256(&key_context->private_stateless.seed, (const XmssValue256 *)&stateless->contents.seed);
        /* The digest remains in big-endian form. */
        big_endian_to_native_256(&key_context->private_stateless.obfuscation_integrity,
            (const XmssValue256 *)&stateless->contents.obfuscation_integrity);
        key_context->private_stateless.index_obfuscation_setting =
            convert_big_endian_word(stateless->contents.index_obfuscation_setting);
        big_endian_to_native_256(&key_context->private_stateless.index_obfuscation_random,
            (const XmssValue256 *)&stateless->contents.index_obfuscation_random);
        key_context->private_key_digest = stateless->integrity;
        key_context->redundant_private_key_digest = stateless->integrity;
        key_context->context.parameter_set = convert_big_endian_word(stateless->scheme_identifier);
        key_context->context.redundant_parameter_set = convert_big_endian_word(stateless->scheme_identifier);
        XmssError result = load_index_obfuscation_permutation(key_context);
        if (result != XMSS_OKAY) {
            context->zeroize(key_context, XMSS_KEY_CONTEXT_SIZE(context->parameter_set,
                key_context->private_stateless.index_obfuscation_setting));
            return result;
        }
    }

    /* Check that the redundant fields are equal. The return value of compare_values_256() is checked only once because
     * the values can only be different if a bit error already happened, and we only try to protect against one. */
    if (key_context->private_stateful.partition_start != key_context->redundant_private_stateful.partition_start
            || key_context->private_stateful.partition_end != key_context->redundant_private_stateful.partition_end
            || compare_values_256(&key_context->private_key_digest, &key_context->redundant_private_key_digest)
                != VALUES_ARE_EQUAL) {
        return XMSS_ERR_FAULT_DETECTED;
    }

    /* Recalculate the integrity hash of the stateless part. This is to verify that there have been no bit errors in
     * the private key since the integrity hash was calculated, and that it was correctly copied to key_context. */
    DEFINE_HASH_FUNCTIONS;
    err_code = INITIALIZE_HASH_FUNCTIONS((XmssParameterSetOID)key_context->context.parameter_set);
    if (err_code != XMSS_OKAY) {
        return err_code;
    }
    digest_cmp = check_integrity_digest(HASH_FUNCTIONS &key_context->private_key_digest,
        (uint8_t *)stateless + sizeof(stateless->integrity),
        sizeof(XmssPrivateKeyStateless) - sizeof(stateless->integrity));
    /* Checking the return value only once because the digests can only be different if a bit error already happened. */
    if (digest_cmp != VALUES_ARE_EQUAL) {
        return XMSS_ERR_FAULT_DETECTED;
    }

    key_context->initialized = (uint32_t)XMSS_INITIALIZATION_INITIALIZED;
    return err_code;
}

XmssError xmss_load_private_key(XmssKeyContext **const key_context,
    const XmssPrivateKeyStatelessBlob *const private_key,
    const XmssPrivateKeyStatefulBlob *const key_usage, const XmssSigningContext *const context)
{
    /* To protect against bit errors in the CPU's flag register, we execute some if-statements in this function twice.
     * The variables being checked are volatile, so the compiler is not allowed to optimize away the redundant if. */

    /* No redundant NULL pointer checks because a bit error can only lead to a segfault. */
    if (key_context == NULL || private_key == NULL || key_usage == NULL || context == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    /*
     * Although xmss_verify_private_key_stateful also checks the stateless part, it can incorrectly detect corruption as
     * an argument mismatch. It does verify the coherence between the two.
     */
    volatile XmssError result = xmss_verify_private_key_stateless(private_key, context);
    REDUNDANT_RETURN_ERR(result);
    result = XMSS_UNINITIALIZED;
    result = xmss_verify_private_key_stateful(key_usage, private_key, NULL, context);
    REDUNDANT_RETURN_ERR(result);

    const XmssPrivateKeyStateful *const key_usage_inner = (const XmssPrivateKeyStateful *)key_usage->data;
    const XmssPrivateKeyStateless *const private_key_inner = (const XmssPrivateKeyStateless *)private_key->data;
    const size_t key_context_size = XMSS_KEY_CONTEXT_SIZE(context->parameter_set,
        convert_big_endian_word(private_key_inner->contents.index_obfuscation_setting));
    XmssKeyContext *key_context_reallocated = context->realloc(*key_context, key_context_size);

    if (key_context_reallocated == NULL) {
        return XMSS_ERR_ALLOC_ERROR;
    }
    *key_context = key_context_reallocated;

    /* clear the contents of the key_context structure. */
    memset(*key_context, 0, key_context_size);

    result = XMSS_UNINITIALIZED;
    result = xmss_load_private_key_internal(*key_context, private_key_inner, key_usage_inner, context);
    REDUNDANT_RETURN_IF(result == XMSS_OKAY, XMSS_OKAY);

    /* Loading the private key failed, clean up and return the error. */
    xmss_free_key_context(*key_context);
    *key_context = NULL;
    return result;
}

/**
 * @brief
 * Generate the private key and populate an XmssKeyContext object.
 *
 * @param[in]       context                     The already initialized signing context.
 * @param[in,out]   key_context                 The key context that is to be allocated and populated
 * @param[in]       secure_random_seeds         The random 96 bytes of random that function as seeds for key generation.
 * @param[in]       index_obfuscation_setting   The index obfuscation scheme to be employed.
 * @param[in]       index_obfuscation_random    The random seed for index obfuscation, may be NULL if index obfuscation
 *                                              is disabled.
 * @retval XMSS_OKAY   The XmssKeyContext was allocated and the generation was successful.
 * @retval XMSS_ERR_NULL_POINTER    A NULL pointer was passed.
 * @retval XMSS_ERR_ALLOC_ERROR     Memory allocation caused an error.
 * @retval XMSS_ERR_BAD_CONTEXT     context is not a correctly initialized context.
 * @retval XMSS_ERR_INVALID_ARGUMENT    An invalid index_obfuscation_setting is passed.
 */
static XmssError generate_private_key_internal(const XmssSigningContext *const context,
    XmssKeyContext **key_context, const XmssBuffer *const secure_random_seeds,
    const XmssIndexObfuscationSetting index_obfuscation_setting, const XmssBuffer *const index_obfuscation_random)
{
    XmssError result = check_signing_context(context);
    if (result != XMSS_OKAY) {
        return result;
    }
    if (key_context == NULL || secure_random_seeds == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }
    if (secure_random_seeds->data == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }
    /* Check index obfuscation version, and perform checks that are specific to the index obfuscation version. */
    switch (index_obfuscation_setting) {
        case XMSS_INDEX_OBFUSCATION_OFF:
            break;
        case XMSS_INDEX_OBFUSCATION_ON:
            if (index_obfuscation_random == NULL || index_obfuscation_random->data == NULL) {
                return XMSS_ERR_NULL_POINTER;
            }
            if (index_obfuscation_random->data_size < sizeof(XmssValue256)) {
                return XMSS_ERR_INVALID_ARGUMENT;
            }
            /* check for overlap between secure random and random */
            if (index_obfuscation_random->data > secure_random_seeds->data) {
                if ((secure_random_seeds->data + secure_random_seeds->data_size)
                        > index_obfuscation_random->data) {
                    return XMSS_ERR_INVALID_ARGUMENT;
                }
            } else { /* secure_random->data <= random->data */
                if ((index_obfuscation_random->data + index_obfuscation_random->data_size)
                        > secure_random_seeds->data) {
                    return XMSS_ERR_INVALID_ARGUMENT;
                }
            }
            break;
        default:
            return XMSS_ERR_INVALID_ARGUMENT;
    }
    if (secure_random_seeds->data_size < 3 * sizeof(XmssValue256)) {
        return XMSS_ERR_INVALID_ARGUMENT;
    }
    switch (index_obfuscation_setting) {
        case XMSS_INDEX_OBFUSCATION_OFF:
            break;
        case XMSS_INDEX_OBFUSCATION_ON:
            break;
        default:
            return XMSS_ERR_INVALID_ARGUMENT;
    }

    const size_t key_context_size = XMSS_KEY_CONTEXT_SIZE(context->parameter_set, index_obfuscation_setting);
    XmssKeyContext *reallocated_key_context = context->realloc(*key_context, key_context_size);
    if (reallocated_key_context == NULL) {
        return XMSS_ERR_ALLOC_ERROR;
    }
    *key_context = reallocated_key_context;

    memset(reallocated_key_context, 0, key_context_size);
    /* Set the signing context */
    reallocated_key_context->context = *context;
    /* initialize the stateless part */
    {
        XmssPrivateKeyStatelessContents *stateless_part = &reallocated_key_context->private_stateless;
        stateless_part->index_obfuscation_setting = index_obfuscation_setting;
        /* Set the private key seed. */
        big_endian_to_native_256(&stateless_part->private_key_seed, &((XmssValue256 *)secure_random_seeds->data)[0]);
        /* Set the PRF seed.
         * Endianness is taken into account for test-vector interoperability with the reference implementation.
         */
        big_endian_to_native_256(&stateless_part->prf_seed, &((XmssValue256 *)secure_random_seeds->data)[1]);

        /* Set the public seed. */
        big_endian_to_native_256(&stateless_part->seed, &((XmssValue256 *)secure_random_seeds->data)[2]);
        /* Conditionally set the index obfuscation seed. */
        if (index_obfuscation_setting == XMSS_INDEX_OBFUSCATION_ON) {
            big_endian_to_native_256(&stateless_part->index_obfuscation_random,
                (XmssValue256 *)index_obfuscation_random->data);
        }
    }
    /* initialize stateful part */
    reallocated_key_context->private_stateful.partition_start = 0;
    /* Note: The partition end is inclusive, hence the subtraction of 1. */
    reallocated_key_context->private_stateful.partition_end =
        index_space_size((XmssParameterSetOID)context->parameter_set) - 1;

    reallocated_key_context->redundant_private_stateful.partition_start = 0;
    reallocated_key_context->redundant_private_stateful.partition_end =
        index_space_size((XmssParameterSetOID)context->parameter_set) - 1;

    /* Set reserved_signatures_start equal to partition_start to denote an empty interval. */
    reallocated_key_context->reserved_signatures_start = reallocated_key_context->private_stateful.partition_start;
    reallocated_key_context->redundant_reserved_signatures_start
        = reallocated_key_context->redundant_private_stateful.partition_start;

    /* Generate the index obfuscation permutation. */
    result = XMSS_UNINITIALIZED;
    result = generate_index_obfuscation_permutation(reallocated_key_context);
    if (result != XMSS_OKAY) {
        /* zeroizes the key context, frees it and sets the pointer to NULL. */
        xmss_free_key_context(*key_context);
        *key_context = NULL;
        return result;
    }

    /* Set the state to initialized (without public key) */
    reallocated_key_context->initialized = (uint32_t)XMSS_INITIALIZATION_INITIALIZED;
    reallocated_key_context->pad_ = 0;
    return result;
}

/**
 * @brief
 * Export the XmssPrivateKeyStatelessBlob, which is the stateless part of the private key.
 *
 * @param[in]       key_context     The key context for which to export the XmssPrivateKeyStatelessBlob.
 * @param[in,out]   stateless_blob  The XmssPrivateKeyStatelessBlob to export.
 *
 * @retval XMSS_OKAY    Success.
 * @retval XMSS_ERR_NULL_POINTER    A NULL pointer was passed.
 * @retval XMSS_ERR_ALLOC_ERROR     Memory allocation caused an error.
 * @retval XMSS_ERR_BAD_CONTEXT     context is not a correctly initialized context.
 * @retval XMSS_ERR_FAULT_DETECTED  A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
static XmssError export_private_key_stateless(const XmssKeyContext *const key_context,
        XmssPrivateKeyStatelessBlob **stateless_blob)
{
    XmssPrivateKeyStatelessBlob *reallocated_stateless_blob = NULL;

    volatile XmssError result = check_key_context_well_formed(key_context);
    REDUNDANT_RETURN_ERR(result);

    if (stateless_blob == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    reallocated_stateless_blob = key_context->context.realloc(*stateless_blob, sizeof(XmssPrivateKeyStateless) +
            sizeof(XmssPrivateKeyStatelessBlob));
    if (reallocated_stateless_blob == NULL) {
        return XMSS_ERR_ALLOC_ERROR;
    }

    reallocated_stateless_blob->data_size = sizeof(XmssPrivateKeyStateless);
    {
        XmssPrivateKeyStateless *stateless = (XmssPrivateKeyStateless *)&reallocated_stateless_blob->data;
        stateless->private_key_stateless_version =
            convert_big_endian_word(XMSS_VERSION_CURRENT_PRIVATE_KEY_STATELESS_STORAGE);
        stateless->redundant_version = convert_big_endian_word(XMSS_VERSION_CURRENT_PRIVATE_KEY_STATELESS_STORAGE);
        stateless->scheme_identifier = convert_big_endian_word(key_context->context.parameter_set);
        stateless->redundant_scheme_identifier = convert_big_endian_word(key_context->context.redundant_parameter_set);

        /* Copy the stateless_contents, and perform the necessary endianness operations in-place. */
        stateless->contents = key_context->private_stateless;
        /* Canonicalize the byte-order of all applicable fields for export. */
        inplace_native_to_big_endian_256(&stateless->contents.prf_seed);
        inplace_native_to_big_endian_256(&stateless->contents.private_key_seed);
        inplace_native_to_big_endian_256(&stateless->contents.seed);
        stateless->contents.index_obfuscation_setting =
            convert_big_endian_word(stateless->contents.index_obfuscation_setting);
        native_to_big_endian_256((XmssValue256 *)&stateless->contents.index_obfuscation_random,
            &key_context->private_stateless.index_obfuscation_random);
        native_to_big_endian_256((XmssValue256 *)&stateless->contents.obfuscation_integrity,
            &key_context->private_stateless.obfuscation_integrity);

        /* Compute the digest over the contents of the XmssPrivateKeyStateless structure excluding the integrity digest
         * field itself.
         */
        xmss_digest(HASH_FUNCTIONS_FROM(key_context->context) &stateless->integrity,
            ((uint8_t *)stateless) + sizeof(stateless->integrity), sizeof(*stateless) - sizeof(stateless->integrity));

        /* Check for bit errors. */
        if (convert_big_endian_word(stateless->private_key_stateless_version)
                != XMSS_VERSION_CURRENT_PRIVATE_KEY_STATELESS_STORAGE
            || convert_big_endian_word(stateless->redundant_version)
                != XMSS_VERSION_CURRENT_PRIVATE_KEY_STATELESS_STORAGE
            || convert_big_endian_word(stateless->scheme_identifier) != (uint32_t)key_context->context.parameter_set
            || convert_big_endian_word(stateless->redundant_scheme_identifier)
                != (uint32_t)key_context->context.parameter_set
        ) {
            key_context->context.free(reallocated_stateless_blob);
            *stateless_blob = NULL;
            return XMSS_ERR_FAULT_DETECTED;
        }
    }
    *stateless_blob = reallocated_stateless_blob;

    return result;
}

/**
 * @brief
 * Export the XmssPrivateKeyStatefulBlob, which is the stateful part of the private key.
 * This does require that the XmssPrivateKeyStatelessBlob has been exported and its digest has already been set in the
 * provided XmssKeyContext.
 *
 * @param[in]       key_context    The key context for which to export the XmssPrivateKeyStatefulBlob.
 * @param[in,out]   stateful_blob  The XmssPrivateKeyStatefulBlob to export.
 *
 * @retval XMSS_OKAY    Success.
 * @retval XMSS_ERR_NULL_POINTER    A NULL pointer was passed.
 * @retval XMSS_ERR_ALLOC_ERROR     Memory allocation caused an error.
 * @retval XMSS_ERR_BAD_CONTEXT     context is not a correctly initialized context.
 * @retval XMSS_ERR_FAULT_DETECTED  A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
static XmssError export_private_key_stateful(const XmssKeyContext *const key_context,
        XmssPrivateKeyStatefulBlob **const stateful_blob)
{
    XmssError result = check_key_context_well_formed(key_context);
    if (result != XMSS_OKAY) {
        return result;
    }

    if (stateful_blob == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    XmssPrivateKeyStatefulBlob *reallocated_stateful_blob = key_context->context.realloc(*stateful_blob,
            sizeof(XmssPrivateKeyStateful) + sizeof(XmssPrivateKeyStatefulBlob));

    if (reallocated_stateful_blob == NULL) {
        return XMSS_ERR_ALLOC_ERROR;
    }
    reallocated_stateful_blob->data_size = sizeof(XmssPrivateKeyStateful);

    XmssPrivateKeyStateful *stateful = (XmssPrivateKeyStateful *)reallocated_stateful_blob->data;
    {
        /* Ensure all content and padding is 0. */
        memset(stateful, 0, sizeof(*stateful));

        /* Copy the digest over the stateless blob from the key_context, as the Stateless key blob needs not be
         * available for export.
         */
        stateful->digest_of_private_key_static_blob = key_context->private_key_digest;

        /* Convert the integer values to big-endian. */
        stateful->private_key_stateful_version =
            convert_big_endian_word(XMSS_VERSION_CURRENT_PRIVATE_KEY_STATEFUL_STORAGE);
        stateful->scheme_identifier = convert_big_endian_word(key_context->context.parameter_set);
        stateful->contents.partition_start = convert_big_endian_word(key_context->private_stateful.partition_start);
        stateful->contents.partition_end = convert_big_endian_word(key_context->private_stateful.partition_end);
        stateful->redundant_version =
            convert_big_endian_word(XMSS_VERSION_CURRENT_PRIVATE_KEY_STATEFUL_STORAGE);
        stateful->redundant_scheme_identifier = convert_big_endian_word(key_context->context.redundant_parameter_set);
        stateful->redundant_contents.partition_start
            = convert_big_endian_word(key_context->redundant_private_stateful.partition_start);
        stateful->redundant_contents.partition_end
            = convert_big_endian_word(key_context->redundant_private_stateful.partition_end);

        /* Compute the digest over the contents of the XmssPrivateKeyStateful structure excluding the integrity digest
         * field itself.
         */
        xmss_digest(HASH_FUNCTIONS_FROM(key_context->context) &stateful->integrity,
            ((uint8_t*)stateful) + sizeof(stateful->integrity), sizeof(*stateful) - sizeof(stateful->integrity));

        /* Check for bit errors. */
        if (convert_big_endian_word(stateful->private_key_stateful_version)
                != XMSS_VERSION_CURRENT_PRIVATE_KEY_STATELESS_STORAGE
            || convert_big_endian_word(stateful->redundant_version)
                != XMSS_VERSION_CURRENT_PRIVATE_KEY_STATELESS_STORAGE
            || convert_big_endian_word(stateful->scheme_identifier) != (uint32_t)key_context->context.parameter_set
            || convert_big_endian_word(stateful->redundant_scheme_identifier)
                != (uint32_t)key_context->context.parameter_set
            || convert_big_endian_word(stateful->contents.partition_start)
                != key_context->private_stateful.partition_start
            || convert_big_endian_word(stateful->contents.partition_end) != key_context->private_stateful.partition_end
            || convert_big_endian_word(stateful->redundant_contents.partition_start)
                != key_context->private_stateful.partition_start
            || convert_big_endian_word(stateful->redundant_contents.partition_end)
                != key_context->private_stateful.partition_end
        ) {
            key_context->context.free(reallocated_stateful_blob);
            *stateful_blob = NULL;
            return XMSS_ERR_FAULT_DETECTED;
        }
    }

    *stateful_blob = reallocated_stateful_blob;
    return result;
}

XmssError xmss_export_public_key(XmssPublicKey *const exported_pub_key, const XmssKeyContext *const key_context)
{
    XmssError result = check_key_context_well_formed(key_context);
    if (result != XMSS_OKAY) {
        return result;
    }
    if (exported_pub_key == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    if (key_context->initialized != XMSS_INITIALIZATION_WITH_PUBLIC_KEY) {
        return XMSS_ERR_NO_PUBLIC_KEY;
    }

    native_to_big_endian_256(&exported_pub_key->root, &key_context->public_key_root);
    native_to_big_endian_256(&exported_pub_key->seed, &key_context->private_stateless.seed);
    exported_pub_key->scheme_identifier = convert_big_endian_word(key_context->context.parameter_set);

    return result;
}

XmssError xmss_verify_exported_public_key(const XmssPublicKey *const exported_pub_key,
    const XmssKeyContext *const key_context)
{
    volatile ValueCompareResult value_cmp = VALUES_ARE_NOT_EQUAL;

    if (exported_pub_key == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    XmssError result = check_key_context_well_formed(key_context);
    if (result != XMSS_OKAY) {
        return result;
    }
    if (key_context->initialized != XMSS_INITIALIZATION_WITH_PUBLIC_KEY) {
        return XMSS_ERR_NO_PUBLIC_KEY;
    }

    const volatile XmssParameterSetOID *const volatile p1  =
        (const XmssParameterSetOID *)&key_context->context.parameter_set;
    const volatile uint32_t *const volatile p2 = &exported_pub_key->scheme_identifier;
    REDUNDANT_RETURN_IF((uint32_t)*p1 != convert_big_endian_word(*p2), XMSS_ERR_ARGUMENT_MISMATCH);

    {
        XmssValue256 canonicalized_root;
        native_to_big_endian_256(&canonicalized_root, &key_context->public_key_root);
        value_cmp = compare_values_256(&canonicalized_root, &exported_pub_key->root);
        REDUNDANT_RETURN_IF(value_cmp != VALUES_ARE_EQUAL, XMSS_ERR_ARGUMENT_MISMATCH);
    }
    {
        XmssValue256 canonicalized_seed;
        native_to_big_endian_256(&canonicalized_seed, &key_context->private_stateless.seed);
        value_cmp = compare_values_256(&canonicalized_seed, &exported_pub_key->seed);
        REDUNDANT_RETURN_IF(value_cmp != VALUES_ARE_EQUAL, XMSS_ERR_ARGUMENT_MISMATCH);
    }
    return result;
}

XmssError xmss_generate_private_key(XmssKeyContext **const key_context, XmssPrivateKeyStatelessBlob **const private_key,
    XmssPrivateKeyStatefulBlob **const key_usage, const XmssBuffer *const secure_random,
    const XmssIndexObfuscationSetting index_obfuscation_setting, const XmssBuffer *const random,
    const XmssSigningContext *const context)
{
    XmssError result = XMSS_ERR_BAD_CONTEXT;

    if (key_context == NULL || private_key == NULL || key_usage == NULL || secure_random == NULL || context == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    result = check_signing_context(context);
    if (result != XMSS_OKAY) {
        return result;
    }

    /* Check index obfuscation version, as that determines the size of the XmssKeyContext.
     * Other parameters are checked when used.
     */
    switch (index_obfuscation_setting) {
        case XMSS_INDEX_OBFUSCATION_OFF:
            break;
        case XMSS_INDEX_OBFUSCATION_ON:
            break;
        default:
            return XMSS_ERR_INVALID_ARGUMENT;
    }

    result = XMSS_UNINITIALIZED;
    result = generate_private_key_internal(context, key_context, secure_random, index_obfuscation_setting, random);
    if (result != XMSS_OKAY) {
        /*
         * (*key_context) is zeroized and freed in case it's allocated by generate_private_key_internal before it fails.
         */
        return result;
    }

    result = XMSS_UNINITIALIZED;
    result = export_private_key_stateless(*key_context, private_key);
    if (result != XMSS_OKAY) {
        xmss_free_key_context(*key_context);
        *key_context = NULL;
        return result;
    }

    /* Copy the digest from the private key stateless part into the key context. */
    {
        XmssPrivateKeyStateless *private_key_internal = ((XmssPrivateKeyStateless *)(*private_key)->data);
        (*key_context)->private_key_digest = private_key_internal->integrity;
        (*key_context)->redundant_private_key_digest = private_key_internal->integrity;
    }

    /* The XmssPrivateKeyStatelessBlob digest completes the key context. */
    (*key_context)->initialized = (uint32_t)XMSS_INITIALIZATION_INITIALIZED;

    result = XMSS_UNINITIALIZED;
    result = export_private_key_stateful(*key_context, key_usage);
    if (result != XMSS_OKAY) {
        xmss_free_key_context(*key_context);
        *key_context = NULL;
        context->zeroize((*private_key)->data, (*private_key)->data_size);
        context->free(*private_key);
        *private_key = NULL;
        return result;
    }

    return result;
}

XmssError xmss_request_future_signatures(XmssPrivateKeyStatefulBlob **const new_key_usage,
    XmssKeyContext *const key_context, const uint32_t signature_count)
{
    if (new_key_usage == NULL || key_context == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }
    if (key_context->initialized != XMSS_INITIALIZATION_WITH_PUBLIC_KEY) {
        return XMSS_ERR_BAD_CONTEXT;
    }
    assert(key_context->private_stateful.partition_start <= key_context->private_stateful.partition_end + 1);

    uint32_t available_signatures =
        key_context->private_stateful.partition_end - key_context->private_stateful.partition_start + 1;
    if (signature_count > available_signatures) {
        return XMSS_ERR_TOO_FEW_SIGNATURES_AVAILABLE;
    }
    key_context->private_stateful.partition_start += signature_count;
    key_context->redundant_private_stateful.partition_start += signature_count;

    /* Check for bit errors. In particular, make sure that a bit error in signature_count can't claim more signatures
     * than available. */
    if (key_context->private_stateful.partition_start != key_context->redundant_private_stateful.partition_start
            || key_context->private_stateful.partition_end != key_context->redundant_private_stateful.partition_end
            || key_context->reserved_signatures_start != key_context->redundant_reserved_signatures_start
            || key_context->private_stateful.partition_start > key_context->private_stateful.partition_end + 1) {
        return XMSS_ERR_FAULT_DETECTED;
    }

    return export_private_key_stateful(key_context, new_key_usage);
}

/**
 * @brief
 * Compute the authentication path in big-endian byte order for signature number idx_sig.
 *
 * @details
 * Based on the example buildAuth algorithm in RFC-8391, Section 4.1.9.
 *
 * @warning
 * The caller is responsible for passing a valid pointer and index. For performance reasons, this will not be checked.
 *
 * @param[out] signature    The signature to which the authentication path is added.
 * @param[in]  key_context  Context containing the XMSS key.
 * @param[in]  idx_sig      (Obfuscated) index of the signature for which to create an authentication path.
 */
static void build_auth(XmssSignature *const signature, const XmssKeyContext *const key_context, const uint32_t idx_sig)
{
    assert(key_context != NULL);

    uint_fast8_t tree_depth = XMSS_TREE_DEPTH(key_context->context.parameter_set);
    for (uint_fast8_t i = 0; i < tree_depth; i++) {
        /* For each i, we need to calculate the sibling of the ancestor of leaf number idx_sig at height i, using
         * xmss_tree_hash(). For this purpose, we need to calculate the index of the first leaf of the subtree rooted
         * at that sibling node. The formula to calculate this index is 2^i * (floor(idx_sig / 2^i) XOR 1).
         * An equivalent way to calculate this is to flip the ith bit in idx_sig (counting from least to most
         * significant) and setting the lower bits to 0. */
        uint32_t subtree_start = idx_sig;
        subtree_start ^= 1 << i;
        subtree_start &= 0xffffffff << i;

        /* We put the native-endian output of xmss_tree_hash() directly into the authentication path portion of the
         * signature and swap it to big-endian at the end. We can cast it to (XmssNativeValue256 *) because the layout
         * of the signature struct ensures that it is 32-bit aligned. */
        xmss_tree_hash(((XmssNativeValue256 *)signature->authentication_path) + i, key_context, key_context->cache,
            subtree_start, i);
    }
    inplace_native_to_big_endian((uint32_t *)signature->authentication_path->data,
        XMSS_VALUE_256_WORDS * (uint_fast16_t)tree_depth);
}

/**
 * @brief
 * Place signature number idx_sig on message_digest.
 *
 * @details
 * Based on Algorithm 11 in RFC-8391, Section 4.1.9. We don't pass ADRS because all fields are either known or set
 * during signature generation.
 * This function is designed to prevent a single random bit error from causing the re-use of a OTS key. Therefore, it
 * expects to be passed a redundant copy of idx_sig. A second one-time signature is created using the redundant copy.
 * If the signatures do not match, both are zeroized and XMSS_ERR_FAULT_DETECTED is returned.
 * It is still possible for a single bit error in the calculation of the authentication path to result in an invalid
 * signature. This causes all reserved signatures to go to waste, but does not compromise the integrity of signatures.
 *
 * @warning
 * The caller is responsible for passing valid pointers and a valid index. For performance reasons, this is not checked.
 *
 * @param[out] signature            Place to store the signature.
 * @param[in]  key_context          Context with the private key used to sign.
 * @param[in]  message_digest       Message digest to sign.
 * @param[in]  idx_sig              Index of the signature (after obfuscation).
 * @param[in]  redundant_idx_sig    Redundant copy of idx_sig.
 * @retval XMSS_OKAY    Success.
 * @retval XMSS_ERR_FAULT_DETECTED  A bit error was detected; note that not all bit errors will be detected.
 */
static XmssError tree_sign(XmssSignature *const signature, const XmssKeyContext *const key_context,
    const XmssNativeValue256 *const message_digest, const uint32_t idx_sig, const uint32_t redundant_idx_sig)
{
    assert(signature != NULL);
    assert(key_context != NULL);
    assert(message_digest != NULL);

    WotspSignature redundant_wotsp_signature = { 0 };
    volatile XmssError result = XMSS_UNINITIALIZED;

    /* We place the native-endian WOTS+ signature in the signature struct and then change the endianness in place.
     * We can cast it to (WotspSignature *) because it is 32-bit aligned due to the layout of XmssSignatureBlob. */
    result = wotsp_sign(&key_context->context, (WotspSignature *)signature->wots_signature, message_digest,
        &key_context->private_stateless.private_key_seed, &key_context->private_stateless.seed, idx_sig);
    REDUNDANT_RETURN_ERR(result);

    result = XMSS_UNINITIALIZED;
    result = wotsp_sign(&key_context->context, &redundant_wotsp_signature, message_digest,
        &key_context->private_stateless.private_key_seed, &key_context->private_stateless.seed, redundant_idx_sig);
    REDUNDANT_RETURN_ERR(result);

    if (memcmp(signature->wots_signature, &redundant_wotsp_signature, sizeof(WotspSignature)) != 0) {
        key_context->context.zeroize(signature->wots_signature, sizeof(WotspSignature));
        key_context->context.zeroize(&redundant_wotsp_signature, sizeof(WotspSignature));
        return XMSS_ERR_FAULT_DETECTED;
    }

    inplace_native_to_big_endian((uint32_t *)signature->wots_signature, XMSS_WOTSP_LEN * 8);

    build_auth(signature, key_context, idx_sig);
    return result;
}

XmssError xmss_sign_message(XmssSignatureBlob **const signature, XmssKeyContext *const key_context,
    const XmssBuffer *const message)
{
    if (signature == NULL || key_context == NULL || message == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }
    if (key_context->initialized != XMSS_INITIALIZATION_WITH_PUBLIC_KEY) {
        return XMSS_ERR_NO_PUBLIC_KEY;
    }

    /* Check redundant values. */
    if (key_context->reserved_signatures_start != key_context->redundant_reserved_signatures_start
            || key_context->private_stateful.partition_start != key_context->redundant_private_stateful.partition_start
            || key_context->private_stateful.partition_end != key_context->redundant_private_stateful.partition_end) {
        return XMSS_ERR_FAULT_DETECTED;
    }

    if (key_context->reserved_signatures_start >= key_context->private_stateful.partition_start) {
        assert(key_context->reserved_signatures_start == key_context->private_stateful.partition_start);
        return XMSS_ERR_TOO_FEW_SIGNATURES_AVAILABLE;
    }
    XmssSignatureBlob *reallocated_signature = key_context->context.realloc(*signature,
        XMSS_SIGNATURE_BLOB_SIZE(key_context->context.parameter_set));
    if (reallocated_signature == NULL) {
        return XMSS_ERR_ALLOC_ERROR;
    }

    const uint32_t idx_sig_pre_obfuscation = key_context->reserved_signatures_start++;
    const uint32_t redundant_idx_sig_pre_obfuscation = key_context->redundant_reserved_signatures_start++;
    /* The obfuscated value is determined twice for detection of bit errors.
     * The validity of the permutation is verified as part of the obfuscation function.
     * If index obfuscation is disabled for this private key, obfuscated_idx_sig equals idx_sig_pre_obfuscation.
     */
    volatile uint32_t obfuscated_idx_sig = 0;
    volatile uint32_t redundant_obfuscated_idx_sig = 0;
    volatile XmssError result = obfuscate_index(&obfuscated_idx_sig, key_context, idx_sig_pre_obfuscation);
    REDUNDANT_RETURN_ERR(result);
    result = XMSS_UNINITIALIZED;
    result = obfuscate_index(&redundant_obfuscated_idx_sig, key_context, redundant_idx_sig_pre_obfuscation);
    REDUNDANT_RETURN_ERR(result);
    Input_PRF input_prf = INIT_INPUT_PRF;
    XmssSignature *signature_data = NULL;
    XmssNativeValue256 native_random = { 0 };
    Input_H_msg input = INIT_INPUT_H_MSG;
    XmssHMsgCtx ctx = { 0 };
    XmssNativeValue256 message_digest = { 0 };

    reallocated_signature->data_size = XMSS_SIGNATURE_SIZE(key_context->context.parameter_set);
    signature_data = (XmssSignature *)reallocated_signature->data;
    signature_data->leaf_index = convert_big_endian_word(obfuscated_idx_sig);

    input_prf.KEY = key_context->private_stateless.prf_seed;
    input_prf.M.idx_sig_block.idx_sig = obfuscated_idx_sig;
    xmss_PRF(HASH_FUNCTIONS_FROM(key_context->context) &native_random, &input_prf);

    native_to_big_endian_256(&signature_data->random_bytes, &native_random);

    input.r = native_random;
    input.Root = key_context->public_key_root;
    input.idx_sig = obfuscated_idx_sig;
    xmss_H_msg_init(HASH_FUNCTIONS_FROM(key_context->context) &ctx, &input);
    xmss_H_msg_update(HASH_FUNCTIONS_FROM(key_context->context) &ctx, message->data, message->data_size, NULL);
    xmss_H_msg_finalize(HASH_FUNCTIONS_FROM(key_context->context) &message_digest, &ctx);

    result = XMSS_UNINITIALIZED;
    result = tree_sign(signature_data, key_context, (XmssNativeValue256 *)&message_digest, obfuscated_idx_sig,
        redundant_obfuscated_idx_sig);
    /* result can only be different from XMSS_OKAY if a bit error happened. Since we only protect against a single
     * bit error, we don't need to double-check here. */
    if (result != XMSS_OKAY) {
        key_context->context.free(reallocated_signature);
        *signature = NULL;
        return XMSS_ERR_FAULT_DETECTED;
    }

    *signature = reallocated_signature;
    return result;
}

XmssError xmss_partition_signature_space(XmssPrivateKeyStatefulBlob **const new_partition,
    XmssPrivateKeyStatefulBlob **const updated_current_partition, XmssKeyContext *const key_context,
    const uint32_t new_partition_size)
{
    if (new_partition == NULL || updated_current_partition == NULL || key_context == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    volatile XmssError err_code = check_key_context_well_formed(key_context);
    REDUNDANT_RETURN_ERR(err_code);
    if (key_context->initialized != XMSS_INITIALIZATION_INITIALIZED
            && key_context->initialized != XMSS_INITIALIZATION_WITH_PUBLIC_KEY) {
        return XMSS_ERR_BAD_CONTEXT;
    }

    XmssPrivateKeyStatefulBlob *reallocated_new_partition = NULL;
    XmssKeyContext *volatile key_context_check = key_context;
    XmssPrivateKeyStateful *volatile new_partition_internal = NULL;
    XmssPrivateKeyStateful *volatile current_partition_internal = NULL;
    volatile uint32_t old_partition_end = key_context->private_stateful.partition_end;
    volatile uint32_t redundant_old_partition_end = key_context->redundant_private_stateful.partition_end;
    uint32_t available_signatures =
        key_context->private_stateful.partition_end - key_context->private_stateful.partition_start + 1;

    if (new_partition_size > available_signatures) {
        return XMSS_ERR_TOO_FEW_SIGNATURES_AVAILABLE;
    }

    key_context->private_stateful.partition_end -= new_partition_size;
    key_context->redundant_private_stateful.partition_end -= new_partition_size;

    err_code = XMSS_UNINITIALIZED;
    err_code = export_private_key_stateful(key_context, updated_current_partition);
    REDUNDANT_RETURN_ERR(err_code);

    reallocated_new_partition
        = key_context->context.realloc(*new_partition, XMSS_PRIVATE_KEY_STATEFUL_BLOB_SIZE);
    if (reallocated_new_partition == NULL) {
        err_code = XMSS_ERR_ALLOC_ERROR;
        goto fail;
    }
    *new_partition = reallocated_new_partition;

    /* Copy *updated_current_partition to *new_partition, because most fields are the same. */
    memcpy(&(*new_partition)->data, &(*updated_current_partition)->data, (*updated_current_partition)->data_size);
    (*new_partition)->data_size = (*updated_current_partition)->data_size;

    /* Set the start and end for the new partition. */
    current_partition_internal = (XmssPrivateKeyStateful *)(*new_partition)->data;
    current_partition_internal->contents.partition_start
        = convert_big_endian_word(key_context->private_stateful.partition_end + 1);
    current_partition_internal->contents.partition_end = convert_big_endian_word(old_partition_end);
    current_partition_internal->redundant_contents.partition_start
        = convert_big_endian_word(key_context->redundant_private_stateful.partition_end + 1);
    current_partition_internal->redundant_contents.partition_end
        = convert_big_endian_word(redundant_old_partition_end);

    /* Update the integrity hash for the new partition. */
    xmss_digest(HASH_FUNCTIONS_FROM(key_context->context) &current_partition_internal->integrity,
        (*new_partition)->data + sizeof(current_partition_internal->integrity),
        sizeof(XmssPrivateKeyStateful) - sizeof(current_partition_internal->integrity));

    /* Verify that a bit error has not caused the partitions to overlap or to exceed the original signature space.
     *
     * At the end of export_private_key_stateful(), it was verified that the redundant fields in
     * updated_current_partition are equal and that they match the partition in key_context. We can therefore assume
     * that the partitions in key_context and updated_current_partition are the same. If not, we will detect a bit error
     * when checking the redundant fields in key_context or updated_current_partition later. */
    new_partition_internal = (XmssPrivateKeyStateful *)(*new_partition)->data;
    if (key_context_check->private_stateful.partition_end + 1
                != convert_big_endian_word(new_partition_internal->contents.partition_start)
            || convert_big_endian_word(new_partition_internal->contents.partition_end) != old_partition_end) {
        err_code = XMSS_ERR_FAULT_DETECTED;
        goto fail;
    }

    /* Check the redundant fields in key_context. */
    err_code = XMSS_UNINITIALIZED;
    err_code = check_key_context_well_formed(key_context_check);
    if (err_code != XMSS_OKAY) {
        goto fail;
    }
    if (err_code != XMSS_OKAY) {
        goto fail;
    }

    /* Check the redundant fields and integrity hashes of the new blobs. */
    err_code = XMSS_UNINITIALIZED;
    err_code = xmss_verify_private_key_stateful(*new_partition, NULL, key_context, NULL);
    if (err_code != XMSS_OKAY) {
        goto fail;
    }
    if (err_code != XMSS_OKAY) {
        goto fail;
    }
    err_code = XMSS_UNINITIALIZED;
    err_code = xmss_verify_private_key_stateful(*updated_current_partition, NULL, key_context, NULL);
    if (err_code != XMSS_OKAY) {
        goto fail;
    }
    if (err_code != XMSS_OKAY) {
        goto fail;
    }

    return err_code;

fail:
    if (err_code == XMSS_OKAY) {
        err_code = XMSS_ERR_FAULT_DETECTED;
    }
    /* Restore key_context to its original state. */
    key_context->private_stateful.partition_end = old_partition_end;
    key_context->redundant_private_stateful.partition_end = redundant_old_partition_end;

    key_context->context.free(*updated_current_partition);
    *updated_current_partition = NULL;

    /* Leave new_partition alone if we haven't reallocated it. */
    if (reallocated_new_partition != NULL) {
        key_context->context.free(*new_partition);
        *new_partition = NULL;
    }
    return err_code;
}

XmssError xmss_merge_signature_space(XmssPrivateKeyStatefulBlob **const new_key_usage,
    XmssKeyContext *const key_context, const XmssPrivateKeyStatefulBlob *const partition_extension)
{
    if (new_key_usage == NULL || key_context == NULL || partition_extension == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    XmssError err_code = xmss_verify_private_key_stateful(partition_extension, NULL, key_context, NULL);
    REDUNDANT_RETURN_ERR(err_code);

    XmssPrivateKeyStateful *extension = (XmssPrivateKeyStateful *)partition_extension->data;
    volatile uint32_t extension_start = convert_big_endian_word(extension->contents.partition_start);
    volatile uint32_t extension_end = convert_big_endian_word(extension->contents.partition_end);
    volatile uint32_t redundant_extension_start
        = convert_big_endian_word(extension->redundant_contents.partition_start);
    volatile uint32_t redundant_extension_end = convert_big_endian_word(extension->redundant_contents.partition_end);

    /* If the extension is empty, there's nothing to do, just export the stateful part of key_context. */
    if (extension_end < extension_start) {
        /* Check if a bit error sent us into the wrong branch. */
        if (extension_end >= extension_start || redundant_extension_end >= redundant_extension_start) {
            return XMSS_ERR_FAULT_DETECTED;
        }
        return export_private_key_stateful(key_context, new_key_usage);
    }

    /* Check if a bit error caused us to skip the previous branch. */
    if (extension_end < extension_start) {
        return XMSS_ERR_FAULT_DETECTED;
    }

    /* Check if we can attach the extension at the end. */
    if (key_context->private_stateful.partition_end + 1 == extension_start) {
        /* Check if a bit error sent us into the wrong branch. */
        if (key_context->private_stateful.partition_end + 1 != extension_start
                || key_context->redundant_private_stateful.partition_end + 1 != redundant_extension_start) {
            return XMSS_ERR_FAULT_DETECTED;
        }
        key_context->private_stateful.partition_end = extension_end;
        key_context->redundant_private_stateful.partition_end = redundant_extension_end;
        return export_private_key_stateful(key_context, new_key_usage);
    }

    /* Check if a bit error caused us to skip the previous branch. */
    if (key_context->redundant_private_stateful.partition_end + 1 == redundant_extension_start) {
        return XMSS_ERR_FAULT_DETECTED;
    }

    /* Check if we can attach the extension at the front. */
    if (extension_end + 1 == key_context->private_stateful.partition_start) {
        /* If we attach an extension at the front, there can be no reserved signatures. */
        assert(key_context->reserved_signatures_start == key_context->private_stateful.partition_start);

        /* Check if a bit error sent us into the wrong branch. */
        if (extension_end + 1 != key_context->private_stateful.partition_start
                || redundant_extension_end + 1 != key_context->redundant_private_stateful.partition_start) {
            return XMSS_ERR_FAULT_DETECTED;
        }
        key_context->private_stateful.partition_start = extension_start;
        key_context->redundant_private_stateful.partition_start = redundant_extension_start;

        /* If no signatures are reserved, we assume that reserved_signatures_start == partition_start, so update it. */
        key_context->reserved_signatures_start = extension_start;
        key_context->redundant_reserved_signatures_start = redundant_extension_start;
        return export_private_key_stateful(key_context, new_key_usage);
    }

    /* Check if a bit error caused us to skip the previous branch. */
    if (extension_end + 1 == key_context->private_stateful.partition_start) {
        return XMSS_ERR_FAULT_DETECTED;
    }

    return XMSS_ERR_PARTITIONS_NOT_CONSECUTIVE;
}

XmssError xmss_get_signature_count(size_t *const total_count, size_t *const remaining_count,
    const XmssKeyContext *const key_context)
{
    if (total_count == NULL || remaining_count == 0 || key_context == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    size_t redundant_remaining_count = 0;
    volatile const XmssError err_code = check_key_context_well_formed(key_context);
    REDUNDANT_RETURN_ERR(err_code);

    *total_count = (size_t)(1llu << XMSS_TREE_DEPTH(key_context->context.parameter_set));
    *remaining_count =
        (size_t)key_context->private_stateful.partition_end - key_context->private_stateful.partition_start + 1;
    redundant_remaining_count = (size_t)key_context->redundant_private_stateful.partition_end
        - key_context->redundant_private_stateful.partition_start + 1;

    return (redundant_remaining_count == *remaining_count) ? XMSS_OKAY : XMSS_ERR_FAULT_DETECTED;
}

void xmss_free_key_generation_context(XmssKeyGenerationContext *const key_generation_context)
{
    if (key_generation_context != NULL && key_generation_context->context != NULL) {
        key_generation_context->context->context.free(key_generation_context->partition_cache);
        key_generation_context->context->context.free(key_generation_context->cache_under_construction);
        key_generation_context->context->context.free(key_generation_context);
    }
}

XmssError xmss_generate_public_key(XmssKeyGenerationContext **const generation_buffer,
    XmssInternalCache **const cache, XmssInternalCache **const generation_cache,
    const XmssKeyContext *const key_context, const XmssCacheType cache_type, const uint8_t cache_depth,
    const uint32_t generation_partitions)
{
    if (generation_buffer == NULL || key_context == NULL || generation_cache == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    XmssError result = check_key_context_well_formed(key_context);
    if (result != XMSS_OKAY) {
        return result;
    }
    if (cache_type != XMSS_CACHE_NONE) {
        if (cache == NULL) {
            return XMSS_ERR_NULL_POINTER;
        }
        if (cache_depth >= XMSS_TREE_DEPTH(key_context->context.parameter_set)) {
            return XMSS_ERR_INVALID_ARGUMENT;
        }
    }
    /* Confirm that the number of partitions is a power of two, and that it's > 0 and smaller or equal to the total
     * size of the index space.
     */
    uint32_t partition_height = 0;
    result = partitions_to_tree_height(&partition_height, generation_partitions,
        (XmssParameterSetOID)key_context->context.parameter_set);
    if (result != XMSS_OKAY) {
        return result;
    }
    /* Allocate the generation context. */
    XmssKeyGenerationContext *const reallocated_generation_buffer = key_context->context.realloc(*generation_buffer,
        XMSS_KEY_GENERATION_CONTEXT_SIZE(generation_partitions));

    if (NULL == reallocated_generation_buffer) {
        return XMSS_ERR_ALLOC_ERROR;
    }

    /* Zeroize the allocated struct.  */
    memset(reallocated_generation_buffer, 0, XMSS_KEY_GENERATION_CONTEXT_SIZE(generation_partitions));
    *generation_buffer = reallocated_generation_buffer;
    (*generation_buffer)->context = key_context;

    /* Allocate the generation cache. */
    const size_t generation_cache_size = XMSS_PUBLIC_KEY_GENERATION_CACHE_SIZE(generation_partitions);
    XmssInternalCache *reallocated_gen_cache = key_context->context.realloc(*generation_cache, generation_cache_size);
    if (reallocated_gen_cache == NULL) {
        xmss_free_key_generation_context(*generation_buffer);
        *generation_buffer = NULL;
        return XMSS_ERR_ALLOC_ERROR;
    }
    *generation_cache = NULL;
    reallocated_gen_cache->cache_level = partition_height;
    reallocated_gen_cache->cache_type = (uint32_t)XMSS_CACHE_SINGLE_LEVEL;
    (*generation_buffer)->partition_cache = reallocated_gen_cache;

    /* Allocate the cache. */
    switch (cache_type) {
        case XMSS_CACHE_NONE:
            break;
        case XMSS_CACHE_SINGLE_LEVEL:
        /* @fallthrough@ */
        case XMSS_CACHE_TOP:  {
            XmssInternalCache *reallocated_cache =
                key_context->context.realloc(*cache, XMSS_INTERNAL_CACHE_SIZE(cache_type, cache_depth,
                    key_context->context.parameter_set));
            if (reallocated_cache == NULL) {
                xmss_free_key_generation_context(*generation_buffer);
                *generation_buffer = NULL;
                return XMSS_ERR_ALLOC_ERROR;
            }
            *cache = NULL;
            reallocated_generation_buffer->cache_under_construction = reallocated_cache;
            reallocated_cache->cache_level = cache_depth;
            reallocated_cache->cache_type = (uint32_t)cache_type;
            break;
        }

        default:
            /* An invalid cache type argument was provided. */
            xmss_free_key_generation_context(*generation_buffer);
            *generation_buffer = NULL;
            return XMSS_ERR_INVALID_ARGUMENT;
    }
    reallocated_generation_buffer->context = key_context;
    reallocated_generation_buffer->generation_partitions = generation_partitions;

    /* Set the generation state for each partition. */
    for (size_t partition = 0; partition < generation_partitions; partition++) {
        reallocated_generation_buffer->partition_states->state = (uint32_t)XMSS_GENERATION_STATE_PREPARED;
    }
    reallocated_generation_buffer->initialized = (uint32_t)XMSS_INITIALIZATION_INITIALIZED;
    return result;
}

XmssError xmss_calculate_public_key_part(XmssKeyGenerationContext *const generation_buffer,
    const uint32_t partition_index)
{
    if (generation_buffer == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }
    if (generation_buffer->initialized != XMSS_INITIALIZATION_INITIALIZED) {
        return XMSS_ERR_BAD_CONTEXT;
    }

    if (partition_index >= generation_buffer->generation_partitions) {
        return XMSS_ERR_INVALID_ARGUMENT;
    }

    {
        uint32_t expected = XMSS_GENERATION_STATE_PREPARED;
        uint32_t new_state = XMSS_GENERATION_STATE_GENERATING;
        /* If atomics are available, multiple invocations with the same partition index will be detected.
         * If not, they may go undetected.
         */
        if (!atomic_compare_exchange_strong(&generation_buffer->partition_states[partition_index].state, &expected,
                new_state)) {
            /* The partition state is not as expected, there was probably an invocation error. */
            return XMSS_ERR_PARTITION_DONE;
        }
    }

    /* The level of the output digest in the treeHash tree. */
    uint32_t partition_height = 0;
    XmssError result =  partitions_to_tree_height(&partition_height, (uint32_t)generation_buffer->generation_partitions,
            (XmssParameterSetOID)generation_buffer->context->context.parameter_set);
    if (result != XMSS_OKAY) {
        return result;
    }
    const XmssKeyContext *key_context = generation_buffer->context;
    XmssParameterSetOID param_set = (XmssParameterSetOID)key_context->context.parameter_set;
    XmssInternalCache *cache_to_build = generation_buffer->cache_under_construction;
    /* Nothing has been cached yet, so no cache is used until it is. */
    XmssInternalCache *cache_to_use = NULL;
    /* If the desired cache level is below the partition height level, cache must be built during the computation
     * of the partition result.
     */
    if (cache_to_build != NULL && cache_to_build->cache_level <= partition_height) {
        /** Store cache height in a variable for readability. */
        const uint32_t cache_height = cache_to_build->cache_level;
        /* (Part of) the sub-tree that's computed for this partition result is to be cached. */
        uint32_t cache_level_delta = partition_height - cache_height;
        /* The start index (for this partition) at the cache level (so not at the OTS index level). */
        const uint32_t first_cache_entry = (uint32_t)partition_index * (1u << cache_level_delta);
        /* The last cache entry index (for this partition) at the cache level. */
        const uint32_t last_cache_entry = (uint32_t)(partition_index + 1) * (1u << cache_level_delta) - 1;
        /* First start by filling the lowest to-be-cached level of the sub-tree. */
        for (uint32_t index = first_cache_entry; index <= last_cache_entry; index++) {
            /* The address in the cache of the node to compute. */
            XmssNativeValue256 *cache_node = &cache_to_build->cache[
                    XMSS_CACHE_ENTRY_OFFSET(cache_to_build->cache_type,
                        cache_to_build->cache_level,
                        param_set, cache_height, index)];
            result = XMSS_UNINITIALIZED;
            result = xmss_tree_hash(cache_node, generation_buffer->context, NULL,
                    index * (1 << cache_height), cache_height);
            if (result != XMSS_OKAY) {
                return result;
            }
        }
        if (cache_to_build->cache_type == XMSS_CACHE_TOP &&
                cache_to_build->cache_level < partition_height) {
                /* The lowest level of the partition's sub-tree of the top-cache has been filled, now the top-cache
                 * specific fill function can be used to finish the sub-tree.
                 */
                result = XMSS_UNINITIALIZED;
                result = xmss_fill_top_cache(cache_to_build, key_context, partition_height,
                        partition_index, cache_to_build->cache_level);
                if (result != XMSS_OKAY) {
                    return result;
                }
        }
        cache_to_use = cache_to_build;
    }

    /*
     * Build the partition cache.
     * Start index is the index of the first leaf in the partition sub-tree, with each partition spanning
     * pow(2, partition_height) OTS indexes.
     * This will use the cache_to_build if it already contains nodes of lower levels.
     */
    const uint32_t start_index = (uint32_t)partition_index * (1u << partition_height);
    XmssNativeValue256 *cache_node = &generation_buffer->partition_cache->cache[
                XMSS_CACHE_ENTRY_OFFSET(generation_buffer->partition_cache->cache_type,
                    generation_buffer->partition_cache->cache_level,
                    generation_buffer->context->context.parameter_set, partition_height, partition_index)];
    result = XMSS_UNINITIALIZED;
    result = xmss_tree_hash(cache_node, generation_buffer->context, cache_to_use, start_index, partition_height);
    if (result != XMSS_OKAY) {
        return result;
    }
    /* Update the partition's generation state. */
    {
        uint32_t expected = XMSS_GENERATION_STATE_GENERATING;
        uint32_t new_state = XMSS_GENERATION_STATE_FINISHED;
        if (!atomic_compare_exchange_strong(&generation_buffer->partition_states[partition_index].state, &expected,
                new_state)) {
            /* The partition state is not as expected, there was probably an invocation error. */
            return XMSS_ERR_PARTITION_DONE;
        }
    }
    return result;
}

/**
 * @brief
 * Perform the final steps of the public key generation and add the results to the key_context.
 *
 * @param[in,out]   key_context         The key context that is to be updated with the public key root.
 * @param[in]       generation_buffer   The generation buffer that contains all the resources to perform the
 *                                      generation.
 * @param[in]       partition_height    The height to which partitions have already been computed.
 * @retval XMSS_OKAY    Success.
 * @retval XMSS_ERR_NULL_POINTER    generation_buffer or key_context was NULL.
 */
static XmssError xmss_finish_calculate_public_key_internal(XmssKeyContext *const key_context,
        const XmssKeyGenerationContext *const generation_buffer, const uint32_t partition_height)
{
    XmssError result = XMSS_UNINITIALIZED;
    if (generation_buffer == NULL || key_context == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }
    XmssInternalCache *cache_to_build = generation_buffer->cache_under_construction;
    XmssInternalCache *cache_to_use = generation_buffer->partition_cache;
    const XmssParameterSetOID param_set = (XmssParameterSetOID)key_context->context.parameter_set;
    const XmssCacheType build_cache_type =
            cache_to_build == NULL ? XMSS_CACHE_NONE : (XmssCacheType)cache_to_build->cache_type;

    if (build_cache_type != XMSS_CACHE_NONE) {
        uint32_t build_cache_level = partition_height;
        if (cache_to_build->cache_level > partition_height) {
            /* The cache (start) level is higher than the partition level, so now compute nodes on the (first) level
             * that is to be cached.
             */
            build_cache_level = cache_to_build->cache_level;
            const uint32_t start_index = 0u;
            const uint32_t stop_index = 1 << (XMSS_TREE_DEPTH(param_set) - build_cache_level);
            for (uint32_t index = start_index; index < stop_index; index++) {
                XmssNativeValue256 *cache_node = &cache_to_build->cache[
                    XMSS_CACHE_ENTRY_OFFSET(build_cache_type, build_cache_level, param_set, build_cache_level, index)
                ];
                /* The start index of xmss_tree_hash is at OTS indexing level, hence the multiplication by
                * power(2, cache_to_build->cache_level)
                */
                result = xmss_tree_hash(cache_node, key_context, cache_to_use,
                        index << build_cache_level, build_cache_level);
                if (result != XMSS_OKAY) {
                    return result;
                }
            }
        }
        /* If we use top caching, we need to finish its tree. */
        if (build_cache_type == XMSS_CACHE_TOP) {
            result = XMSS_UNINITIALIZED;
            result = xmss_fill_top_cache(cache_to_build, key_context,
                    XMSS_TREE_DEPTH(param_set), 0, build_cache_level);
            if (result != XMSS_OKAY) {
                return result;
            }
        }
        cache_to_use = cache_to_build;
    }
    return xmss_tree_hash(&key_context->public_key_root, key_context, cache_to_use, 0,
        XMSS_TREE_DEPTH(generation_buffer->context->context.parameter_set));
}

XmssError xmss_finish_calculate_public_key(XmssPublicKeyInternalBlob **const public_key,
    XmssKeyGenerationContext **const generation_buffer, XmssKeyContext *const key_context)
{
    if (public_key == NULL || generation_buffer == NULL || *generation_buffer == NULL || key_context == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    XmssError result = check_key_context_well_formed(key_context);
    if (result != XMSS_OKAY) {
        return XMSS_ERR_BAD_CONTEXT;
    }
    if (key_context != (*generation_buffer)->context) {
        return XMSS_ERR_BAD_CONTEXT;
    }

    /* Check that all partitions have been marked as finished. */
    for (size_t i = 0; i < (*generation_buffer)->generation_partitions; i++) {
        if ((*generation_buffer)->partition_states[i].state != XMSS_GENERATION_STATE_FINISHED) {
            return XMSS_ERR_UNFINISHED_PARTITIONS;
        }
    }

    /* Determine the tree-height of the partitions. */
    uint32_t partition_height = 0;
    result = XMSS_UNINITIALIZED;
    result = partitions_to_tree_height(&partition_height, (uint32_t)(*generation_buffer)->generation_partitions,
            (XmssParameterSetOID)key_context->context.parameter_set);
    if (result != XMSS_OKAY) {
        return result;
    }

    /* Determine the cache size in order to allocate the public key blob. */
    XmssInternalCache *cache_to_build = (*generation_buffer)->cache_under_construction;
    const XmssCacheType cache_type =
            cache_to_build == NULL ? XMSS_CACHE_NONE : (XmssCacheType)cache_to_build->cache_type;
    const uint32_t cache_level = (cache_type == XMSS_CACHE_NONE ? 0 : cache_to_build->cache_level);
    const XmssParameterSetOID param_set = (XmssParameterSetOID)key_context->context.parameter_set;
    const size_t public_key_blob_size = XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE(cache_type, cache_level, param_set);
    const size_t public_key_size = public_key_blob_size - sizeof(XmssPublicKeyInternalBlob);
    XmssPublicKeyInternalBlob *reallocated_blob = key_context->context.realloc(*public_key, public_key_blob_size);

    if (reallocated_blob == NULL) {
        return XMSS_ERR_ALLOC_ERROR;
    }
    reallocated_blob->data_size = public_key_size;

    /* Pointer to the public key structure the blob. */
    XmssPublicKeyInternal *const public_key_inner = (XmssPublicKeyInternal *)reallocated_blob->data;

    /* Compute the public key root node and fill caches as appropriate. */
    result = XMSS_UNINITIALIZED;
    result = xmss_finish_calculate_public_key_internal(key_context, *generation_buffer, partition_height);

    /* Check the result of the root node computation. */
    if (result != XMSS_OKAY) {
        /* Free the public key blob. */
        key_context->context.free(reallocated_blob);
        *public_key = NULL;
        return result;
    }
    /* The cache_to_build is moved from the generation context to the key context. */
    (*generation_buffer)->cache_under_construction = NULL;
    /* Free the generation buffer and its partition cache that are no longer needed. */
    xmss_free_key_generation_context(*generation_buffer);
    *generation_buffer = NULL;

    /* Free the key context's existing cache if there is one. */
    key_context->context.free(key_context->cache);
    /* Update the key context to add the new public key root and the new cache pointer (may be NULL). */
    key_context->cache = cache_to_build;
    key_context->initialized = (uint32_t)XMSS_INITIALIZATION_WITH_PUBLIC_KEY;

    /* Canonicalize and populate in the XmssPublicKeyInner. */
    public_key_inner->public_key_version = convert_big_endian_word(XMSS_VERSION_CURRENT_PUBLIC_KEY_STORAGE);
    public_key_inner->scheme_identifier = convert_big_endian_word(param_set);
    public_key_inner->redundant_version = convert_big_endian_word(XMSS_VERSION_CURRENT_PUBLIC_KEY_STORAGE);
    public_key_inner->redundant_scheme_identifier = convert_big_endian_word(param_set);
    /* The digest is already in big-endian form. */
    public_key_inner->digest_of_private_key_static_blob = key_context->private_key_digest;
    /* Set the public key root in big-endian form. */
    native_to_big_endian_256(&public_key_inner->root, &key_context->public_key_root);
    public_key_inner->cache_type = convert_big_endian_word((uint32_t)cache_type);
    public_key_inner->cache_level = convert_big_endian_word((uint32_t)cache_level);
    if (cache_type != XMSS_CACHE_NONE && cache_level != XMSS_TREE_DEPTH(param_set)) {
        native_to_big_endian((uint8_t *)public_key_inner->cache, cache_to_build->cache->data,
                XMSS_VALUE_256_WORDS * XMSS_CACHE_ENTRY_COUNT(cache_to_build->cache_type,
                    cache_to_build->cache_level, key_context->context.parameter_set));
    }

    /* Compute the digest over the contents of the XmssPublicKeyInternal structure excluding the integrity digest
     * field itself.
     */
    xmss_digest(HASH_FUNCTIONS_FROM(key_context->context) &public_key_inner->integrity,
                ((uint8_t *)public_key_inner) + sizeof(public_key_inner->integrity),
                public_key_size - sizeof(public_key_inner->integrity));

    /* Check for bit errors. */
    if (convert_big_endian_word(public_key_inner->public_key_version) != XMSS_VERSION_CURRENT_PUBLIC_KEY_STORAGE
        || convert_big_endian_word(public_key_inner->redundant_version) != XMSS_VERSION_CURRENT_PUBLIC_KEY_STORAGE
        || convert_big_endian_word(public_key_inner->scheme_identifier) != (uint32_t)key_context->context.parameter_set
        || convert_big_endian_word(public_key_inner->redundant_scheme_identifier)
            != (uint32_t)key_context->context.parameter_set
    ) {
        key_context->context.free(reallocated_blob);
        *public_key = NULL;
        return XMSS_ERR_FAULT_DETECTED;
    }

    *public_key = reallocated_blob;
    return result;
}

XmssError xmss_verify_public_key(const XmssPublicKeyInternalBlob *const pub_key,
    const XmssPrivateKeyStatelessBlob *const private_key, const XmssKeyContext *const key_context)
{
    /* To protect against bit errors in the CPU's flag register, we execute some if-statements in this function twice.
     * The variables being checked are volatile, so the compiler is not allowed to optimize away the redundant if. */

    /* No redundant NULL pointer checks because a bit error here can only lead to a segfault. */
    if (pub_key == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    size_t pub_key_size = pub_key->data_size;
    XmssPublicKeyInternal *pub_key_internal = NULL;
    XmssParameterSetOID scheme_identifier = 0;
    XmssCacheType cache_type = XMSS_CACHE_NONE;
    uint32_t cache_level = 0;
    volatile XmssError err_code = XMSS_UNINITIALIZED;
    volatile ValueCompareResult value_cmp = VALUES_ARE_NOT_EQUAL;
    volatile bool private_key_checked = false;
    volatile bool key_context_checked = false;

    /* Check that the blob is large enough to contain all the fields of XmssPublicKeyInternal before the cache.
     * We need to know that we can access these fields before we can calculate the actual expected data_size.
     * No redundant checks because an incorrect size leads to an incorrect integrity digest or a segfault. */
    if (pub_key_size < sizeof(XmssPublicKeyInternal)) {
        return XMSS_ERR_INVALID_BLOB;
    }
    pub_key_internal = (XmssPublicKeyInternal *)pub_key->data;

    /* Check that the size is correct and does not have a flipped bit. */
    REDUNDANT_RETURN_IF(
        convert_big_endian_word(pub_key_internal->public_key_version) != XMSS_VERSION_CURRENT_PUBLIC_KEY_STORAGE,
        XMSS_ERR_INVALID_BLOB);
    if (convert_big_endian_word(pub_key_internal->redundant_version) != XMSS_VERSION_CURRENT_PUBLIC_KEY_STORAGE) {
        return XMSS_ERR_FAULT_DETECTED;
    }

    /* Determine the hash function to use for the integrity digest. */
    scheme_identifier = (XmssParameterSetOID)convert_big_endian_word(pub_key_internal->scheme_identifier);

    DEFINE_HASH_FUNCTIONS;
    err_code = INITIALIZE_HASH_FUNCTIONS(scheme_identifier);
    REDUNDANT_RETURN_ERR(err_code);

    /* Extract and validate the required parameters to calculate the expected size. */
    cache_type = (XmssCacheType)convert_big_endian_word(pub_key_internal->cache_type);
    if (cache_type != XMSS_CACHE_NONE && cache_type != XMSS_CACHE_SINGLE_LEVEL && cache_type != XMSS_CACHE_TOP) {
        return XMSS_ERR_INVALID_BLOB;
    }
    cache_level = convert_big_endian_word(pub_key_internal->cache_level);
    if (cache_level > XMSS_TREE_DEPTH(scheme_identifier)) {
        return XMSS_ERR_INVALID_BLOB;
    }

    if (pub_key_size != XMSS_PUBLIC_KEY_INTERNAL_SIZE(cache_type, cache_level, scheme_identifier)) {
        return XMSS_ERR_INVALID_BLOB;
    }

    value_cmp = check_integrity_digest(HASH_FUNCTIONS &pub_key_internal->integrity,
        (uint8_t *)pub_key_internal + sizeof(pub_key_internal->integrity),
        pub_key_size - sizeof(pub_key_internal->integrity));
    REDUNDANT_RETURN_IF(value_cmp != VALUES_ARE_EQUAL, XMSS_ERR_FAULT_DETECTED);

    if (private_key != NULL) {
        XmssPrivateKeyStateless *private_key_internal = NULL;

        /* Separate size check, to ensure that we can access the digest of the private key stateless blob. */
        if (private_key->data_size != XMSS_PRIVATE_KEY_STATELESS_BLOB_SIZE - sizeof(XmssPrivateKeyStatelessBlob)) {
            return XMSS_ERR_INVALID_BLOB;
        }

        /*
         * Check that this is the private key that corresponds to the public key.
         * This check is optimistically performed before verifying the integrity of the private key stateless blob,
         * since that will spuriously fail if it uses a different hash than the public key being verified.
         */
        private_key_internal = (XmssPrivateKeyStateless *)private_key->data;
        value_cmp = compare_values_256(&pub_key_internal->digest_of_private_key_static_blob,
                                     &private_key_internal->integrity);
        REDUNDANT_RETURN_IF(value_cmp != VALUES_ARE_EQUAL, XMSS_ERR_ARGUMENT_MISMATCH);

        err_code = XMSS_UNINITIALIZED;
        err_code = verify_private_key_stateless_internal(HASH_FUNCTIONS private_key,
            scheme_identifier, convert_big_endian_word(pub_key_internal->redundant_scheme_identifier));
        REDUNDANT_RETURN_ERR(err_code);

        private_key_checked = true;
    }

    if (key_context != NULL) {
        if (key_context->initialized == XMSS_INITIALIZATION_UNINITIALIZED) {
            return XMSS_ERR_BAD_CONTEXT;
        }
        value_cmp = compare_values_256(&pub_key_internal->digest_of_private_key_static_blob,
                                     &key_context->private_key_digest);
        REDUNDANT_RETURN_IF(value_cmp != VALUES_ARE_EQUAL, XMSS_ERR_ARGUMENT_MISMATCH);
        key_context_checked = true;
    }

    /* Check that a bit error didn't cause the program to skip verification steps. */
    if (private_key_checked != (private_key != NULL) || key_context_checked != (key_context != NULL)) {
        return XMSS_ERR_FAULT_DETECTED;
    }

    return err_code;
}
