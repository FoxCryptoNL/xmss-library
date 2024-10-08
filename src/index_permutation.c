/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Pepijn Westen
 */

/**
 * @file
 * @brief
 * Pseudo-random permutation of an XMSS key's index space.
 */
#include <assert.h>
#include <string.h>

#include "index_permutation.h"
#include "xmss_config.h"

#include "endianness.h"
#include "signing_private.h"
#include "wotsp.h"

/**
 * @brief
 * The context structure for the index pseudo random number generation.
*/
typedef struct ObfuscationRandomContext {
    /**
     * @brief
     * The input to the digest function used as a deterministic random generator.
     */
    Input_PRFindex prf_index_input;
    /**
     * @brief
     * The random pool.
    */
    XmssNativeValue256 random_pool;
    /**
     * @brief
     * The size in words of the random pool.
     *
     * @details
     * Expected to always remain in range [8, 0].
    */
    uint32_t random_pool_word_size;
} ObfuscationRandomContext;

/**
 * Initializes the index obfuscation context to a explicitly invalid initial state.
*/
#define INITIALIZE_OBFUSCATION_RANDOM_CONTEXT               \
    {                                                       \
        .prf_index_input = INIT_INPUT_PRFINDEX,             \
        .random_pool = { {0} },                             \
        .random_pool_word_size = 0,                         \
    }

/**
 * @brief
 * Returns a deterministic unbiased pseudorandom selection s, with: 0 <= s < range.
 *
 * @details
 * The determinism requires that the context is initialized deterministically.
 * The determinism for a sequence of calls does require that the range parameter is also deterministic for that
 * sequence. I.e. two sequences are guaranteed to deterministically produce the same results only if the calls for the
 * two sequences are the same.
 * Random numbers are generated in groups of 8 using PRFindex, which is a modification of PRFkeygen.
 * PRFindex generates a deterministic XmssValue256 output based on data in rng_context->prf_index_input,
 * which includes a counter that is incremented every time a new XmssValue256 is generated.
 *
 * @warning The caller is responsible for providing valid inputs. For performance reasons these will not be checked.
 * @param[in]           hash_functions  The hash functions to use.
 * @param[in,out]       rng_context     The context used for random generation, should be pre-initialized by caller.
 * @param[in]           range           The range from which to generate a selection, must be in [1, UINT32_MAX].
 * @returns a value in the range of [0, range - 1].
*/
static uint32_t deterministic_selection(HASH_FUNCTIONS_PARAMETER ObfuscationRandomContext *const rng_context,
    const uint32_t range)
{
    /* Initialize the result to an out-of-band value. */
    uint32_t result = range;
    assert(range > 0);
    assert(rng_context != NULL);

    /*
     * To make a selection without bias, random numbers that are equal to or larger than largest multiple of range that
     * is < 2^32 are disposed.
    */
    const uint32_t bias_threshold = (uint32_t)(-(1ll << 32) % range);

    while (1) {
        if (rng_context->random_pool_word_size == 0) {
            xmss_PRFindex(HASH_FUNCTIONS &rng_context->random_pool, &rng_context->prf_index_input);
            rng_context->prf_index_input.drbg_counter++;
            rng_context->random_pool_word_size = sizeof(XmssNativeValue256) / sizeof(uint32_t);
        }
        result = rng_context->random_pool.data[rng_context->random_pool_word_size - 1];
        rng_context->random_pool_word_size--;

        if (bias_threshold != 0 && result >= bias_threshold) {
            /* result % range would result in a bias, draw a new random number. */
            continue;
        }
        return result % range;
    }
}

XmssError generate_pseudorandom_permutation(HASH_FUNCTIONS_PARAMETER uint32_t *const permutation,
    const uint32_t num_elements, const XmssNativeValue256 *const index_permutation_seed,
    const XmssNativeValue256 *const SEED)
{
    const uint32_t max_index = num_elements - 1;

    ObfuscationRandomContext rng_context = INITIALIZE_OBFUSCATION_RANDOM_CONTEXT;

    if (NULL == permutation || NULL == index_permutation_seed || NULL == SEED) {
        return XMSS_ERR_NULL_POINTER;
    }

    rng_context.prf_index_input.S_INDEX = *index_permutation_seed;
    rng_context.prf_index_input.SEED = *SEED;

    /* Populate the initial non-permuted index space. */
    for (uint32_t i = 0; i < num_elements; i++) {
        permutation[i] = i;
    }
    /* Perform the Fisher-Yates shuffle. */
    for (uint32_t i = 0; i < max_index; i++) {
        uint32_t tmp = permutation[max_index - i];
        /* select one value  in range [0, max_index - i]. */
        uint32_t selection = deterministic_selection(HASH_FUNCTIONS &rng_context, max_index - i + 1);
        permutation[max_index - i] = permutation[selection];
        permutation[selection] = tmp;
    }

    return XMSS_OKAY;
}
