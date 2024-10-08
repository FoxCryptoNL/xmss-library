/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Pepijn Westen
 */

/**
 * @file
 * @brief
 * XMSS tree hashing.
 */

#include <assert.h>

#include "rand_hash.h"


void rand_hash(HASH_FUNCTIONS_PARAMETER XmssNativeValue256 *const digest_out, Input_PRF *const rand_hash_state,
    const XmssNativeValue256 *const left, const XmssNativeValue256 *const right)
{
    Input_H input_h = INIT_INPUT_H;

    assert(digest_out != NULL);
    assert(rand_hash_state != NULL);
    assert(left != NULL);
    assert(right != NULL);
    ASSERT_HASH_FUNCTIONS();

    /* Compute KEY for H. */
    rand_hash_state->M.ADRS.typed.L_tree_Address.keyAndMask = 0;
    xmss_PRF(HASH_FUNCTIONS &input_h.KEY, rand_hash_state);

    /* Compute and apply BM_0 to LEFT input node. */
    rand_hash_state->M.ADRS.typed.L_tree_Address.keyAndMask = 1;
    xmss_PRF(HASH_FUNCTIONS &input_h.M[0], rand_hash_state);
    for (size_t i = 0; i < XMSS_VALUE_256_WORDS; i++) {
        input_h.M[0].data[i] ^= left->data[i];
    }

    /* Compute and apply BM_1 to RIGHT input node. */
    rand_hash_state->M.ADRS.typed.L_tree_Address.keyAndMask = 2;
    xmss_PRF(HASH_FUNCTIONS &input_h.M[1], rand_hash_state);
    for (size_t i = 0; i < XMSS_VALUE_256_WORDS; i++) {
        input_h.M[1].data[i] ^= right->data[i];
    }

    /* Compute output */
    xmss_H(HASH_FUNCTIONS digest_out, &input_h);
}
