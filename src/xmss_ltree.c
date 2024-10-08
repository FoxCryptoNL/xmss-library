/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Pepijn Westen
 */

/**
 * @file
 * @brief
 * XMSS L-Tree hashing.
 */

#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "xmss_ltree.h"

#include "rand_hash.h"
#include "utils.h"


void xmss_ltree(HASH_FUNCTIONS_PARAMETER XmssNativeValue256 *const output, WotspPublicKey *const pk, ADRS *const adrs,
    const XmssNativeValue256 *const seed)
{
    Input_PRF ltree_state = INIT_INPUT_PRF;
    size_t len = XMSS_WOTSP_LEN;

    assert(output != NULL);
    assert(pk != NULL);
    assert(adrs != NULL);
    assert(seed != NULL);
    ASSERT_HASH_FUNCTIONS();

    ltree_state.M.ADRS = *adrs;
    ltree_state.KEY = *seed;

    /* Reset the tree height. */
    ltree_state.M.ADRS.typed.L_tree_Address.tree_height = 0;

    while (len > 1) {
        for (uint32_t i = 0; i < len / 2; i++) {
            ltree_state.M.ADRS.typed.L_tree_Address.tree_index = i;
            rand_hash(HASH_FUNCTIONS &pk->hashes[i], &ltree_state, &pk->hashes[2 * i], &pk->hashes[2 * i + 1]);
        }
        if (len % 2 == 1) {
            /* Move the leftover node to the first position after the end of the first half of the array. */
            pk->hashes[len / 2] = pk->hashes[len - 1];
            len = len / 2 + 1;
        } else {
            len = len / 2;
        }
        ltree_state.M.ADRS.typed.L_tree_Address.tree_height += 1;
    }
    *output = pk->hashes[0];
}
