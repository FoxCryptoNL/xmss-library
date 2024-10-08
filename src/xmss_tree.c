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
#include <string.h>

#include "xmss_tree.h"

#include "endianness.h"
#include "rand_hash.h"
#include "signing_private.h"
#include "types.h"
#include "utils.h"
#include "wotsp_signing.h"
#include "xmss_hashes.h"
#include "xmss_ltree.h"

/**
 * @brief
 * The maximum tree depth supported by this library.
*/
#define XMSS_MAX_TREE_DEPTH 20

/**
 * @brief
 * A Stack structure for use in the TreeHash algorithm.
*/
typedef struct XmssTreeHashStack {
    /**
     * @brief
     * The number of items on the stack.
     *
     * @details
     * must stay in range [0, XMSS_MAX_TREE_DEPTH - 1], with 0 meaning the stack is empty.
     * This also represents the index of the first empty item of the stack.
     */
    uint32_t count;
    /**
     * @brief
     * The stack's item storage array, with a length that is sufficient for the maximum supported tree depth.
     *
     * @details
     * if count > 0, item[count - 1] is the top item on the stack.
     * The stack has a fixed size sufficient for XMSS_MAX_TREE_DEPTH items.
     */
    struct {
        /** @brief Tree height of the node. */
        uint32_t tree_height;
        /** @brief The digest of the node. */
        XmssNativeValue256 digest;
    } items[XMSS_MAX_TREE_DEPTH];
} XmssTreeHashStack;

/** @brief Initializer for an empty XmssTreeHashStack. */
#define INIT_XMSS_TREE_HASH_STACK {                                           \
    .count = 0,                                                               \
}

XmssError xmss_tree_hash(XmssNativeValue256 *const output, const XmssKeyContext *const key_context,
    const XmssInternalCache *const cache_to_use, const uint32_t start_index, const uint32_t target_node_height)
{
    XmssTreeHashStack stack = INIT_XMSS_TREE_HASH_STACK;
    /* The tree_hash_state input can largely be reused between the different tree_hash operations.
     * This structure contains both the SEED and the ADRS.
    */
    Input_PRF tree_hash_state = INIT_INPUT_PRF;

    /* A convenience accessor to the ADRS member of tree_hash_state. */
    ADRS *adrs = &tree_hash_state.M.ADRS;

    if (key_context == NULL || output == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }
    /* The tree height should be in the tree structure that's defined by the parameter set. */
    if (target_node_height > XMSS_TREE_DEPTH(key_context->context.parameter_set)) {
        return XMSS_ERR_ARGUMENT_MISMATCH;
    }
    /* The algorithm requires that start_index is a multiple of 2^target_node_height. */
    if (start_index % (1 << target_node_height) != 0) {
        return XMSS_ERR_ARGUMENT_MISMATCH;
    }
    /* The start node should be in the tree structure that's defined by the parameter set. */
    if (start_index >= (1u << (XMSS_TREE_DEPTH(key_context->context.parameter_set)))) {
        return XMSS_ERR_ARGUMENT_MISMATCH;
    }

    /* Set the seed in the tree_hash_state. */
    tree_hash_state.KEY = key_context->private_stateless.seed;

    for (uint32_t i = 0 ; i < (1u << target_node_height) ; i++) {
        /* The current node. This is the data storage for the leaf node at OTS address start_index + i. */
        XmssNativeValue256 node;
        adrs->typed.Hash_Tree_Address.tree_height = 0;
        /* Check if cache contains a relevant level (target's level or a lower level). */
        if (cache_to_use != NULL && cache_to_use->cache_level <= target_node_height) {
            if (cache_to_use->cache_type == XMSS_CACHE_TOP) {
                /* in case of a top-cache, the target node is already cached. */
                adrs->type = ADRS_type_Hash_Tree_Address;
                adrs->typed.Hash_Tree_Address.padding = 0;
                adrs->typed.Hash_Tree_Address.tree_height = target_node_height;
                adrs->typed.Hash_Tree_Address.tree_index = (i + start_index) >> adrs->typed.Hash_Tree_Address.tree_height;
            } else {
                adrs->type = ADRS_type_Hash_Tree_Address;
                adrs->typed.Hash_Tree_Address.padding = 0;
                adrs->typed.Hash_Tree_Address.tree_height = cache_to_use->cache_level;
                adrs->typed.Hash_Tree_Address.tree_index = (i + start_index) >> cache_to_use->cache_level;
            }
            const XmssNativeValue256 *const cached_digest = &cache_to_use->cache[
                XMSS_CACHE_ENTRY_OFFSET(cache_to_use->cache_type, cache_to_use->cache_level,
                    key_context->context.parameter_set, adrs->typed.Hash_Tree_Address.tree_height,
                    adrs->typed.Hash_Tree_Address.tree_index)];
            node = *cached_digest;
            /* Increase i with the sub-tree width of the cached node, accounting for the end-of-loop increment of 1. */
            i += (1u << adrs->typed.Hash_Tree_Address.tree_height) - 1u;
        } else {
            /* No cached nodes available for this sub-tree, so start the computation from the public key of
             * start_index + i.
             */
            WotspPublicKey pk;
            /* Generate the public key for the selected leaf. */
            adrs->type = ADRS_type_OTS_Hash_Address;
            adrs->typed.OTS_Hash_Address.OTS_address = start_index + i;
            wotsp_gen_public_key(&key_context->context, &pk, &key_context->private_stateless.private_key_seed,
                                &key_context->private_stateless.seed, start_index + i);

            /* Compress the public key using the ltree algorithm. */
            adrs->type = ADRS_type_L_tree_Address;
            adrs->typed.L_tree_Address.L_tree_address = start_index + i;
            xmss_ltree(HASH_FUNCTIONS_FROM(key_context->context) &node, &pk, adrs,
                    &key_context->private_stateless.seed);

            /* Prepare the state struct for rand_hash computation. */
            adrs->type = ADRS_type_Hash_Tree_Address;
            adrs->typed.Hash_Tree_Address.padding = 0;
            adrs->typed.Hash_Tree_Address.tree_height = 0;
            adrs->typed.Hash_Tree_Address.tree_index = i + start_index;
        }

        while (stack.count && stack.items[stack.count - 1].tree_height == adrs->typed.Hash_Tree_Address.tree_height) {
            /*
             * Compute the node at the next level:
             * Update the tree_index in adrs to the tree index of the node to compute,
             * then pop the top node on the stack as 'left' input and the current node as 'right' input to rand_hash,
             * then update adrs tree_height to the level of the resultant node.
             */
            adrs->typed.Hash_Tree_Address.tree_index = (adrs->typed.Hash_Tree_Address.tree_index - 1) / 2;
            stack.count -= 1;
            rand_hash(HASH_FUNCTIONS_FROM(key_context->context) &node, &tree_hash_state,
                &stack.items[stack.count].digest, &node);
            adrs->typed.Hash_Tree_Address.tree_height += 1;
        }

        /* Push the node to the stack. */
        assert(stack.count < XMSS_MAX_TREE_DEPTH - 1);
        stack.items[stack.count].digest = node;
        stack.items[stack.count].tree_height = adrs->typed.Hash_Tree_Address.tree_height;
        stack.count += 1;
    }

    assert(stack.count == 1);
    assert(stack.items[0].tree_height == target_node_height);

    /* Return the node on the stack. */
    *output = stack.items[0].digest;
    return XMSS_OKAY;
}

XmssError xmss_fill_top_cache(XmssInternalCache *const cache, const XmssKeyContext *const key_context,
    const uint32_t subtree_root_height, const uint32_t subtree_root_index, const uint32_t pre_cached_height)
{
    /* The tree_hash_state input can largely be reused between the different tree_hash operations.
     * This structure contains both the SEED and the ADRS.
    */
    Input_PRF tree_hash_state = INIT_INPUT_PRF;

    /* A convenience accessor to the ADRS member of tree_hash_state. */
    ADRS *adrs = &tree_hash_state.M.ADRS;
    adrs->type = ADRS_type_Hash_Tree_Address;

    if (cache == NULL || key_context == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }
    if (pre_cached_height > subtree_root_height || pre_cached_height < cache->cache_level) {
        return XMSS_ERR_ARGUMENT_MISMATCH;
    }
    if (subtree_root_index >= 1u << (XMSS_TREE_DEPTH(key_context->context.parameter_set) - subtree_root_height)) {
        return XMSS_ERR_ARGUMENT_MISMATCH;
    }

    /* Set the seed in the tree_hash_state. */
    tree_hash_state.KEY = key_context->private_stateless.seed;
    /* Fill the sub-tree. */
    for (uint32_t height = pre_cached_height; height < subtree_root_height; height++) {
        /* Tree height setting for RAND_HASH is tree height of the input nodes. */
        adrs->typed.Hash_Tree_Address.tree_height = height;
        const uint32_t start = subtree_root_index << (subtree_root_height - height);
        const uint32_t stop = (subtree_root_index + 1) << (subtree_root_height - height);
        for (uint32_t index = start; index < stop; index += 2) {
            XmssNativeValue256 *left = &cache->cache[XMSS_CACHE_ENTRY_OFFSET(cache->cache_type, cache->cache_level,
                key_context->context.parameter_set, height, index)];
            XmssNativeValue256 *right = left + 1;
            XmssNativeValue256 *out = &cache->cache[XMSS_CACHE_ENTRY_OFFSET(cache->cache_type, cache->cache_level,
                key_context->context.parameter_set, height + 1, index >> 1)];
            adrs->typed.Hash_Tree_Address.tree_index = index >> 1;
            rand_hash(HASH_FUNCTIONS_FROM(key_context->context) out, &tree_hash_state, left, right);
        }
    }
    return XMSS_OKAY;
}
