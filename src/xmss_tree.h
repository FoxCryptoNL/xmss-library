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

#pragma once

#ifndef XMSS_XMSS_TREE_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_XMSS_TREE_H_INCLUDED

#include <stdint.h>

#include "config.h"

#include "private.h"
#include "wotsp.h"

/**
 * @brief
 * Compute node (start_index / pow(2, target_node_height)) at height target_node_height.
 * Implementation of RFC 8391 Algorithm 9: treeHash.
 *
 * @details
 * To compute the fourth node at height 2, target_node_height is 2 and start_index should be 3 * pow(2, 2) = 12 (the
 * index of the first leaf in the sub-tree that generates node `(2, 3)`).
 * The ADRS parameter of RFC 8391 Algorithm 9 has been omitted, as the information it contains is relevant only in
 * XMSS^MT (viz. the layer and tree addresses).
 *
 * @param[out]      output              The output for the target node to be written to.
 * @param[in]       key_context         The key context.
 * @param[in]       cache_to_use        The cache to use for skipping parts of the tree that have already been
 *                                      computed, may be NULL.
 * @param[in]       start_index         The index of the first OTS key in the sub-tree, corresponds with parameter 's'
 *                                      from Algorithm 9.
 * @param[in]       target_node_height  The tree level of the target node to compute, must be in range
 *                                      [0, XMSS_TREE_DEPTH(param_set)], corresponds with parameter 't' from
 *                                      Algorithm 9. A value of 0 represents the bottom or leaf level, and
 *                                      XMSS_TREE_DEPTH(param_set) represents the height of the root node of the tree.
 * @returns The root node of the tree.
*/
XmssError xmss_tree_hash(XmssNativeValue256 *restrict output, const XmssKeyContext *key_context,
        const XmssInternalCache *const cache_to_use, const uint32_t start_index, const uint32_t target_node_height);

/**
 * @brief
 * Function to fill a sub-tree of a top-cache, given that the sub-tree has been cached upto a level.
 *
 * @warning The subtree_root_index is specified at the target level, as opposed to the start_index parameter of
 * xmss_tree_hash, which is the index at the OTS index level.
 *
 * @param[in,out]   cache                   The cache to fill, may not be NULL.
 * @param[in]       keygen_context          The key generation context.
 * @param[in]       subtree_root_height     The height of the sub-tree root, should be in range
 *                                          [pre_cached_height, XMSS_TREE_DEPTH(param_set)].
 * @param[in]       subtree_root_index      The index of the sub-tree root at subtree_root_height.
 * @param[in]       pre_cached_height       The height at which the cache is already filled for this sub-tree.
 * @retval XMSS_OKAY    Success.
 * @retval XMSS_ERR_NULL_POINTER    cache or keygen_context was NULL.
 * @retval XMSS_ERR_INVALID_ARGUMENT    subtree_root_height, subtree_root_index or pre_cached_height are at odds
 *                                      with each other or with the cache metadata.
 */
XmssError xmss_fill_top_cache(XmssInternalCache *cache, const XmssKeyContext *const restrict keygen_context,
    uint32_t subtree_root_height, uint32_t subtree_root_index, uint32_t pre_cached_height);

/**
 * @brief
 * Compresses WOTS+ public key. Implementation of L-Tree function from RFC 8391 section 4.1.5.
 *
 * @warning The caller is responsible for providing valid pointers. For performance reasons these will not be checked.
 * @warning the compression is done in-place to conserve memory, so the public key is mangled by this function.
 *
 * @param[in]       hash_functions  The hash functions to use.
 * @param[out]      output          The result of the L-tree computation.
 * @param[in,out]   pk              The public key, which will be overwritten during compression.
 * @param[in,out]   adrs            The adrs structure for this ltree operation. Address type must be set by caller.
 * @param[in]       seed            The public seed in native-endian form.
 */
void xmss_ltree(HASH_ABSTRACTION(const xmss_hashes *restrict hash_functions) XmssNativeValue256 *restrict output,
        WotspPublicKey *restrict pk, ADRS *restrict adrs, const XmssNativeValue256 *restrict seed);

/**
 * @brief
 * Implementation of Randomized Tree Hashing (RFC 8391 section 4.1.4).
 *
 * @warning The caller is responsible for providing valid pointers. For performance reasons these will not be checked.
 *
 * @param[in]       hash_functions  The hash functions to use.
 * @param[out]      digest_out      The randomized hash digest.
 * @param[in,out]   rand_hash_state Structure containing the SEED and the ADRS for this operation.
 *                                  The keyAndMask of the address is written by this function.
 * @param [in]      left            The left input node. May alias with digest_out but not with right.
 * @param [in]      right           The right input node. May alias with digest_out but not with left.
 */
void rand_hash(HASH_ABSTRACTION(const xmss_hashes *restrict hash_functions) XmssNativeValue256 *digest_out,
        Input_PRF *rand_hash_state, const XmssNativeValue256 *left, const XmssNativeValue256 *right);

#endif /* !XMSS_XMSS_TREE_H_INCLUDED */
