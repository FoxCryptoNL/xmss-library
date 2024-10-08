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

#include "libxmss.h"
#include "signing_private.h"
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
LIBXMSS_STATIC
XmssError xmss_tree_hash(XmssNativeValue256 *output, const XmssKeyContext *key_context,
    const XmssInternalCache *cache_to_use, uint32_t start_index, uint32_t target_node_height);

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
LIBXMSS_STATIC
XmssError xmss_fill_top_cache(XmssInternalCache *cache, const XmssKeyContext *keygen_context,
    uint32_t subtree_root_height, uint32_t subtree_root_index, uint32_t pre_cached_height);

#endif /* !XMSS_XMSS_TREE_H_INCLUDED */
