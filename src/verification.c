/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Max Fillinger
 */

/**
 * @file
 * @brief
 * XMSS verification library.
 */

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "config.h"

#include "endianness.h"
#include "structures.h"
#include "utils.h"
#include "verification.h"
#include "wotsp.h"
#include "xmss_hashes.h"
#include "xmss_tree.h"

/**
 * @brief
 * Calculate the digest of msg using H_msg.
 *
 * @warning
 * The caller is responsible for supplying valid pointers. This will not be checked.
 *
 * @param[in]  hash_functions   Hash functions to use.
 * @param[out] digest           Location to store the digest.
 * @param[in]  msg              Message to hash.
 * @param[in]  leaf_index       Index of the signature that is being checked.
 * @param[in]  random           Per-message salt, supplied with the signature, in big-endian.
 * @param[in]  public_key       The public key, in big-endian.
 */
static inline void calculate_message_digest(HASH_ABSTRACTION(const xmss_hashes *const restrict hash_functions)
    XmssNativeValue256 *const restrict digest, const XmssBuffer *const restrict msg, const uint32_t leaf_index,
    const XmssValue256 *const restrict random, const XmssValue256 *const restrict public_key)
{
#if XMSS_ENABLE_HASH_ABSTRACTION
    assert(hash_functions != NULL);
#endif
    assert(digest != NULL && msg != NULL && random != NULL && public_key != NULL);

    Input_H_msg input_h_msg = INIT_INPUT_H_MSG;
    big_endian_to_native_256(&input_h_msg.r, random);
    big_endian_to_native_256(&input_h_msg.Root, public_key);
    input_h_msg.idx_sig = leaf_index;
    xmss_H_msg(HASH_ABSTRACTION(hash_functions) digest, &input_h_msg, msg->data, msg->data_size);
}

/**
 * @brief
 * Calculate the expected WOTS+ public key and compress it to a leaf node of the XMSS hash tree.
 *
 * @warning
 * The caller is responsible for supplying valid pointers. This will not be checked.
 *
 * @param[in]  hash_functions   Hash functions to use.
 * @param[out] leaf_node        Location to store the leaf node.
 * @param[in]  leaf_index       Index of the leaf node.
 * @param[in]  seed             Seed for the PRF.
 * @param[in]  digest           Message digest.
 * @param[in]  signature        XMSS signature containing the WOTS+ signature.
 */
static inline void calculate_leaf_node(HASH_ABSTRACTION(const xmss_hashes *const restrict hash_functions)
    XmssNativeValue256 *const restrict leaf_node, const uint32_t leaf_index, const XmssNativeValue256 *const restrict seed,
    const XmssNativeValue256 *const restrict digest, const XmssSignature *const restrict signature)
{
#if XMSS_ENABLE_HASH_ABSTRACTION
    assert(hash_functions != NULL);
#endif
    assert(leaf_node != NULL && seed != NULL && digest != NULL && signature != NULL);

    WotspSignature wotsp_signature; /* Uninitialized for performance reasons. */
    WotspPublicKey expected_wotsp_public_key;  /* Uninitialized for performance reasons. */
    ADRS adrs = { 0 };

    /* Convert the WOTS+ signature contained in signature to native-endian and calculate the expected WOTS+
     * public key. */
    big_endian_to_native(wotsp_signature.hashes[0].data, signature->wots_signature[0].data,
        XMSS_VALUE_256_WORDS * XMSS_WOTSP_LEN);
    wotsp_calculate_expected_public_key(HASH_ABSTRACTION(hash_functions) &expected_wotsp_public_key, digest,
        &wotsp_signature, seed, leaf_index);

    /* Compress the WOTS+ public key to get the corresponding leaf node of the XMSS tree. */
    adrs.type = ADRS_type_L_tree_Address;
    adrs.typed.L_tree_Address.L_tree_address = leaf_index;
    xmss_ltree(HASH_ABSTRACTION(hash_functions) leaf_node, &expected_wotsp_public_key, &adrs, seed);
}

/**
 * @brief
 * Calculate the root node of the XMSS hash tree from a leaf node and authentication path.
 *
 * @warning
 * The caller is responsible for supplying valid pointers. This will not be checked.
 *
 * @param[in]     hash_functions        Hash functions to use.
 * @param[in,out] tree_node             The hash value of the leaf node; will be overwritten
 *                                      with the value of the root node at the end.
 * @param[in]     leaf_index            The index of the leaf node.
 * @param[in]     tree_height           Height of the XMSS hash tree.
 * @param[in]     seed                  The seed for the PRF.
 * @param[in]     authentication_path   The authentication path, must contain tree_height hashes.
 */
static inline void calculate_root_node(HASH_ABSTRACTION(const xmss_hashes *const restrict hash_functions)
    XmssNativeValue256 *const restrict tree_node, const uint32_t leaf_index, const uint32_t tree_height,
    const XmssNativeValue256 *const restrict seed, const XmssValue256 *const restrict authentication_path)
{
#if XMSS_ENABLE_HASH_ABSTRACTION
    assert(hash_functions != NULL);
#endif
    assert(tree_node != NULL && authentication_path != NULL);

    Input_PRF input_prf = INIT_INPUT_PRF;
    native_256_copy(&input_prf.KEY, seed);
    input_prf.M.ADRS.type = ADRS_type_Hash_Tree_Address;
    input_prf.M.ADRS.typed.Hash_Tree_Address.tree_index = leaf_index;

    for (uint32_t height = 0; height < tree_height; height++) {
        XmssNativeValue256 auth_path_node;  /* Uninitialized for performance reasons. */
        big_endian_to_native_256(&auth_path_node, &authentication_path[height]);
        input_prf.M.ADRS.typed.Hash_Tree_Address.tree_height = height;

        if ((input_prf.M.ADRS.typed.Hash_Tree_Address.tree_index & 1) == 0) {
            input_prf.M.ADRS.typed.Hash_Tree_Address.tree_index /= 2;
            rand_hash(HASH_ABSTRACTION(hash_functions) tree_node, &input_prf, tree_node, &auth_path_node);
        }
        else {
            input_prf.M.ADRS.typed.Hash_Tree_Address.tree_index /= 2;
            rand_hash(HASH_ABSTRACTION(hash_functions) tree_node, &input_prf, &auth_path_node, tree_node);
        }
    }
}

XmssError xmss_calculate_expected_public_key(
    XmssValue256 *const restrict expected_public_key, const XmssBuffer *const restrict msg,
    const XmssPublicKeyBlob *const restrict pub_key, const XmssSignatureBlob *const restrict signature)
{
    if (expected_public_key == NULL || msg == NULL || pub_key == NULL || signature == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }
    XmssParameterSetOID parameter_set = (XmssParameterSetOID)convert_big_endian_word(pub_key->data.scheme_identifier);
    if (signature->data_size != XMSS_SIGNATURE_BLOB_SIZE(parameter_set) - sizeof(XmssSignatureBlob)) {
        return XMSS_ERR_INVALID_BLOB;
    }

    const XmssSignature *signature_data = xmss_get_signature_struct(signature);
    uint32_t leaf_index = convert_big_endian_word(signature_data->leaf_index);
    XmssError err_code = XMSS_OKAY;
    XmssNativeValue256 msg_digest;  /* Uninitialized for performance reasons. */
    XmssNativeValue256 seed;  /* Uninitialized for performance reasons. */
    XmssNativeValue256 tree_node;  /* Uninitialized for performance reasons. */
#if XMSS_ENABLE_HASH_ABSTRACTION
    xmss_hashes hash_functions;
#endif

    err_code = xmss_get_hash_functions(HASH_ABSTRACTION(&hash_functions) parameter_set);
    if (err_code != XMSS_OKAY) {
        return err_code;
    }

    big_endian_to_native_256(&seed, &pub_key->data.seed);

    calculate_message_digest(HASH_ABSTRACTION(&hash_functions) &msg_digest, msg, leaf_index,
        &signature_data->random_bytes, &pub_key->data.public_key);
    calculate_leaf_node(HASH_ABSTRACTION(&hash_functions) &tree_node, leaf_index, &seed, &msg_digest, signature_data);
    calculate_root_node(HASH_ABSTRACTION(&hash_functions) &tree_node, leaf_index, XMSS_TREE_DEPTH(parameter_set),
        &seed, signature_data->authentication_path);

    native_to_big_endian_256(expected_public_key, &tree_node);

    return XMSS_OKAY;
}
