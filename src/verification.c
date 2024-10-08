/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Max Fillinger
 * SPDX-FileContributor: Frans van Dorsselaer
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
#include "verification.h"

#include "endianness.h"
#include "fault_detection_helpers.h"
#include "opaque_structures.h"
#include "rand_hash.h"
#include "structures.h"
#include "utils.h"
#include "wotsp_verification.h"
#include "xmss_hashes.h"
#include "xmss_ltree.h"


/**
 * @brief
 * The states of VerificationContextInternal.
 *
 * @remarks
 * Any values not explicitly defined shall be interpreted as #VERIFICATION_CTX_UNINITIALIZED.
 */
typedef enum VerificationContextState
{
    /** Explicitly uninitialized; set when xmss_verification_init fails. */
    VERIFICATION_CTX_UNINITIALIZED = XMSS_DISTANT_VALUE_1,

    /**
     * Initialized; ready to accept any number of calls to xmss_verification_update followed by any number of calls
     * to xmss_verification_check.
     */
    VERIFICATION_CTX_INITIALIZED = XMSS_DISTANT_VALUE_2,

    /** xmss_verification_check has been called at least once, and until now all verifications succeeded. */
    VERIFICATION_CTX_CALCULATED = XMSS_DISTANT_VALUE_3,

    /** Verification failed; final state. */
    VERIFICATION_CTX_INVALID_SIGNATURE = XMSS_DISTANT_VALUE_4,

    /** Fault detected; final state. */
    VERIFICATION_CTX_FAULT_DETECTED = XMSS_DISTANT_VALUE_5,

} VerificationContextState;


/** @brief Internal representation of VerificationContext. */
typedef struct VerificationContextInternal {

    /* 64-bit alignment boundary */

    /** @brief The state of the context, in a fixed size union. */
    union {
        VerificationContextState value;
        uint32_t alignment;
    } state;

    /** @brief The parameter set of the public key, in a fixed size union. */
    union {
        XmssParameterSetOID value;
        uint32_t alignment;
    } parameter_set;

    /* 64-bit alignment boundary */

    /**
     * @brief
     * A pointer to the public key, in a fixed size union.
     *
     * @remarks
     * The pointer value itself is volatile to detect pointer manipulation during xmss_verification_check.
     */
    union {
        const XmssPublicKey *volatile pointer;
        uint64_t alignment;
    } public_key;

    /* 64-bit alignment boundary */

    /** @brief A pointer to the signature, in a fixed size union. */
    union {
        const XmssSignature *pointer;
        uint64_t alignment;
    } signature;

    /* 64-bit alignment boundary */

    /** @brief The context for the message digest calculation. */
    XmssHMsgCtx h_msg_ctx;

    /* 64-bit alignment boundary */

    /** @brief The calculated public key root; only to be interpreted when state == VERIFICATION_CTX_CALCULATED. */
    XmssValue256 calculated_root;

    /* 64-bit alignment boundary */

} VerificationContextInternal;

/** @private */
XMSS_STATIC_ASSERT(sizeof(VerificationContextInternal) == XMSS_VERIFICATION_CONTEXT_SIZE,
    "XMSS_VERIFICATION_CONTEXT_SIZE does not match actual size of VerificationContextInternal.");


XmssError xmss_verification_init(XmssVerificationContext *const context,
    const XmssPublicKey *const public_key, const XmssSignature *const signature,
    const size_t signature_length)
{
    if (context == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }
    VerificationContextInternal *const ctx = (VerificationContextInternal *)context->data;

    /* Just in case we fail *and* the state is accidentally in one of the defined valid states *and* the caller fails
     * to honor our error return *and* calls one of the other functions, we first set the state explicitly to
     * uninitialized.
     */
    ctx->state.value = VERIFICATION_CTX_UNINITIALIZED;

    if (public_key == NULL || signature == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }

    /* We store the (native) XmssParameterSetOID explicitly, just in case the caller forgets about keeping the public
     * key constant between calls. Changing the public key will simply fail signature verification, but changing the
     * parameter set would mess up our hash context.
     */
    ctx->parameter_set.value = (XmssParameterSetOID)convert_big_endian_word(public_key->scheme_identifier);

    /* This effectively validates the public key (in the sense that the parameter set is valid and supported). */
    DEFINE_HASH_FUNCTIONS;
    if (INITIALIZE_HASH_FUNCTIONS(ctx->parameter_set.value) != XMSS_OKAY)
    {
        return XMSS_ERR_INVALID_ARGUMENT;
    }

    /* Bail out early if the provided signature cannot possibly be correct. */
    if (signature_length != XMSS_SIGNATURE_SIZE(ctx->parameter_set.value)) {
        return XMSS_ERR_INVALID_SIGNATURE;
    }
    uint32_t native_leaf_index = convert_big_endian_word(signature->leaf_index);
    if (native_leaf_index >= 1u << XMSS_TREE_DEPTH(ctx->parameter_set.value)) {
        return XMSS_ERR_INVALID_SIGNATURE;
    }

    ctx->public_key.pointer = public_key;
    ctx->signature.pointer = signature;

    Input_H_msg input = INIT_INPUT_H_MSG;
    big_endian_to_native_256(&input.r, &signature->random_bytes);
    big_endian_to_native_256(&input.Root, &public_key->root);
    input.idx_sig = native_leaf_index;

    xmss_H_msg_init(HASH_FUNCTIONS &ctx->h_msg_ctx, &input);

    /* For good measure (in case someone reuses the context and skips the calculation the second use). */
    memset(&ctx->calculated_root, 0, sizeof(ctx->calculated_root));

    ctx->state.value = VERIFICATION_CTX_INITIALIZED;

    return XMSS_OKAY;
}


XmssError xmss_verification_update(XmssVerificationContext *const context, const uint8_t *const part,
    const size_t part_length, const uint8_t *volatile *const part_verify)
{
    if (part_verify != NULL) {
        *part_verify = NULL;
    }

    if (context == NULL || (part == NULL && part_length > 0)) {
        return XMSS_ERR_NULL_POINTER;
    }
    VerificationContextInternal *const ctx = (VerificationContextInternal *)context->data;

    if (ctx->state.value != VERIFICATION_CTX_INITIALIZED) {
        return XMSS_ERR_BAD_CONTEXT;
    }

    if (part_length == 0) {
        /* Nothing to do. This supports callers calling this function exactly once (with the entire message) and the
         * message just happens to be empty (without the caller realizing that).
         */
        if (part_verify != NULL) {
            *part_verify = part;
        }
        return XMSS_OKAY;
    }

    DEFINE_HASH_FUNCTIONS;
    if (INITIALIZE_HASH_FUNCTIONS(ctx->parameter_set.value) != XMSS_OKAY)
    {
        /* The only reason this could fail at this point is a corrupt value of the parameter set. */
        return XMSS_ERR_FAULT_DETECTED;
    }

    xmss_H_msg_update(HASH_FUNCTIONS &ctx->h_msg_ctx, part, part_length, part_verify);

    return XMSS_OKAY;
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
 *
 * @retval XMSS_OKAY                Leaf node calculated successfully.
 * @retval XMSS_ERR_FAULT_DETECTED  A fault was detected.
 */
static inline XmssError calculate_leaf_node(HASH_FUNCTIONS_PARAMETER XmssNativeValue256 *const leaf_node,
    const uint32_t leaf_index, const XmssNativeValue256 *const seed, const XmssNativeValue256 *const digest,
    const XmssSignature *const signature)
{
    ASSERT_HASH_FUNCTIONS();
    assert(leaf_node != NULL && seed != NULL && digest != NULL && signature != NULL);

    WotspSignature wotsp_signature = { 0 };
    WotspPublicKey expected_wotsp_public_key = { 0 };
    ADRS adrs = { 0 };
    volatile XmssError result = XMSS_UNINITIALIZED;

    /* Convert the WOTS+ signature contained in signature to native-endian and calculate the expected WOTS+
     * public key. */
    big_endian_to_native((uint32_t *)&wotsp_signature, (const uint8_t *)signature->wots_signature,
        XMSS_VALUE_256_WORDS * XMSS_WOTSP_LEN);
    result = wotsp_calculate_expected_public_key(HASH_FUNCTIONS &expected_wotsp_public_key, digest, &wotsp_signature,
        seed, leaf_index);
    REDUNDANT_RETURN_ERR(result);

    /* Compress the WOTS+ public key to get the corresponding leaf node of the XMSS tree. */
    adrs.type = ADRS_type_L_tree_Address;
    adrs.typed.L_tree_Address.L_tree_address = leaf_index;
    xmss_ltree(HASH_FUNCTIONS leaf_node, &expected_wotsp_public_key, &adrs, seed);

    return result;
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
static inline void calculate_root_node(HASH_FUNCTIONS_PARAMETER XmssNativeValue256 *const tree_node,
    const uint32_t leaf_index, const uint32_t tree_height, const XmssNativeValue256 *const seed,
    const XmssValue256 *const authentication_path)
{
    ASSERT_HASH_FUNCTIONS();
    assert(tree_node != NULL && authentication_path != NULL);

    Input_PRF input_prf = INIT_INPUT_PRF;
    input_prf.KEY = *seed;
    input_prf.M.ADRS.type = ADRS_type_Hash_Tree_Address;
    input_prf.M.ADRS.typed.Hash_Tree_Address.tree_index = leaf_index;

    for (uint32_t height = 0; height < tree_height; height++) {
        XmssNativeValue256 auth_path_node = { 0 };
        big_endian_to_native_256(&auth_path_node, &authentication_path[height]);
        input_prf.M.ADRS.typed.Hash_Tree_Address.tree_height = height;

        if ((input_prf.M.ADRS.typed.Hash_Tree_Address.tree_index & 1) == 0) {
            input_prf.M.ADRS.typed.Hash_Tree_Address.tree_index /= 2;
            rand_hash(HASH_FUNCTIONS tree_node, &input_prf, tree_node, &auth_path_node);
        }
        else {
            input_prf.M.ADRS.typed.Hash_Tree_Address.tree_index /= 2;
            rand_hash(HASH_FUNCTIONS tree_node, &input_prf, &auth_path_node, tree_node);
        }
    }
}

XmssError xmss_verification_check(XmssVerificationContext *const context, const XmssPublicKey *public_key)
{
    if (context == NULL) {
        return XMSS_ERR_NULL_POINTER;
    }
    VerificationContextInternal *const ctx = (VerificationContextInternal *)context->data;

    switch (ctx->state.value) {
        case VERIFICATION_CTX_INITIALIZED:
            /* This is the first call to this function after the last xmss_verification_update. Calculate the expected
             * root first. */

            if (public_key != ctx->public_key.pointer)
            {
                /* Pointer manipulation detected, cache the result and bail out. */
                ctx->state.value = VERIFICATION_CTX_FAULT_DETECTED;
                return XMSS_ERR_FAULT_DETECTED;
            }
            {
                uint32_t leaf_index = convert_big_endian_word(ctx->signature.pointer->leaf_index);
                volatile XmssError result = XMSS_UNINITIALIZED;
                XmssNativeValue256 digest = { 0 };
                XmssNativeValue256 native_seed = { 0 };
                XmssNativeValue256 tree_node = { 0 };

                big_endian_to_native_256(&native_seed, &ctx->public_key.pointer->seed);

                DEFINE_HASH_FUNCTIONS;
                if (INITIALIZE_HASH_FUNCTIONS(ctx->parameter_set.value) != XMSS_OKAY)
                {
                    /* The only reason this could fail at this point is a corrupt value of the parameter set. */
                    ctx->state.value = VERIFICATION_CTX_FAULT_DETECTED;
                    return XMSS_ERR_FAULT_DETECTED;
                }

                xmss_H_msg_finalize(HASH_FUNCTIONS &digest, &ctx->h_msg_ctx);

                result = calculate_leaf_node(HASH_FUNCTIONS &tree_node, leaf_index, &native_seed, &digest,
                    ctx->signature.pointer);
                REDUNDANT_RETURN_ERR(result);

                calculate_root_node(HASH_FUNCTIONS &tree_node, leaf_index, XMSS_TREE_DEPTH(ctx->parameter_set.value),
                    &native_seed, ctx->signature.pointer->authentication_path);

                native_to_big_endian_256(&ctx->calculated_root, &tree_node);
            }

            ctx->state.value = VERIFICATION_CTX_CALCULATED;
            /* fall through */

        case VERIFICATION_CTX_CALCULATED:
            if (public_key != ctx->public_key.pointer)
            {
                /* Pointer manipulation detected, cache the result and bail out. */
                ctx->state.value = VERIFICATION_CTX_FAULT_DETECTED;
                return XMSS_ERR_FAULT_DETECTED;
            }
            {
                volatile ValueCompareResult value_cmp = VALUES_ARE_NOT_EQUAL;
                value_cmp = compare_values_256(&ctx->public_key.pointer->root, &ctx->calculated_root);
                /* For simple bit-error resilience, we check the return value twice. */
                if (value_cmp == VALUES_ARE_EQUAL) {
                    if (value_cmp == VALUES_ARE_EQUAL) {
                        /* Signature appears valid. We do not cache the result, so this can be checked again for fault
                         * tolerance. */
                        return XMSS_OKAY;
                    }
                }
            }

            /* Signature failed verification. Cache the result. */
            ctx->state.value = VERIFICATION_CTX_INVALID_SIGNATURE;
            /* fall through */

        case VERIFICATION_CTX_INVALID_SIGNATURE:
            /* Verification failed already, just return that result again. */
            return XMSS_ERR_INVALID_SIGNATURE;

        case VERIFICATION_CTX_FAULT_DETECTED:
            /* A fault was detected before, just return that result again. */
            return XMSS_ERR_FAULT_DETECTED;

        case VERIFICATION_CTX_UNINITIALIZED:
        default:
            return XMSS_ERR_BAD_CONTEXT;
    }
}
