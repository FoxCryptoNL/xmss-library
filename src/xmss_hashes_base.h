/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * Prototypes for the XMSS hash functions.
 */

#pragma once

#ifndef XMSS_XMSS_HASHES_BASE_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_XMSS_HASHES_BASE_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "config.h"

#include "structures.h"
#include "types.h"
#include "utils.h"

/** @brief Block size of SHA-256 in bytes. */
#define SHA256_BLOCK_SIZE 64

/** @brief Size of the Keccak state array (for SHAKE256_256 calculations). */
#define KECCAK_STATE_ARRAY_SIZE 200

/** @brief  Value for the ADRS.type member to indicate the union member typed.OTS_Hash_Address is used. */
#define ADRS_type_OTS_Hash_Address (0u)

/** @brief  Value for the ADRS.type member to indicate the union member typed.L_tree_Address is used. */
#define ADRS_type_L_tree_Address (1u)

/** @brief  Value for the ADRS.type member to indicate the union member typed.Hash_Tree_Address is used. */
#define ADRS_type_Hash_Tree_Address (2u)

/**
 * @brief
 * The ADRS structure as defined by RFC 8391, Section 2.5. This structure acts as a unique salt for each of the
 * XMSS hash functions and improves the collision resistance of the underlying hash algorithm.
 */
typedef struct ADRS {
    /** @brief As this implementation does not support Multi-Tree XMSS, this value is always 0. */
    uint32_t layer_address;
    /**
     * @brief
     * This (unaligned) 64-bit number is serialized to byte stream as big-endian. When deserialized as native uint32_t,
     * then the high word comes first, the low word comes last.
     */
    struct {
        /** @brief As this implementation does not support Multi-Tree XMSS, this value is always 0. */
        uint32_t high;
        /** @brief As this implementation does not support Multi-Tree XMSS, this value is always 0. */
        uint32_t low;
    } tree_address;
    /**
     * @brief
     * Either ADRS_type_OTS_Hash_Address, ADRS_type_L_tree_Address, or ADRS_type_Hash_Tree_Address indicating which
     * typed union member is used.
     */
    uint32_t type;
    /** @brief Contains the strong types as indicated by the type member. */
    union {
        /** @brief Used when the ADRS structure is an OTS Hash Address. */
        struct {
            /** @brief The index of the OTS key pair within the tree. */
            uint32_t OTS_address;
            /** @brief The chain address of the hash. */
            uint32_t chain_address;
            /** @brief The address of the hash function call within the chain. */
            uint32_t hash_address;
            /**
             * @brief
             * Used to generate two different addresses for one hash function call.
             *
             * @details
             * Set to zero to generate the key.
             * Set to one to generate the 32-byte bitmask.
             */
            uint32_t keyAndMask;
        } OTS_Hash_Address;
        /** @brief Used when the ADRS structure is an L-tree Address. */
        struct {
            /** @brief The index of the leaf computed with this L-tree. */
            uint32_t L_tree_address;
            /** @brief The height of the node being input for the next computation inside the L-tree. */
            uint32_t tree_height;
            /** @brief The index of the node at tree_height, inside the L-tree. */
            uint32_t tree_index;
            /**
             * @brief
             * Used to generate three different addresses for one function call.
             *
             * @details
             * Set to zero to generate the key.
             * Set to one to generate the most significant 32 bytes of the 64-byte bitmask.
             * Set to two to generate the least significant 32 bytes of the 64-byte bitmask.
             */
            uint32_t keyAndMask;
        } L_tree_Address;
        /** @brief Used when the ADRS structure is a Hash Tree Address. */
        struct {
            /** @brief Must be 0. */
            uint32_t padding;
            /** @brief The height of the tree node being input for the next computation. */
            uint32_t tree_height;
            /** @brief The index of this node at tree_height. */
            uint32_t tree_index;
            /**
             * @brief
             * Used to generate three different addresses for one function call.
             *
             * @details
             * Set to zero to generate the key.
             * Set to one to generate the most significant 32 bytes of the 64-byte bitmask.
             * Set to two to generate the least significant 32 bytes of the 64-byte bitmask.
             */
            uint32_t keyAndMask;
        } Hash_Tree_Address;
    } typed;
} ADRS;

/**
 * @brief
 * Struct holding the index of the signature for generating the per-message randomness. Equals toByte(idx_sig,32).
 */
typedef struct IdxSigBlock {
    /** @brief Zeros. */
    uint32_t zero[7];
    /** @brief The index of the signature. */
    uint32_t idx_sig;
} IdxSigBlock;

/** @private */
XMSS_STATIC_ASSERT(sizeof(ADRS) == sizeof(IdxSigBlock), "ADRS and IdxSigBlock should have equal size.");

/**
 * @brief
 * Initializer for the toByte(x,32) prefix of the specialized XMSS hash functions.
 *
 * @details
 * toByte(x,y) is defined in RFC 8391, Section 2.4.
 *
 * @param[in] x   A non-negative integer.
 */
#define INIT_TO_BYTE_32(x) { { 0, 0, 0, 0, 0, 0, 0, x } }

#if XMSS_ENABLE_SHA256
/**
 * @brief
 * Initializer for the SHA-256 padding in the optimized input to the XMSS hash functions.
 *
 * @param[in] length_in_bits   The length in bits of the entire message that is hashed.
 */
#   define INIT_PADDING_SHA256(length_in_bits) \
    , \
    .padding_sha256 = { \
        .start = 0x80000000, \
        .zero = { 0 }, \
        .length = (length_in_bits) \
    }
#else
#   define INIT_PADDING_SHA256(length)
#endif

/**
 * @brief
 * The optimized input to the XMSS F(KEY,M) hash function.
 *
 * @details
 * Example initialization:
 *
 * ```
 * Input_F input = INIT_INPUT_F;
 *
 * XmssNativeValue256 *source_key;
 * uint8_t *source_message;
 * input.KEY = *source_key;
 * big_endian_to_native(input.M, source_message, 8);
 * ```
 */
typedef struct Input_F {
    /** @brief Initialize to toByte(0). */
    const XmssNativeValue256 prefix_0;

    /**
     * @brief
     * First parameter to the XMSS F(KEY,M) hash function.
     *
     * @details
     * In practice, KEY is always the output of another XMSS hash function.
     */
    XmssNativeValue256 KEY;

    /** @brief The second parameter to the XMSS F(KEY,M) hash function. */
    XmssNativeValue256 M;
#if XMSS_ENABLE_SHA256
    /**
     * @brief
     * Always initialize this padding with INIT_PADDING_SHA256(768), irrespective of the underlying algorithm used.
     */
    struct {
        /** @brief Initialize to 0x80000000. */
        const uint32_t start;
        /** @brief Initialize to { 0 }, size is set to align the struct with the block size of SHA-256. */
        const uint32_t zero[TO_WORDS(SHA256_BLOCK_SIZE - sizeof(XmssNativeValue256)) - 2u];
        /** @brief Initialize to the number of bits before the padding. */
        const uint32_t length;
    } padding_sha256;
#endif
} Input_F;

/** @brief Size of Input_F, excluding SHA-256 padding. */
#define INPUT_F_DATA_SIZE (3u * sizeof(XmssNativeValue256))

/**
 * @brief
 * The initializer for the Input_F structure.
 *
 * @details
 * Note that the non-const fields KEY and M need to be copied in later.
 */
#define INIT_INPUT_F \
    { \
        .prefix_0 = INIT_TO_BYTE_32(0), \
        .KEY = { { 0 } }, \
        .M = { { 0 } } \
        INIT_PADDING_SHA256(TO_BITS(INPUT_F_DATA_SIZE)) \
    }

/**
 * @brief
 * The optimized input to the XMSS H(KEY,M) hash function.
 *
 * @details
 * Example initialization:
 *
 * ```
 * Input_H input = INIT_INPUT_H;
 *
 * XmssNativeValue256 *source_key;
 * uint8_t *source_message;
 * input.KEY = *source_key;
 * big_endian_to_native(input.M[0].data, source_message, 16);
 * ```
 */
typedef struct Input_H {
    /** @brief Initialize to toByte(1). */
    XmssNativeValue256 prefix_1;

    /**
     * @brief
     * The first parameter to the XMSS H(KEY,M) hash function.
     *
     * @details
     * In practice, KEY is always the output of another XMSS hash function.
     */
    XmssNativeValue256 KEY;

    /**
     * @brief
     * The second parameter to the XMSS H(KEY,M) hash function.
     *
     * @details
     * In practice, M is always two consecutive 256-bit values, in native form.
     */
    XmssNativeValue256 M[2];
#if XMSS_ENABLE_SHA256
    /**
     * @brief
     * Always initialize this padding with INIT_PADDING_SHA256(1024), irrespective of the underlying algorithm used.
     */
    struct {
        /** @brief Initialize to 0x80000000. */
        const uint32_t start;
        /** @brief Initialize to { 0 }, size is set to align the struct with the block size of SHA-256. */
        const uint32_t zero[TO_WORDS(SHA256_BLOCK_SIZE) - 2u];
        /** @brief Initialize to the number of bits before the padding. */
        const uint32_t length;
    } padding_sha256;
#endif
} Input_H;

/** @brief Size of Input_H, excluding SHA-256 padding. */
#define INPUT_H_DATA_SIZE (4u * sizeof(XmssNativeValue256))

/**
 * @brief
 * The initializer for the Input_H structure.
 *
 * @details
 * Note that the non-const fields KEY and M need to be copied in later.
 */
#define INIT_INPUT_H \
    { \
        .prefix_1 = INIT_TO_BYTE_32(1), \
        .KEY = { { 0 } }, \
        .M = { { { 0 } }, { { 0 } } } \
        INIT_PADDING_SHA256(TO_BITS(INPUT_H_DATA_SIZE)) \
    }

/**
 * @brief
 * The optimized input for the KEY parameter to the XMSS H_msg(KEY,M) hash function.
 *
 * @details
 * KEY = r || Root || toByte(idx_sig,32).
 *
 * Example initialization:
 *
 * ```
 * Input_H_msg input = INIT_INPUT_H_MSG;
 *
 * XmssNativeValue256 *source_r;
 * XmssValue256 *source_root;
 * uint32_t source_idx_sig;
 * input.r = *source_r;
 * big_endian_to_native_256(&input.Root, source_root);
 * input.idx_sig = source_idx_sig;
 * ```
 */
typedef struct Input_H_msg {
    /** @brief Initialize to toByte(2). */
    const XmssNativeValue256 prefix_2;

    /**
     * @brief
     * The hash randomization value.
     *
     * @details
     * In practice, $r$ is always the output of another XMSS hash function.
     */
    XmssNativeValue256 r;

    /** @brief The public root key. */
    XmssNativeValue256 Root;
    /** @brief Initialize to { 0 }. */
    const uint32_t zero_[7];
    /** @brief The (obfuscated) signature index. */
    uint32_t idx_sig;
} Input_H_msg;

/**
 * @brief
 * The initializer for the Input_H_msg structure.
 *
 * @details
 * Note that the non-const fields r, Root, and idx_sig need to be copied in later.
 */
#define INIT_INPUT_H_MSG \
    { \
        .prefix_2 = INIT_TO_BYTE_32(2), \
        .r = { { 0 } }, \
        .Root = { { 0 } }, \
        .zero_ = { 0 }, \
        .idx_sig = 0 \
    }

/**
 * @brief
 * The optimized input to the XMSS PRF(KEY,M) hash function.
 *
 * @details
 * M = ADRS or 00...0|idx_sig.
 *
 * Example initialization:
 *
 * ```
 * Input_PRF input = INIT_INPUT_PRF;
 *
 * XmssNativeValue256 *source_key;
 * ADRS *source_adrs;
 * input.KEY = *source_key;
 * big_endian_to_native(input.M.ADRS, source_adrs, sizeof(ADRS));
 * ```
 */
typedef struct Input_PRF {
    /** @brief Initialize to toByte(3). */
    const XmssNativeValue256 prefix_3;
    /** @brief The first parameter to the XMSS PRF(KEY,M) hash function. */
    XmssNativeValue256 KEY;
    /** @brief The second parameter to the XMSS PRF(Key,M) hash function. */
    union {
        /** @brief M when using the PRF in WOTS+ or the XMSS hash tree. */
        ADRS ADRS;
        /** @brief M when generating the per-message randomness for H_msg. */
        IdxSigBlock idx_sig_block;
    } M;
#if XMSS_ENABLE_SHA256
    /**
     * @brief
     * Always initialize this padding with INIT_PADDING_SHA256(768), irrespective of the underlying algorithm used.
     */
    struct {
        /** @brief Initialize to 0x80000000. */
        const uint32_t start;
        /** @brief Initialize to { 0 }, size is set to align the struct with the block size of SHA-256. */
        const uint32_t zero[TO_WORDS(SHA256_BLOCK_SIZE - sizeof(ADRS)) - 2u];
        /** @brief Initialize to the number of bits before the padding. */
        const uint32_t length;
    } padding_sha256;
#endif
} Input_PRF;

/** @brief Size of Input_PRF, excluding SHA-256 padding. */
#define INPUT_PRF_DATA_SIZE (2u * sizeof(XmssNativeValue256) + sizeof(ADRS))

/**
 * @brief
 * The initializer for the Input_PRF structure.
 *
 * @details
 * Note that the non-const parameters KEY and ADRS need to be copied in later.
 */
#define INIT_INPUT_PRF \
    { \
        .prefix_3 = INIT_TO_BYTE_32(3), \
        .KEY = { { 0 } }, \
        .M = { { 0 } } \
        INIT_PADDING_SHA256(TO_BITS(INPUT_PRF_DATA_SIZE)) \
    }

/**
 * @brief
 * The optimized input to the XMSS PRFkeygen(KEY,M) hash function.
 *
 * @details
 * KEY = S_XMSS and M = SEED || ADRS.
 *
 * Example initialization:
 *
 * ```
 * Input_PRFkeygen input = INIT_INPUT_PRFKEYGEN;
 *
 * XmssValue256 *source_s_xmss;
 * XmssValue256 *source_seed;
 * ADRS *source_adrs;
 * big_endian_to_native_256(&input.S_XMSS, source_s_xmss);
 * big_endian_to_native_256(&input.SEED, source_seed);
 * input.ADRS = *source_adrs;
 * ```
 */
typedef struct Input_PRFkeygen {
    /** @brief Initialize to toByte(4). */
    const XmssNativeValue256 prefix_4;
    /** @brief The secret key generation seed. */
    XmssNativeValue256 S_XMSS;
    /** @brief The public seed. */
    XmssNativeValue256 SEED;
    /** @brief The address of the hash. */
    ADRS ADRS;
#if XMSS_ENABLE_SHA256
    /**
     * @brief
     * Always initialize this padding with INIT_PADDING_SHA256(1024), irrespective of the underlying algorithm used.
     */
    struct {
        /** @brief Initialize to 0x80000000. */
        const uint32_t start;
        /** @brief Initialize to { 0 }, size is set to align the struct with the block size of SHA-256. */
        const uint32_t zero[TO_WORDS(SHA256_BLOCK_SIZE) - 2u];
        /** @brief Initialize to the number of bits before the padding. */
        const uint32_t length;
    } padding_sha256;
#endif
} Input_PRFkeygen;

/** @brief Size of Input_PRFkeygen, excluding SHA-256 padding. */
#define INPUT_PRF_KEYGEN_DATA_SIZE (3u * sizeof(XmssNativeValue256) + sizeof(ADRS))

/**
 * @brief
 * The initializer for the Input_PRFkeygen structure.
 *
 * @details
 * Note that the non-const parameters S_XMSS, SEED, and ADRS need to be copied in later.
 */
#define INIT_INPUT_PRFKEYGEN \
    { \
        .prefix_4 = INIT_TO_BYTE_32(4), \
        .S_XMSS = { { 0 } }, \
        .SEED = { { 0 } }, \
        .ADRS = { 0 } \
        INIT_PADDING_SHA256(TO_BITS(INPUT_PRF_KEYGEN_DATA_SIZE)) \
    }

/**
 * @brief
 * The optimized input to the XMSS PRFindex(KEY,M) hash function.
 *
 * @details
 * KEY = S_INDEX and M = SEED || toByte(counter,32).
 *
 * Example initialization:
 *
 * ```
 * Input_PRFindex input = INIT_INPUT_PRFINDEX;
 *
 * XmssValue256 *source_s_index;
 * XmssValue256 *source_seed;
 * uint32_t source_drbg_counter;
 * big_endian_to_native_256(&input.S_INDEX, source_s_index);
 * big_endian_to_native_256(&input.SEED, source_seed);
 * input.drbg_counter = source_drbg_counter;
 * ```
 */
typedef struct Input_PRFindex {
    /** @brief Initialize to toByte(5). */
    const XmssNativeValue256 prefix_5;
    /** @brief The secret index permutation seed. */
    XmssNativeValue256 S_INDEX;
    /** @brief The public seed. */
    XmssNativeValue256 SEED;
    /** @brief Initialize to { 0 }, size is set to match the size of Input_PRF. */
    const uint32_t zero[7];
    /** @brief The counter for the DRBG. */
    uint32_t drbg_counter;
#if XMSS_ENABLE_SHA256
    /**
     * @brief
     * Always initialize this padding with INIT_PADDING_SHA256(1024), irrespective of the underlying algorithm used.
     */
    struct {
        /** @brief Initialize to 0x80000000. */
        const uint32_t start;
        /** @brief Initialize to { 0 }, size is set to align with the SHA-256 block size. */
        const uint32_t zero[TO_WORDS(SHA256_BLOCK_SIZE) - 2u];
        /** @brief Initialize to the number of bits before the padding. */
        const uint32_t length;
    } padding_sha256;
#endif
} Input_PRFindex;

/** @brief Size of Input_PRFindex, excluding SHA-256 padding. */
#define INPUT_PRF_INDEX_DATA_SIZE (3u * sizeof(XmssNativeValue256) + 8u * sizeof(uint32_t))

/**
 * @brief
 * The initializer for the Input_PRFindex structure.
 *
 * @details
 * Note that the non-const parameters S_INDEX, SEED, and drbg_counter need to be copied in later.
 */
#define INIT_INPUT_PRFINDEX \
    { \
        .prefix_5 = INIT_TO_BYTE_32(5), \
        .S_INDEX = { { 0 } }, \
        .SEED = { { 0 } }, \
        .drbg_counter = 0 \
        INIT_PADDING_SHA256(TO_BITS(INPUT_PRF_INDEX_DATA_SIZE)) \
    }

#if XMSS_ENABLE_SHA256
/** @brief Context when we calculate SHA256 hashes with streaming data. */
typedef struct XmssHMsgSha256Ctx {
    /** @brief Intermediate hash value. */
    XmssNativeValue256 intermediate_hash;
    /** @brief Partial block, for when the length of the input is not a multiple of the block size, stored in big-endian. */
    uint8_t partial_block[SHA256_BLOCK_SIZE];
    /** @brief Bytes in the partial block. */
    union {
        size_t value;
        uint64_t alignment;
    } bytes_in_partial_block;
    /** @brief Bytes that have been hashed, not counting bytes stored in partial_block. */
    uint64_t bytes_hashed;
    /** @brief padding to match the size of XmssHMsgShake256_256Ctx . */
    uint8_t _padding[200 + 8 - 32 - 64 - 8 - 8];
} XmssHMsgSha256Ctx;
#endif

#if XMSS_ENABLE_SHAKE256_256
/** @brief Context when we calculate SHAKE256_256 hashes with streaming data. */
typedef struct XmssHMsgShake256_256Ctx {
    /** @brief Keccak state array for calculating the SHAKE256_256 hash. */
    uint64_t shake256_256_state_array[KECCAK_STATE_ARRAY_SIZE / sizeof(uint64_t)];
    /** @brief Offset for the next absorb; always < 136, the block size of SHAKE256_256. */
    union {
        uint_fast8_t value;
        uint64_t alignment;
    } offset;
} XmssHMsgShake256_256Ctx;
#endif

#if XMSS_ENABLE_SHA256 && XMSS_ENABLE_SHAKE256_256
/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssHMsgSha256Ctx) == sizeof(XmssHMsgShake256_256Ctx),
    "XmssHMsgSha256Ctx and XmssHMsgShake256_256Ctx have different sizes.");
#endif

/** @brief Context for calculating H_msg hashes from streaming data. */
typedef union XmssHMsgCtx {
#if XMSS_ENABLE_SHA256
    /** @brief Context when we use SHA256. */
    XmssHMsgSha256Ctx sha256_ctx;
#endif
#if XMSS_ENABLE_SHAKE256_256
    /** @brief Context when we use SHAKE256_256. */
    XmssHMsgShake256_256Ctx shake256_256_ctx;
#endif
    /** @brief Context pointer for hash implementations with the generic interface. */
    void *generic_ctx;
} XmssHMsgCtx;

#if XMSS_ENABLE_HASH_ABSTRACTION

/**
 * @brief
 * Execute the XMSS F(KEY,M) hash function.
 *
 * @details
 * The input parameters are provided in a single structure for performance reasons.
 *
 * @param[out] native_digest   The output of the XMSS F(KEY,M) hash function in native form.
 * @param[in] input   The input parameters to the XMSS F(KEY,M) hash function as a single, optimized structure.
 */
typedef void (*prototype_F)(XmssNativeValue256 *native_digest, const Input_F *input);

/**
 * @brief
 * Execute the XMSS H(KEY,M) hash function.
 *
 * @details
 * The input parameters are provided in a single structure for performance reasons.
 *
 * @param[out] native_digest   The output of the XMSS H(KEY,M) hash function in native form.
 * @param[in] input   The input parameters to the XMSS H(KEY,M) hash function as a single, optimized structure.
 */
typedef void (*prototype_H)(XmssNativeValue256 *native_digest, const Input_H *input);

/**
 * @brief
 * Initialize the context for calculating the XMSS H_msg(KEY,M) hash function.
 *
 * @details
 * KEY = r || Root || toByte(idx_sig, 32).
 *
 * The KEY parameters are provided in a single structure for performance reasons.
 *
 * @param[out] ctx  Context holding the intermediate state of the hash calculation.
 * @param[in] input     Input to the XMSS H_msg() hash function, excluding the message.
 */
typedef void (*prototype_H_msg_init)(XmssHMsgCtx *ctx, const Input_H_msg *input);

/**
 * @brief
 * Update the calculation of the XMSS H_msg(KEY,M) hash function with the next part of M.
 *
 * @details
 * When fault injection tolerance is required, provide a non-NULL `part_verify` parameter. After this function
 * completes successfully, compare the value returned in `*part_verify` with the original message `part` pointer.
 *
 * @param[in,out]   ctx         Context holding the intermediate state of the hash calculation.
 * @param[in]       part        Next part of the message; may be NULL if and only if part_length is 0.
 * @param[in]       part_length Length of part in bytes.
 * @param[out]      part_verify (optional, may be NULL) Outputs a copy of `part` to verify the correct message was
 *                              processed. This can be used to mitigate fault injections.
 */
typedef void (*prototype_H_msg_update)(XmssHMsgCtx *ctx, const uint8_t *part, size_t part_length,
    const uint8_t *volatile *part_verify);

/**
 * @brief
 * Finalize the calculation of the XMSS H_msg(KEY,M) hash function and output the digest.
 *
 * @param[out] native_digest    The output of the XMSS H_msg(KEY,M) hash function in native form.
 * @param[in] ctx   Context holding the intermediate state of the hash calculation.
 */
typedef void (*prototype_H_msg_finalize)(XmssNativeValue256 *native_digest, XmssHMsgCtx *ctx);

/**
 * @brief
 * Execute the XMSS PRF(KEY,M) hash function.
 *
 * @details
 * M = ADRS.
 *
 * The input parameters are provided in a single structure for performance reasons.
 *
 * @param[out] native_digest   The output of the XMSS PRF(KEY,M) hash function in native form.
 * @param[in] input   The input parameters to the XMSS PRF(KEY,M) hash function as a single, optimized structure.
 */
typedef void (*prototype_PRF)(XmssNativeValue256 *native_digest, const Input_PRF *input);

#if XMSS_ENABLE_SIGNING

/**
 * @brief
 * Execute the XMSS PRFkeygen(KEY,M) hash function.
 *
 * @details
 * KEY = X_SEED and M = SEED || ADRS.
 *
 * The input parameters are provided in a single structure for performance reasons.
 *
 * @param[out] native_digest   The output of the XMSS PRFkeygen(KEY,M) hash function in native form.
 * @param[in] input   The input parameters to the XMSS PRFkeygen(KEY,M) hash function as a single, optimized structure.
 */
typedef void (*prototype_PRFkeygen)(XmssNativeValue256 *native_digest, const Input_PRFkeygen *input);

/**
 * @brief
 * Execute the index obfuscation hash function PRFindex(KEY,M).
 *
 * @details
 * KEY = S_INDEX and M = SEED || toByte(counter,32).
 *
 * PRFindex returns 256-bits of pseudo-random data. It is modeled after PRFkeygen, with a unique hash prefix,
 * toByte(5,32). Use different values for counter to get independent 256-bit random values.
 *
 * PRFindex(KEY,M) = HASH(toByte(5,32) || KEY || M)
 *
 * The input parameters are provided in a single structure for performance reasons.
 *
 * @param[out] native_digest   The output of the index obfuscation PRFindex(KEY,M) hash function in native form.
 * @param[in] input   The input parameters to the index obfuscation PRFindex(KEY,M) hash function as a single,
 *                    optimized structure.
 */
typedef void (*prototype_PRFindex)(XmssNativeValue256 *native_digest, const Input_PRFindex *input);

/**
 * @brief
 * Generate a digest of a message.
 *
 * @param[out] digest   The output digest.
 * @param[in] message   Input message; may be NULL if and only if message_length is 0.
 * @param[in] message_length   Input message length in bytes.
 */
typedef void (*prototype_digest)(XmssValue256 *digest, const uint8_t *message, size_t message_length);

/**
 * @brief
 * Generate a digest of an array of 32-bit native words.
 *
 * @param[out] native_digest   The output digest.
 * @param[in] words            Input data; may be NULL if and only if data_count is 0.
 * @param[in] word_count       The number of data words.
 */
typedef void (*prototype_native_digest)(XmssNativeValue256 *native_digest, const uint32_t *words, size_t word_count);

#endif /* XMSS_ENABLE_SIGNING */

/**
 * @brief
 * Abstraction helper containing all XMSS hash functions.
 *
 * @details
 * The context for a key should contain (possibly, a pointer to) a variable of this type if and only if
 * XMSS_ENABLE_HASH_ABSTRACTION is true.
 *
 * Example:
 * ```
 * struct {
 *      ...
 * #if XMSS_ENABLE_HASH_ABSTRACTION
 *      xmss_hashes *hashes_to_use;
 * #endif
 *      ...
 * } key_context;
 * ```
 */
typedef struct xmss_hashes {
    /** @brief The XMSS F() hash function. */
    prototype_F F;

    /** @brief The XMSS H() hash function. */
    prototype_H H;

    /** @brief The XMSS H_msg_init() function. */
    prototype_H_msg_init H_msg_init;

    /** @brief The XMSS H_msg_update() function. */
    prototype_H_msg_update H_msg_update;

    /** @brief The XMSS H_msg_finalize() function. */
    prototype_H_msg_finalize H_msg_finalize;

    /** @brief The XMSS PRF() hash function. */
    prototype_PRF PRF;

#if XMSS_ENABLE_SIGNING

    /** @brief The XMSS PRFkeygen() hash function. */
    prototype_PRFkeygen PRFkeygen;

    /** @brief The index obfuscation PRFindex() hash function. */
    prototype_PRFindex PRFindex;

    /** @brief The standardized, generic, byte-oriented digest function. */
    prototype_digest digest;

    /** @brief The internal native 32-bit word-oriented digest function. */
    prototype_native_digest native_digest;

#endif /* XMSS_ENABLE_SIGNING */
} xmss_hashes;

#endif /* XMSS_ENABLE_HASH_ABSTRACTION */

#endif /* !XMSS_XMSS_HASHES_BASE_H_INCLUDED */
