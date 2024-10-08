/*
 * SPDX-FileCopyrightText: 2022 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Thomas Schaap
 */

/**
 * @file
 * @brief
 * Private definitions of internal structures.
 *
 * @details
 * These are implementation details that should *not* be considered stable.
 */

#pragma once

#ifndef XMSS_PRIVATE_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_PRIVATE_H_INCLUDED

#include "config.h"

#include "compat.h"
#include "compat_stdatomic.h"
#include "opaque_structures.h"
#include "structures.h"
#include "types.h"
#include "xmss_hashes.h"


/**
 * @brief
 * The current version of the internal storage format for the private key stateless parts.
 *
 * @details
 * When a version of the XMSS library is released, this storage format version is definitive and that storage format
 * will never change without changing the version, as well.
 */
#define XMSS_VERSION_CURRENT_PRIVATE_KEY_STATELESS_STORAGE 1

/**
 * @brief
 * The current version of the internal storage format for the private key stateful parts.
 *
 * @details
 * When a version of the XMSS library is released, this storage format version is definitive and that storage format
 * will never change without changing the version, as well.
 */
#define XMSS_VERSION_CURRENT_PRIVATE_KEY_STATEFUL_STORAGE 1

/**
 * @brief
 * The current version of the internal storage format for the public key.
 *
 * @details
 * When a version of the XMSS library is released, this storage format version is definitive and that storage format
 * will never change without changing the version, as well.
 */
#define XMSS_VERSION_CURRENT_PUBLIC_KEY_STORAGE 1

/** The state of a context. */
typedef enum XmssInitializationState
{
    /** The context has not yet been initialized. */
    XMSS_INITIALIZATION_UNINITIALIZED = XMSS_DISTANT_VALUE_0,
    /** The context has been initialized. */
    XMSS_INITIALIZATION_INITIALIZED = XMSS_DISTANT_VALUE_1,
    /** The key context has been initialized and contains both a private and a public key. */
    XMSS_INITIALIZATION_WITH_PUBLIC_KEY = XMSS_DISTANT_VALUE_2
} XmssInitializationState;

/** The state of a single key generation partition's work. */
typedef enum XmssGenerationState
{
    /** The work partition has been prepared, but not yet started. */
    XMSS_GENERATION_STATE_PREPARED = XMSS_DISTANT_VALUE_0,
    /** The work partition's calculations have been started, but are not yet complete. */
    XMSS_GENERATION_STATE_GENERATING = XMSS_DISTANT_VALUE_1,
    /** The work partition's calculations have all been done and the results are stored. */
    XMSS_GENERATION_STATE_FINISHED = XMSS_DISTANT_VALUE_2
} XmssGenerationState;

struct XmssSigningContext {
    /**
     * @brief
     * Whether the signing context has been initialized. This field takes values from XmssInitializationState.
     *
     * @details
     * None of the other members are valid if this is not XMSS_INITIALIZATION_INITIALIZED.
     * Note that due to the constraints on xmss_free_signing_context it is required to either fully initialize an
     * allocated XmssSigningContext, or to correctly deallocate it again.
     */
    uint32_t initialized;
    /**
     * @brief
     * The XMSS parameter set that defines the keys that can be generated or loaded by this library's instantiation.
     * This field takes values from XmssParameterSetOID.
     */
    uint32_t parameter_set;
    /** @brief Redundant copy of parameter_set, for bit error resilience. */
    uint32_t redundant_parameter_set;
    /** @brief Explicit padding. */
    uint32_t pad_;
#if XMSS_ENABLE_HASH_ABSTRACTION
    /**
     * @brief
     * The hash functions used.
     *
     * This is simply used as a cached value for xmss_get_hash_functions(parameter_set).
     * Redundancy is not needed; if this pointer gets corrupted, then either the integrity checks will fail
     * or (more likely) the software will simply crash.
     */
    const xmss_hashes *hash_functions;
#else
    void *pad_hash_functions;
#endif
    /**
     * The realloc() function to use.
     * @see xmss_context_initialize for more information about memory management.
     */
    XmssReallocFunction realloc;
    /**
     * The free() function to use.
     * @see xmss_context_initialize for more information about memory management.
     */
    XmssFreeFunction free;
    /**
     * The function to safely zeroize sensitive data.
     * @see XmssZeroizeFunction for more information.
     */
    XmssZeroizeFunction zeroize;
};

/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssSigningContext) == XMSS_SIGNING_CONTEXT_SIZE, "XMSS_SIGNING_CONTEXT_SIZE mismatch.");

struct XmssInternalCache {
    /**
     * @brief
     * The type of cache. This field takes values from XmssCacheType.
     *
     * @see xmss_generate_public_key() for more information on the different cache types.
     */
    uint32_t cache_type;
    /**
     * @brief
     * The level of the cache.
     *
     * @details
     * Values outside [0, h] are invalid.
     * A lower level will result in a larger cache.
     *
     * Ignored for cache type XMSS_CACHE_NONE.
     *
     * @see xmss_generate_public_key() for more information on the cache level for different cache types.
     */
    uint32_t cache_level;
    /**
     * @brief
     * The cache entries, from lowest address to highest address in the tree, or from 'left' to 'right'.
     *
     * @details
     * For single level caching, this must be sized to 2^(XMSS_TREE_DEPTH(param_set)-cache_level) entries.
     *
     * For top caching, this must be sized 2^(XMSS_TREE_DEPTH(param_set)-cache_level+1)-1 entries.
     *
     * For no caching or cache_level == XMSS_TREE_DEPTH(param_set), this must be empty.
     *
     * The XMSS_CACHE_ENTRY_COUNT macro can be used to directly determine the correct number of entries. The
     * XMSS_CACHE_ENTRY_OFFSET macro can be used to find a specific entry's offset in this array.
     */
    XmssNativeValue256 cache[];
};

/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssInternalCache) == XMSS_INTERNAL_CACHE_SIZE(XMSS_CACHE_NONE,
    XMSS_TREE_DEPTH(XMSS_PARAM_SHA2_10_256), XMSS_PARAM_SHA2_10_256), "XMSS_INTERNAL_CACHE_SIZE mismatch.");
/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssInternalCache) == XMSS_INTERNAL_CACHE_SIZE(XMSS_CACHE_NONE,
    0,  XMSS_PARAM_SHA2_10_256), "XMSS_INTERNAL_CACHE_SIZE mismatch.");
/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssInternalCache) == XMSS_INTERNAL_CACHE_SIZE(XMSS_CACHE_SINGLE_LEVEL,
    XMSS_TREE_DEPTH(XMSS_PARAM_SHA2_10_256), XMSS_PARAM_SHA2_10_256), "XMSS_INTERNAL_CACHE_SIZE mismatch.");
/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssInternalCache) + sizeof(XmssValue256) * 4
    == XMSS_INTERNAL_CACHE_SIZE(XMSS_CACHE_SINGLE_LEVEL,
    XMSS_TREE_DEPTH(XMSS_PARAM_SHA2_10_256) - 2, XMSS_PARAM_SHA2_10_256), "XMSS_INTERNAL_CACHE_SIZE mismatch.");
/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssInternalCache) + sizeof(XmssValue256) * 3 == XMSS_INTERNAL_CACHE_SIZE(XMSS_CACHE_TOP,
    XMSS_TREE_DEPTH(XMSS_PARAM_SHA2_10_256) - 1, XMSS_PARAM_SHA2_10_256), "XMSS_INTERNAL_CACHE_SIZE mismatch.");
/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssInternalCache) + sizeof(XmssValue256) * 7 ==
        XMSS_INTERNAL_CACHE_SIZE(XMSS_CACHE_TOP, XMSS_TREE_DEPTH(XMSS_PARAM_SHA2_10_256) - 2, XMSS_PARAM_SHA2_10_256),
    "XMSS_INTERNAL_CACHE_SIZE mismatch.");

/**
 * @brief
 * The offset of a specific cache entry in the array of cached entries.
 *
 * @note The arguments to XMSS_CACHE_ENTRY_OFFSET will be evaluated multiple times.
 *
 * @param[in] cache_type    The cache type that is used.
 * @param[in] cache_level   The cache level that is used.
 * @param[in] param_set     The parameter set of the key for which the cache is used.
 * @param[in] entry_level   The level of the entry being looked up. For single level caching entry_level==cache_level,
 *                          since only one level is cached. For top caching cache_level <= entry_level <=
 *                          XMSS_TREE_DEPTH(param_set).
 * @param[in] entry_index   The index of the entry within its level, counting from left to right in the tree (i.e. by
 *                          increasing address). 0 <= entry_index < 2 ** (XMSS_TREE_DEPTH(param_set) - entry_level).
 */
#define XMSS_CACHE_ENTRY_OFFSET(cache_type, cache_level, param_set, entry_level, entry_index) \
    ((cache_type) == XMSS_CACHE_TOP ? \
        ((1u << ((XMSS_TREE_DEPTH(param_set) - (cache_level)) + 1u)) - \
            (1u << ((XMSS_TREE_DEPTH(param_set) - (entry_level)) + 1u)) + (entry_index)) : \
        ((cache_type) == XMSS_CACHE_SINGLE_LEVEL ? (entry_index) : \
            0u \
        ) \
    )

/**
 * @brief
 * A private key's stateless parts, excluding the scheme identifier.
 *
 * @details
 * Partial structure. Do not use this without any additional protections!
 */
typedef struct XmssPrivateKeyStatelessContents {
    /*
     * Note that the scheme identifier is not included in this convenience structure. It is added manually to aid in
     * 64-bits padding of the containing structures.
     */
    /** @brief The PRF_SEED for this private key. */
    XmssNativeValue256 prf_seed;
    /** @brief The seed for private key generation. NIST terminology: SK_SEED */
    XmssNativeValue256 private_key_seed;
    /**
     * @brief
     * The public SEED used with this private key.
     *
     * @details
     * Contrary to the other members SEED is actually public information, but it is required to be able to do anything
     * with the private key.
     */
    XmssNativeValue256 seed;

    /** @brief The XmssIndexObfuscationSetting to use with this private key. */
    uint32_t index_obfuscation_setting;
    /** @brief Explicit padding. */
    uint32_t pad_;
    /** @brief The seed for the index obfuscation used with this private key. */
    XmssNativeValue256 index_obfuscation_random;
    /**
     * @brief
     * The native integrity digest calculated over the entire obfuscation array.
     *
     * @details
     * When the index obfuscation is calculated, the results are stored in a consecutive array of uint32_t values, the
     * index into the array being the un-obfuscated index. The values are stored in native-endian.
     * The entire array, 4*(2**h) bytes where h is the tree depth for the private key, is used as a single input
     * message to the unseeded native-endian digest function corresponding to the parameter set for the private
     * key.
     */
    XmssNativeValue256 obfuscation_integrity;
} XmssPrivateKeyStatelessContents;

/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssPrivateKeyStatelessContents) == XMSS_PRIVATE_KEY_STATELESS_PART_SIZE,
    "XMSS_PRIVATE_KEY_STATELESS_PART_SIZE mismatch");

/**
 * @brief
 * An explicitly big-endian variant of XmssPrivateKeyStatefulContents.
 *
 * @see XmssPrivateKeyStatefulContents for the specification of the contents.
 */
typedef XmssPrivateKeyStatelessContents XmssPrivateKeyStatelessContentsBigEndian;

/**
 * @brief
 * A private key partition's stateful part.
 *
 * @details
 * Partial structure. Do not use without any additional protections!
 */
typedef struct XmssPrivateKeyStatefulContents {
    /** @brief The lowest non-obfuscated index in this private key partition that may be used for signing. */
    uint32_t partition_start;
    /**
     * @brief
     * The highest non-obfuscated index in this private key partition that may be used for signing.
     *
     * @details
     * partition_end is inclusive: non-obfuscated index partition_end may be used, i.e. the private key partition in
     * this context allows for 1+partition_end-partition_start signatures to be generated.
     */
    uint32_t partition_end;
} XmssPrivateKeyStatefulContents;

/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssPrivateKeyStatefulContents) == XMSS_PRIVATE_KEY_STATEFUL_PART_SIZE,
    "XMSS_PRIVATE_KEY_STATEFUL_PART_SIZE mismatch");

/**
 * @brief
 * A big-endian variant of XmssPrivateKeyStatefulContents.
 *
 * @see XmssPrivateKeyStatelessContents for the specification of the contents.
 */
typedef XmssPrivateKeyStatefulContents XmssPrivateKeyStatefulContentsBigEndian;

struct XmssKeyContext {
    /**
     * @brief
     * How far the key context has been initialized. This field takes values from XmssInitializationState.
     *
     * @details
     * None of the other members are valid if this is not XMSS_INITIALIZATION_INITIALIZED or
     * XMSS_INITIALIZATION_WITH_PUBLIC_KEY.
     */
    uint32_t initialized;
    /** @brief Explicit padding. */
    uint32_t pad_;
    /** @brief The signing library's instantiation. */
    XmssSigningContext context;
    /**
     * @brief
     * The stateless part of the loaded private key.
     *
     * @details
     * Note that the data must be in native-endian.
     */
    XmssPrivateKeyStatelessContents private_stateless;
    /**
     * @brief
     * The stateful part of the loaded private key partition.
     *
     * @details
     * Note that the data must be in native-endian.
     */
    XmssPrivateKeyStatefulContents private_stateful;
    /** @brief Redundant copy of private_stateful for bit error resilience. */
    XmssPrivateKeyStatefulContents redundant_private_stateful;
    /**
     * @brief
     * The digest of the XmssPrivateKeyStatelessBlob associated with this key context.
     *
     * @details
     * This is a digest of the entire 'data' part of the blob, except the integrity field itself.
     */
    XmssValue256 private_key_digest;
    /** @brief Redundant copy of private_key_digest for bit error resilience. */
    XmssValue256 redundant_private_key_digest;
    /**
     * @brief
     * The public key root.
     *
     * @details
     * This is not valid if initialized is not XMSS_INITIALIZATION_WITH_PUBLIC_KEY.
     */
    XmssNativeValue256 public_key_root;
    /**
     * @brief
     * The loaded cache.
     *
     * @details
     * This is not valid if initialized is not XMSS_INITIALIZATION_WITH_PUBLIC_KEY. May be NULL.
     */
    XmssInternalCache *cache;
    /**
     * @brief
     * The first signature that has been reserved but not used.
     *
     * @details
     * If reserved_signatures_start == private_stateful.partition_start, then no more signatures are available until
     * request_future_signatures() is called.
     */
    uint32_t reserved_signatures_start;
    /** @brief Redundant copy of reserved_signatures_start for bit error resilience. */
    uint32_t redundant_reserved_signatures_start;
    /**
     * @brief
     * The permutation used for index obfuscation.
     *
     * @details
     * Contains 2^tree_depth elements if private_stateless.index_obfuscation_setting is not XMSS_INDEX_OBFUSCATION_OFF.
     */
    uint32_t obfuscation[];
};

/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssKeyContext) == XMSS_KEY_CONTEXT_SIZE(XMSS_PARAM_SHA2_10_256, XMSS_INDEX_OBFUSCATION_OFF),
    "XMSS_KEY_CONTEXT_SIZE mismatch");
/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssKeyContext) + (1 << 10) * sizeof(uint32_t) ==
    XMSS_KEY_CONTEXT_SIZE(XMSS_PARAM_SHA2_10_256, XMSS_INDEX_OBFUSCATION_ON),
    "XMSS_KEY_CONTEXT_SIZE mismatch");

struct XmssKeyGenerationContext {
    /**
     * @brief
     * Whether or not the XmssKeyGenerationContext has been initialized. This field takes values from
     * XmssInitializationState.
     *
     * @details
     * None of the other members are valid if this is not XMSS_INITIALIZATION_INITIALIZED.
     */
    uint32_t initialized;
    /** @brief The number of partitions into which the public key calculations were divided. */
    uint32_t generation_partitions;
    /** @brief A pointer to the XmssKeyContext for which this context was created. */
    const XmssKeyContext *context;
    /**
     * @brief
     * The cache that is being constructed. May be NULL is no cache is being constructed.
     *
     * @details
     * Each calculation partition will write the part of the cache under construction for which it encounters the
     * values during its calculations.
     * Note that the cache under construction will remain empty if its cache level is lower than
     * log(generation_partitions), in which case it has to be filled in by xmss_finish_calculate_public_key.
     */
    XmssInternalCache *cache_under_construction;
    /**
     * @brief
     * Temporary cache to hold the partition results, must be non-NULL if .initialized is set to
     * XMSS_INITIALIZATION_INITIALIZED.
    */
    XmssInternalCache *partition_cache;
    /**
     * @brief
     * The gathered results of all the calculation partitions. Contains generation_partitions elements.
     *
     * @details
     * Each calculation partition is calculated in a single call to xmss_calculate_public_key_part, the partition_index
     * is the index into this array.
     */
    struct {
        /** @brief The XmssGenerationState of this calculation partition. */
        ATOMIC uint32_t state;
    } partition_states[];
};

/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssKeyGenerationContext) == XMSS_KEY_GENERATION_CONTEXT_SIZE(0),
    "XMSS_KEY_GENERATION_CONTEXT_SIZE mismatch");
/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssKeyGenerationContext) + (sizeof(uint32_t))
    == XMSS_KEY_GENERATION_CONTEXT_SIZE(1), "XMSS_KEY_GENERATION_CONTEXT_SIZE mismatch");

/**
 * @brief
 * The stateless part of a private key, in a format that can be stored in non-volatile memory.
 *
 * @details
 * Note that all the contents must be written in big-endian.
 *
 * The offsets and data types of private_key_stateless_version, scheme_identifier and integrity must not change between
 * versions. Keeping them the same allows detecting bit errors in the stored version or parameter set using the
 * integrity digest, without needing to rely on the (unchecked) version to identify the location of the other two
 * members.
 *
 * The public API that allows storing this blob without knowing its contents is XmssPrivateKeyStatelessBlob. The
 * data_size member of XmssPrivateKeyStatelessBlob must be set to the exact size of XmssPrivateKeyStateless. If that is
 * the case, the data member of an XmssPrivateKeyStatelessBlob may freely be cast to an XmssPrivateKeyStateless.
 */
typedef struct XmssPrivateKeyStateless {
    /**
     * @brief
     * Integrity digest over the entire structure's contents, with the exception of this member.
     */
    XmssValue256 integrity;
    /**
     * @brief
     * The storage format version of this stateless private key part.
     * @see XMSS_VERSION_CURRENT_PRIVATE_KEY_STATELESS_STORAGE
     */
    uint32_t private_key_stateless_version;
    /** @brief The XmssParameterSetOID with which the private key was generated. */
    uint32_t scheme_identifier;
    /** @brief Redundant copy of private_key_stateless_version. */
    uint32_t redundant_version;
    /** @brief Redundant copy of scheme_identifier. */
    uint32_t redundant_scheme_identifier;
    /** @brief The contents of the private key's stateless parts. */
    XmssPrivateKeyStatelessContentsBigEndian contents;
} XmssPrivateKeyStateless;

/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssPrivateKeyStatelessBlob) + sizeof(XmssPrivateKeyStateless) ==
    XMSS_PRIVATE_KEY_STATELESS_BLOB_SIZE, "XMSS_PRIVATE_KEY_STATELESS_BLOB_SIZE mismatch");
/** @private */
XMSS_STATIC_ASSERT(offsetof(XmssPrivateKeyStateless, integrity) == 0,
    "XmssPrivateKeyStateless integrity digest must be the first field in the blob data");
/** @private */
XMSS_STATIC_ASSERT(offsetof(XmssPrivateKeyStateless, private_key_stateless_version) == sizeof(XmssValue256),
    "XmssPrivateKeyStateless version must be the second field in the blob");
/** @private */
XMSS_STATIC_ASSERT(offsetof(XmssPrivateKeyStateless, scheme_identifier) ==
    offsetof(XmssPrivateKeyStateless, private_key_stateless_version) + sizeof(uint32_t),
    "XmssPrivateKeyStateless scheme identifier must be the third field in the blob");

/**
 * @brief
 * The stateful part of a private key, in a format that can be stored in non-volatile memory.
 *
 * @details
 * Note that all the contents must be written in big-endian.
 *
 * The offsets and data types of private_key_stateful_version, scheme_identifier and integrity must not change between
 * versions. Keeping them the same allows detecting bit errors in the stored version or parameter set using the
 * integrity digest, without needing to rely on the (unchecked) version to identify the location of the other two
 * members.
 *
 * The public API that allows storing this blob without knowing its contents is XmssPrivateKeyStatefulBlob. The
 * data_size member of XmssPrivateKeyStatefulBlob must be set to the exact size of XmssPrivateKeyStateful. If that is
 * the case, the data member of an XmssPrivateKeyStatefulBlob may freely be cast to an XmssPrivateKeyStateful.
 */
typedef struct XmssPrivateKeyStateful {
    /**
     * @brief
     * Integrity digest over the entire structure's contents, except for this member.
     * This includes everything but the data_size member.
     */
    XmssValue256 integrity;
    /**
     * @brief
     * The storage format version of this stateful private key part.
     * @see XMSS_VERSION_CURRENT_PRIVATE_KEY_STATEFUL_STORAGE
     */
    uint32_t private_key_stateful_version;
    /**
     * @brief
     * The XmssParameterSetOID with which this private key was generated.
     *
     * @details
     * Although this is part of the stateless private key part, it is needed to identify the correct hashing algorithm
     * for calculating the integrity digests.
     */
    uint32_t scheme_identifier;
    /** @brief Redundant copy of private_key_stateful_version for bit error resilience. */
    uint32_t redundant_version;
    /** @brief Redundant copy of scheme_identifier for bit error resilience. */
    uint32_t redundant_scheme_identifier;
    /**
     * @brief
     * A digest over the XmssPrivateKeyStatelessBlob that corresponds to this private key, except for its data_size and
     * digest members.
     *
     * @details
     * This digest is used to verify that the stateful private key parts are only loaded with the correct stateless
     * private key parts.
     */
    XmssValue256 digest_of_private_key_static_blob;
    /** @brief The contents of the private key's stateful parts. */
    XmssPrivateKeyStatefulContentsBigEndian contents;
    /** @brief Redundant copy of contents for bit error resilience. */
    XmssPrivateKeyStatefulContentsBigEndian redundant_contents;
} XmssPrivateKeyStateful;

/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssPrivateKeyStatefulBlob) + sizeof(XmssPrivateKeyStateful) ==
    XMSS_PRIVATE_KEY_STATEFUL_BLOB_SIZE, "XMSS_PRIVATE_KEY_STATEFUL_BLOB_SIZE mismatch");
/** @private */
XMSS_STATIC_ASSERT(offsetof(XmssPrivateKeyStateful, integrity) == 0,
    "XmssPrivateKeyStateful integrity must be the first field in the blob");
/** @private */
XMSS_STATIC_ASSERT(offsetof(XmssPrivateKeyStateful, private_key_stateful_version) ==
    offsetof(XmssPrivateKeyStateful, integrity) + sizeof(XmssValue256),
    "XmssPrivateKeyStateful private_key_stateful_version must be the second field in the blob");
/** @private */
XMSS_STATIC_ASSERT(offsetof(XmssPrivateKeyStateful, scheme_identifier) ==
    offsetof(XmssPrivateKeyStateful, private_key_stateful_version) + sizeof(uint32_t),
    "XmssPrivateKeyStateful scheme identifier must be the third field in the blob");

/**
 * @brief
 * The public key and cache, in a format that can be stored in non-volatile memory.
 *
 * @details
 * Note that all the contents must be written in big-endian.
 *
 * The offsets and data types of public_key_version, scheme_identifier and integrity must not change between versions.
 * Keeping them the same allows detecting bit errors in the stored version or parameter set using the integrity digest,
 * without needing to rely on the (unchecked) version to identify the location of the other two members.
 *
 * The public API that allows storing this blob without knowing its contents is XmssPrivateKeyStatefulBlob. The
 * data_size member of XmssPrivateKeyStatefulBlob must be set to the exact size of XmssPrivateKeyStateful. If that is
 * the case, the data member of an XmssPrivateKeyStatefulBlob may freely be case to an XmssPrivateKeyStateful.
 * The public API that allows storing this blob without knowing its contents is XmssPublicKeyInternalBlob. The
 * data_size member of XmssPublicKeyInternalBlob must be set to the exact size of XmssPublicKeyInternal. If that is the
 * case, the data member of an XmssPublicKeyInternalBlob may freely be cast to an XmssPublicKeyInternal.
 */
typedef struct XmssPublicKeyInternal {
    /**
     * @brief
     * Integrity digest over the entire structure's contents, with the exception of this member.
     */
    XmssValue256 integrity;
    /**
     * @brief
     * The storage format version of this public key.
     * @see XMSS_VERSION_CURRENT_PUBLIC_KEY_STORAGE
     */
    uint32_t public_key_version;
    /**
     * @brief
     * The XmssParameterSetOID with which this public key was generated.
     *
     * @details
     * Although this is part of the stateless private key part, it is needed to identify the correct hashing algorithm
     * for calculating the integrity digests.
     */
    uint32_t scheme_identifier;
    /** @brief Redundant copy of public_key_version for bit error resilience. */
    uint32_t redundant_version;
    /** @brief Redundant copy of scheme_identifier for bit error resilience. */
    uint32_t redundant_scheme_identifier;
    /**
     * @brief
     * A digest over the XmssPrivateKeyStateless that corresponds to this public key, except for its data_size and
     * integrity member.
     *
     * @details
     * This digest is used to verify that the public key is only loaded with the correct private key.
     */
    XmssValue256 digest_of_private_key_static_blob;
    /** @brief The public key root. */
    XmssValue256 root;
    /** @brief The type of caching stored within this public key. This must be a valid value of type XmssCacheType. */
    uint32_t cache_type;
    /**
     * @brief
     * The level of the cache stored with this public key.
     *
     * @details
     * Values outside outside [0, h] are invalid.
     * @see XmssInternalCache's structure for more information about the cache type and level.
     */
    uint32_t cache_level;
    /**
     * @brief The cache entries.
     * @see XmssInternalCache's structure for more information about the size of this array, as a function of the cache
     * type and cache level.
     */
    XmssValue256 cache[];
} XmssPublicKeyInternal;

/**
 * @brief
 * Size of XmssPublicKeyInternal, including cache.
 *
 * @note The arguments of XMSS_PUBLIC_KEY_INTERNAL_SIZE will be evaluated multiple times.
 *
 * @param[in] cache_type    The cache type that is used.
 * @param[in] cache_level   The cache level that is to be held.
 * @param[in] param_set     The parameter set of the key for which the cache will be used.
 * @see xmss_generate_public_key for more information about the cache type and level.
 */
#define XMSS_PUBLIC_KEY_INTERNAL_SIZE(cache_type, cache_level, param_set) \
        (sizeof(XmssPublicKeyInternal) + sizeof(XmssValue256) \
        * XMSS_CACHE_ENTRY_COUNT(cache_type, cache_level, param_set))

/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssPublicKeyInternalBlob) + sizeof(XmssPublicKeyInternal) ==
        XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE(XMSS_CACHE_NONE, XMSS_TREE_DEPTH(XMSS_PARAM_SHA2_10_256) - 1,
        XMSS_PARAM_SHA2_10_256), "XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE mismatch");
/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssPublicKeyInternalBlob) + sizeof(XmssPublicKeyInternal)  ==
    XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE(XMSS_CACHE_SINGLE_LEVEL,
        XMSS_TREE_DEPTH(XMSS_PARAM_SHA2_10_256), XMSS_PARAM_SHA2_10_256),
        "XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE mismatch");
/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssPublicKeyInternal) + sizeof(XmssPublicKeyInternalBlob) + sizeof(XmssValue256) * 3 ==
    XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE(XMSS_CACHE_TOP,
        XMSS_TREE_DEPTH(XMSS_PARAM_SHA2_10_256) - 1, XMSS_PARAM_SHA2_10_256),
        "XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE mismatch");
/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssPublicKeyInternalBlob) + sizeof(XmssPublicKeyInternal) + (1 << 2) * sizeof(XmssValue256)
        == XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE(XMSS_CACHE_SINGLE_LEVEL, XMSS_TREE_DEPTH(XMSS_PARAM_SHA2_10_256) - 2,
        XMSS_PARAM_SHA2_10_256), "XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE mismatch");
/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssPublicKeyInternalBlob) + sizeof(XmssPublicKeyInternal) + ((1 << 4) - 1)
        * sizeof(XmssValue256) ==
        XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE(XMSS_CACHE_TOP, XMSS_TREE_DEPTH(XMSS_PARAM_SHA2_10_256) - 3,
        XMSS_PARAM_SHA2_10_256), "XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE mismatch");
/** @private */
XMSS_STATIC_ASSERT(offsetof(XmssPublicKeyInternal, integrity) == 0,
    "XmssPublicKeyInternal integrity digest must be the first field in the blob");
/** @private */
XMSS_STATIC_ASSERT(offsetof(XmssPublicKeyInternal, public_key_version) == sizeof(XmssValue256),
    "XmssPublicKeyInternal version must be the second field in the blob");
/** @private */
XMSS_STATIC_ASSERT(offsetof(XmssPublicKeyInternal, scheme_identifier) ==
    offsetof(XmssPublicKeyInternal, public_key_version) + sizeof(uint32_t),
    "XmssPublicKeyInternal scheme identifier must be the third field in the blob");

#endif /* !XMSS_PRIVATE_H_INCLUDED */
