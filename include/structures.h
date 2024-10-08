/*
 * SPDX-FileCopyrightText: 2022 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Thomas Schaap
 */

/**
 * @file
 * @brief XMSS library specific structured types.
 *
 * @details
 * There is no need to include this header explicitly. Instead, include either verification.h or signing.h.
 */

#pragma once

#ifndef XMSS_STRUCTURES_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_STRUCTURES_H_INCLUDED

#include "compat.h"
#include "opaque_structures.h"
#include "types.h"

/**
 * @brief
 * A stored stateless private key part.
 *
 * @details
 * Use this structure's contents to store or read a stateless private key part.
 *
 * After writing a stateless private key part, it is strongly recommended to read it back and validate the correctness
 * of the read back version using xmss_verify_private_key_stateless().
 *
 * When creating an XmssPrivateKeyStatelessBlob, the #XMSS_PRIVATE_KEY_STATELESS_BLOB_SIZE macro can be used to allocate
 * the correct `data_size` for the structure and its opaque contents.
 */
typedef struct XmssPrivateKeyStatelessBlob {
    /** @brief The size in bytes of the `data` array. */
    size_t data_size;
    /** @brief The data to be stored. */
    uint8_t data[];
} XmssPrivateKeyStatelessBlob;

/**
 * @brief
 * The size in bytes of an XmssPrivateKeyStatelessBlob.
 */
#define XMSS_PRIVATE_KEY_STATELESS_BLOB_SIZE \
    (sizeof(XmssPrivateKeyStatelessBlob) + sizeof(XmssValue256) + 4 + 4 + 4 + 4 + XMSS_PRIVATE_KEY_STATELESS_PART_SIZE)

/**
 * @brief
 * A stored stateful private key part.
 *
 * @details
 * Use this structure's contents to store or read a stateful private key part.
 *
 * After writing a stateful private key part, it is strongly recommended to read it back and validate the correctness of
 * the read back version using xmss_verify_private_key_stateful().
 *
 * When creating an XmssPrivateKeyStatefulBlob, the #XMSS_PRIVATE_KEY_STATEFUL_BLOB_SIZE macro can be used to allocate
 * the correct size for the structure and its opaque contents.
 */
typedef struct XmssPrivateKeyStatefulBlob {
    /** @brief The size in bytes of the `data` array. */
    size_t data_size;
    /** @brief The data to be stored. */
    uint8_t data[];
} XmssPrivateKeyStatefulBlob;

/**
 * @brief
 * The size in bytes of an XmssPrivateKeyStatefulBlob.
 */
#define XMSS_PRIVATE_KEY_STATEFUL_BLOB_SIZE \
    (sizeof(XmssPrivateKeyStatefulBlob) + sizeof(XmssValue256) + 4 + 4 + 4 + 4 + sizeof(XmssValue256) + \
        2 * XMSS_PRIVATE_KEY_STATEFUL_PART_SIZE)

/**
 * @brief
 * A stored public key for the signing library.
 *
 * @details
 * Use this structure's contents to store or read a public key for the signing library.
 *
 * After writing a public key, it is strongly recommended to read it back and validate the correctness of the read back
 * version using xmss_verify_public_key().
 *
 * When creating an XmssPublicKeyInternalBlob, the #XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE() macro can be used to allocate
 * the correct size for the structure and its opaque contents.
 */
typedef struct XmssPublicKeyInternalBlob {
    /** @brief The size in bytes of the `data` array. */
    size_t data_size;
    /** @brief The data to be stored. */
    uint8_t data[];
} XmssPublicKeyInternalBlob;

/**
 * @brief
 * The size in bytes of an XmssPublicKeyInternalBlob.
 *
 * @note The arguments to #XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE() will be evaluated multiple times.
 *
 * @param[in] cache_type    The cache type that is used.
 * @param[in] cache_level   The cache level that is to be held.
 * @param[in] param_set     The parameter set for the public key.
 * @see xmss_generate_public_key() for more information about the cache type and level.
 */
#define XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE(cache_type, cache_level, param_set) \
    (sizeof(XmssPublicKeyInternalBlob) + sizeof(XmssValue256) + 4u + 4u + sizeof(XmssValue256) + sizeof(XmssValue256) + \
     4u + 4u + 4u + 4u + sizeof(XmssValue256) * XMSS_CACHE_ENTRY_COUNT(cache_type, cache_level, param_set))


/**
 * @brief
 * Exportable format for a public key.
 *
 * @details
 * This is a public key in the format described by RFC 8391, Section 4.1.7.
 * Note that for all parameter sets supported by this library the XMSS security parameter $n = 32$.
 * Therefore, this structure has a fixed size; it will not fit public keys for other values of $n$.
 */
typedef struct XmssPublicKey {
    /**
     * @brief
     * The #XmssParameterSetOID with which this public key was generated.
     *
     * @details
     * `scheme_identifier` must be written in big-endian notation.
     */
    uint32_t scheme_identifier;
    /** @brief The public key root. */
    XmssValue256 root;
    /** @brief The public SEED. */
    XmssValue256 seed;
} XmssPublicKey;

/**
 * @brief
 * The size of the XmssPublicKey.
 *
 * @details
 * Included for API consistency.
 */
#define XMSS_PUBLIC_KEY_SIZE \
    (sizeof(XmssPublicKey))

/**
 * @brief
 * Exportable format for a signature.
 *
 * @details
 * This is a signature in the format described by RFC 8391, Section 4.1.8.
 *
 * For use with the XMSS library APIs, use XmssSignatureBlob and the #XMSS_SIGNATURE_BLOB_SIZE() macro.
 */
typedef struct XmssSignature {
    /**
     * @brief
     * The leaf index of the key that was used for generating the signature. If index obfuscation is used, then
     * this is the obfuscated index.
     *
     * @details
     * `leaf_index` must be written in big-endian notation.
     */
    uint32_t leaf_index;
    /** @brief The randomized hashing string $r$. */
    XmssValue256 random_bytes;
    /** @brief The WOTS+ signature. */
    XmssValue256 wots_signature[67];
    /**
     * @brief
     * The authentication path.
     *
     * @details
     * `authentication_path` contains one node for every level in the tree, so `tree_depth` nodes in total.
     */
    XmssValue256 authentication_path[];
} XmssSignature;

/**
 * @brief
 * Structure that embeds the exportable format for a signature, along with the signature's data size.
 *
 * @details
 * This is a signature in the format described by RFC 8391, Section 4.1.8.
 *
 * When creating an XmssSignatureBlob, the #XMSS_SIGNATURE_BLOB_SIZE() macro can be used to allocate the correct
 * size.
 */
typedef struct XmssSignatureBlob {
    /**
     * @brief
     * The size in bytes of the exported signature.
     *
     * @details
     * The size of *the contents of* the signature blob:
     *     `data_size` = #XMSS_SIGNATURE_SIZE(parameter_set).
     *
     * `data_size` is written in native-endian and is not part of the exported data.
     */
    size_t data_size;
    /**
     * @brief
     * The signature data in the format described by RFC 8391, Section 4.1.8.
     * This will always contain one signature in the XmssSignature format.
     */
    uint8_t data[];
} XmssSignatureBlob;

/**
 * @brief
 * Provide access to an XmssSignatureBlob's data as a structured type.
 *
 * @param[in] signature     The signature to access as a struct.
 * @returns A pointer to the signature struct. NULL if signature is NULL.
 */
static inline XmssSignature *xmss_get_signature_struct(const XmssSignatureBlob *const signature)
{
    if (signature == NULL) {
        return NULL;
    }
    return (XmssSignature *)signature->data;
}

/**
 * @brief
 * The size in bytes of an XmssSignature.
 *
 * Note that when using the XMSS API, XmssSignatureBlob and #XMSS_SIGNATURE_BLOB_SIZE() should be used.
 *
 * @note The argument to #XMSS_SIGNATURE_SIZE() will be evaluated multiple times.
 *
 * @param[in] param_set The #XmssParameterSetOID that was used for the signature.
 */
#define XMSS_SIGNATURE_SIZE(param_set) \
    (sizeof(XmssSignature) + sizeof(XmssValue256) * XMSS_TREE_DEPTH(param_set))

/**
 * @brief
 * The size in bytes of an XmssSignatureBlob.
 *
 * @note The argument to #XMSS_SIGNATURE_BLOB_SIZE() will be evaluated multiple times.
 *
 * @param[in] param_set The #XmssParameterSetOID that was used for the signature.
 */
#define XMSS_SIGNATURE_BLOB_SIZE(param_set) \
    (sizeof(XmssSignatureBlob) + XMSS_SIGNATURE_SIZE(param_set))

/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssSignatureBlob) + sizeof(XmssSignature) + 10 * sizeof(XmssValue256)
    == XMSS_SIGNATURE_BLOB_SIZE(XMSS_PARAM_SHA2_10_256), "XMSS_SIGNATURE_BLOB_SIZE mismatch");
/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssSignatureBlob) + sizeof(XmssSignature) + 16 * sizeof(XmssValue256)
    == XMSS_SIGNATURE_BLOB_SIZE(XMSS_PARAM_SHA2_16_256), "XMSS_SIGNATURE_BLOB_SIZE mismatch");

/** @brief Size of an XmssVerificationContext. */
#define XMSS_VERIFICATION_CONTEXT_SIZE (4 + 4 + 8 + 8 + 200 + 8 + 32)

/**
 * @brief
 * The context for signature verification.
 */
typedef union XmssVerificationContext {
    /** @brief Content of the XmssVerificationContext, opaque to the library user. */
    uint8_t data[XMSS_VERIFICATION_CONTEXT_SIZE];
    /** @brief Enforces alignment of `data`. */
    uint64_t alignment;
} XmssVerificationContext;

#endif /* !XMSS_STRUCTURES_H_INCLUDED */
