/*
 * SPDX-FileCopyrightText: 2022 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Thomas Schaap
 */

/**
 * @file
 * @brief
 * Enumerations, basic types and callback function specifications.
 *
 * @details
 * There is no need to include this header explicitly. Instead, include either verification.h or signing.h.
 */

#pragma once

#ifndef XMSS_TYPES_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_TYPES_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "compat.h"

/**
 * @brief
 * A list of Hamming(8,4) code words.
 *
 * @details
 * These code words are used to provide values with high hamming distance to other enums' values.
 *
 * #XMSS_DISTANT_VALUE_0 is guaranteed to be 0, allowing its use for values that should automatically be set when a
 * structure it contains is cleared to all-zeroes.
 */
enum XmssDistantValues
{
    /** @brief Code word 0: $00000000_2$. */
    XMSS_DISTANT_VALUE_0 = 0x00,

    /** @brief Code word 1: $11010010_2$. */
    XMSS_DISTANT_VALUE_1 = 0xD2,

    /** @brief Code word 2: $01010101_2$. */
    XMSS_DISTANT_VALUE_2 = 0x55,

    /** @brief Code word 3: $10000111_2$. */
    XMSS_DISTANT_VALUE_3 = 0x87,

    /** @brief Code word 4: $10011001_2$. */
    XMSS_DISTANT_VALUE_4 = 0x99,

    /** @brief Code word 5: $01001011_2$. */
    XMSS_DISTANT_VALUE_5 = 0x4B,

    /** @brief Code word 6: $11001100_2$. */
    XMSS_DISTANT_VALUE_6 = 0xCC,

    /** @brief Code word 7: $00011110_2$. */
    XMSS_DISTANT_VALUE_7 = 0x1E,

    /** @brief Code word 8: $11100001_2$. */
    XMSS_DISTANT_VALUE_8 = 0xE1,

    /** @brief Code word 9: $00110011_2$. */
    XMSS_DISTANT_VALUE_9 = 0x33,

    /** @brief Code word A: $10110100_2$. */
    XMSS_DISTANT_VALUE_A = 0xB4,

    /** @brief Code word B: $01100110_2$. */
    XMSS_DISTANT_VALUE_B = 0x66,

    /** @brief Code word C: $01111000_2$. */
    XMSS_DISTANT_VALUE_C = 0x78,

    /** @brief Code word D: $10101010_2$. */
    XMSS_DISTANT_VALUE_D = 0xAA,

    /** @brief Code word E: $00101101_2$. */
    XMSS_DISTANT_VALUE_E = 0x2D,

    /** @brief Code word F: $11111111_2$. */
    XMSS_DISTANT_VALUE_F = 0xFF,
};

/**
 * @brief
 * The return codes for the functions in the XMSS library.
 *
 * @details
 * The values of these return codes are chosen from a Hamming(8,4) code to ensure bit error resilience.
 * Note that #XMSS_DISTANT_VALUE_0 (with value 0) is unused to avoid accidentally confusing it with an uninitialized
 * value.
 *
 * @see XmssDistantValues
 * @see xmss_error_to_description()
 * @see xmss_error_to_name()
 */
typedef enum XmssError
{
    /* NOTE to developers
     * ==================
     *
     * Keep the enumeration-constants synchronized with xmss_error_to_name().
     * Keep the Doxygen descriptions for the enumeration-constants synchronized with xmss_error_to_description().
     */

    /* XMSS_DISTANT_VALUE_0 must not be used. */

    /** @brief Success. */
    XMSS_OKAY = XMSS_DISTANT_VALUE_1,

    /** @brief An unexpected NULL pointer was passed. */
    XMSS_ERR_NULL_POINTER = XMSS_DISTANT_VALUE_2,

    /** @brief The signature is invalid. */
    XMSS_ERR_INVALID_SIGNATURE = XMSS_DISTANT_VALUE_3,

    /** @brief A mismatch was detected between arguments. */
    XMSS_ERR_ARGUMENT_MISMATCH = XMSS_DISTANT_VALUE_4,

    /** @brief An error occurred with memory allocation. */
    XMSS_ERR_ALLOC_ERROR = XMSS_DISTANT_VALUE_5,

    /** @brief A blob structure was found to be invalid. */
    XMSS_ERR_INVALID_BLOB = XMSS_DISTANT_VALUE_6,

    /** @brief The passed context is in an incorrect state. */
    XMSS_ERR_BAD_CONTEXT = XMSS_DISTANT_VALUE_7,

    /** @brief The value of an argument was invalid. */
    XMSS_ERR_INVALID_ARGUMENT = XMSS_DISTANT_VALUE_8,

    /** @brief The calculations for the key generation partition were already performed. */
    XMSS_ERR_PARTITION_DONE = XMSS_DISTANT_VALUE_9,

    /** @brief Not all key generation partition calculations were completed. */
    XMSS_ERR_UNFINISHED_PARTITIONS = XMSS_DISTANT_VALUE_A,

    /** @brief There are not enough signatures available to allow the operation. */
    XMSS_ERR_TOO_FEW_SIGNATURES_AVAILABLE = XMSS_DISTANT_VALUE_B,

    /** @brief Partitions are not consecutive. */
    XMSS_ERR_PARTITIONS_NOT_CONSECUTIVE = XMSS_DISTANT_VALUE_C,

    /** @brief The key context does not have a public key loaded. */
    XMSS_ERR_NO_PUBLIC_KEY = XMSS_DISTANT_VALUE_D,

    /**
     * @brief
     * A fault was detected.
     *
     * @details
     * Note that faults can also cause different errors or segfaults.
     */
    XMSS_ERR_FAULT_DETECTED = XMSS_DISTANT_VALUE_E,

    /**
     * @brief
     * Function returned prematurely.
     *
     * @details
     * Dummy value to initialize return value variables before the correct value is known.
     */
    XMSS_UNINITIALIZED = XMSS_DISTANT_VALUE_F
} XmssError;

/**
 * @brief
 * The XMSS parameter sets that are supported by this library.
 *
 * @details
 * These are the supported subset of OIDs for XMSS parameter sets as defined in:
 *
 * - for SHA-256: RFC 8391, Section 5.3 and NIST SP 800-208, Section 5.1.
 * - for SHAKE256/256: NIST SP 800-208, Section 5.3.
 *
 * @note
 * All listed OIDs are defined, even if a hash algorithm was disabled during compilation and as a result is not
 * supported.
 */
typedef enum XmssParameterSetOID
{
    /** @brief SHA-256, tree height 10. */
    XMSS_PARAM_SHA2_10_256 = 1,

    /** @brief SHA-256, tree height 16. */
    XMSS_PARAM_SHA2_16_256 = 2,

    /** @brief SHA-256, tree height 20. */
    XMSS_PARAM_SHA2_20_256 = 3,

    /** @brief SHAKE256/256, tree height 10. */
    XMSS_PARAM_SHAKE256_10_256 = 0x10,

    /** @brief SHAKE256/256, tree height 16. */
    XMSS_PARAM_SHAKE256_16_256 = 0x11,

    /** @brief SHAKE256/256, tree height 20. */
    XMSS_PARAM_SHAKE256_20_256 = 0x12,
} XmssParameterSetOID;

/**
 * @brief
 * The tree depth for a given XMSS parameter set.
 *
 * @note The argument to #XMSS_TREE_DEPTH() will be evaluated multiple times.
 *
 * @param[in] param_set A valid #XmssParameterSetOID.
 */
#define XMSS_TREE_DEPTH(param_set) \
    (((param_set) == XMSS_PARAM_SHA2_10_256 || (param_set) == XMSS_PARAM_SHAKE256_10_256) ? 10u : \
        (((param_set) == XMSS_PARAM_SHA2_16_256 || (param_set) == XMSS_PARAM_SHAKE256_16_256) ? 16u : \
            (((param_set) == XMSS_PARAM_SHA2_20_256 || (param_set) == XMSS_PARAM_SHAKE256_20_256) ? 20u : \
                0u /* Garbage in, 0 out */ \
            ) \
        ) \
    )

/**
 * @brief
 * The supported settings for index obfuscation.
 */
typedef enum XmssIndexObfuscationSetting
{
    /** @brief No index obfuscation. */
    XMSS_INDEX_OBFUSCATION_OFF = XMSS_DISTANT_VALUE_1,

    /** @brief Index obfuscation is enabled. */
    XMSS_INDEX_OBFUSCATION_ON = XMSS_DISTANT_VALUE_2
} XmssIndexObfuscationSetting;

/**
 * @brief
 * The type of caching to use.
 */
typedef enum XmssCacheType
{
    /** @brief No caching. */
    XMSS_CACHE_NONE = XMSS_DISTANT_VALUE_1,

    /**
     * @brief
     * Single level caching.
     *
     * @details
     * Single level caching saves half the cache space, but increases computation time for every signature.
     */

    XMSS_CACHE_SINGLE_LEVEL = XMSS_DISTANT_VALUE_2,
    /**
     * @brief
     * Top caching.
     *
     * @details
     * Top caching caches a single level and all levels above that, up to the root. Top caching requires twice as much
     * space as single level but saves computation time for every signature.
     */
    XMSS_CACHE_TOP = XMSS_DISTANT_VALUE_3
} XmssCacheType;

/**
 * @brief
 * A generic 256-bit value, represented as a byte stream.
 *
 * @see XmssNativeValue256
 *
 * @details
 * For all supported parameter sets, both digests and seeds are 256-bit values.
 *
 * This type makes no guarantees about the memory alignment of the object.
 * It may be freely cast to and from a `uint8_t` pointer.
 *
 * This type ensures that both caller and callee agree on the amount of data pointed to.
 */
typedef struct XmssValue256 {
    /** @brief The byte stream representation of the value. */
    uint8_t data[32];
} XmssValue256;

/**
 * @brief
 * The number of 32-bits words in an XmssValue256.
 *
 * @details
 * Defined as a literal constant to allow its use in both a signed and an unsigned context.
 */
#define XMSS_VALUE_256_WORDS 8

/** @private */
XMSS_STATIC_ASSERT(XMSS_VALUE_256_WORDS == sizeof(XmssValue256) / sizeof(uint32_t),
    "inconsistent value of XMSS_VALUE_256_WORDS");

/**
 * @brief
 * The internal (native) representation of a 256-bit value.
 *
 * @see XmssValue256
 *
 * @note This type is for library internal use only. It is defined in the public API headers only for the
 * hash overrides using the internal interface.
 *
 * @details
 * For all supported parameter sets, both digests and seeds are 256-bit values.
 *
 * This form of the value is guaranteed to be aligned on a 32-bit memory boundary.
 * It may be freely cast to and from a `uint32_t` pointer.
 *
 * May require byte swapping to get XmssValue256.
 *
 * This type ensures that both caller and callee agree on the amount of data pointed to.
 */
typedef struct XmssNativeValue256 {
    /** @brief The contents of the value. */
    uint32_t data[XMSS_VALUE_256_WORDS];
} XmssNativeValue256;

/** @private */
XMSS_STATIC_ASSERT(sizeof(XmssNativeValue256) == sizeof(XmssValue256),
    "XmssNativeValue256 and XmssValue256 should have equal size");

/**
 * @brief
 * A pointer to a buffer with a given size.
 */
typedef struct XmssBuffer {
    /** @brief The size in bytes of `data`. */
    size_t data_size;
    /** @brief The data. May be NULL if and only if `data_size` is 0. */
    uint8_t *data;
} XmssBuffer;

/**
 * @brief
 * A function to reallocate memory.
 *
 * @details
 * All memory allocations will be done using this function.
 *
 * Note that the signature for this function type is identical to that of standard C `realloc()`.
 *
 * @see xmss_context_initialize() for additional information about memory management.
 *
 * @param[in] ptr   The pointer to an existing block of memory to resize, or NULL to allocate a new block of memory. If
 *                  the memory reallocation function returns a non-NULL value that is different from this argument, this
 *                  pointer is considered to no longer be valid and will neither be used nor passed to a memory
 *                  deallocation function.
 * @param[in] size  The requested size of the memory block.
 * @returns The pointer to the memory block, which is at least size bytes large, or NULL if (re)allocation failed.
 */
typedef void *(*XmssReallocFunction)(void *ptr, size_t size);

/**
 * @brief
 * A function to deallocate memory.
 *
 * @details
 * All memory deallocations will be done using this function.
 *
 * Note that the signature for this function type is identical to that of standard C `free()`.
 *
 * @see xmss_context_initialize() for additional information about memory management.
 *
 * @param[in] ptr   The pointer to the allocated memory. After the memory deallocation function returns this pointer is
 *                  considered to no longer be valid and will neither be used nor passed to a memory deallocation
 *                  function again.
 */
typedef void (*XmssFreeFunction)(void *ptr);

/**
 * @brief
 * A function to securely erase sensitive data.
 *
 * @details
 * This function overwrites sensitive data in memory with zeros.
 *
 * @param[in] ptr   The pointer to the object to erase.
 * @param[in] size  The size in bytes of the object.
 */
typedef void (*XmssZeroizeFunction)(void *ptr, size_t size);

#endif /* !XMSS_TYPES_H_INCLUDED */
