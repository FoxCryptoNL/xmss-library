/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief Prototypes for the SHA-256 hash function override using the generic interface.
 * @see generic_digest.h
 *
 * @details
 * Include this file in your override implementation for SHA-256 using the generic digest interface.
 *
 * Compile the library with CMake as follows:
 * ```
 * cmake -DXMSS_SHA256=OverrideGeneric
 * ```
 */

#pragma once

#ifndef XMSS_OVERRIDE_SHA256_GENERIC_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_OVERRIDE_SHA256_GENERIC_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "types.h"


/**
 * @copydoc XmssGenericDigestInit
 * @see XmssGenericDigestInit
 * @details
 * This is the specialization for the SHA-256 algorithm.
 */
void *sha256_init(void);

/**
 * @copydoc XmssGenericDigestUpdate
 * @see XmssGenericDigestUpdate
 * @details
 * This is the specialization for the SHA-256 algorithm.
 */
void sha256_update(void *restrict context, const uint8_t *restrict data, size_t data_length);

/**
 * @copydoc XmssGenericDigestFinalize
 * @see XmssGenericDigestFinalize
 * @details
 * This is the specialization for the SHA-256 algorithm.
 */
void sha256_finalize(void *restrict context, XmssValue256 *restrict digest);

#endif /* !XMSS_OVERRIDE_SHA256_GENERIC_H_INCLUDED */
