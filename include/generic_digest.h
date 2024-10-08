/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief Abstract typedefs for hash function overrides using the generic interface.
 * @details
 * Do not include this file. Instead, either include override_sha256_generic.h or
 * override_shake256_256_generic.h, depending on the specific algorithm you are overriding.
 *
 * For each digest algorithm (SHA-256 and/or SHAKE256/256), the library allows to override its internal implementation.
 * The main use case is hardware acceleration.
 *
 * If your platform is compatible with the internal format of the library, then it is preferred to use the internal
 * interface rather than the generic interface specified here.
 *
 * When supplying an override using the generic interface, you will have to implement 3 functions (per algorithm, that
 * you are overriding):
 * - #XmssGenericDigestInit
 * - #XmssGenericDigestUpdate
 * - #XmssGenericDigestFinalize
 *
 * The library guarantees that the functions are called in the following order:
 * - exactly one call to the initialize function
 * - 0 or more calls to the update function
 * - exactly one call to the finalize function
 *
 * Per thread, there will be at most one digest in use at any one time. This implies that if you use the library single
 * threaded, then you could use a single statically allocated context. In that case the opaque `context` parameter does
 * not necessarily have to be provided or used (i.e., it could simply be NULL).
 *
 * **Error handling**
 *
 * For performance reasons, the functions themselves do not provide a means to return errors. If your digest
 * implementation can fail, then the failing function should store its error in a global (or thread-local)
 * context. This context must then be checked after each library call.
 *
 * For example (not using bit error resilient booleans for readability):
 *
 * ```
 * static bool digest_error;
 *
 * digest_error = false;
 * XmssError result = xmss_generate_private_key();
 * if (result != XMSS_OKAY || digest_error) {
 *     // handle errors
 * }
 * ```
 */

#pragma once

#ifndef XMSS_GENERIC_DIGEST_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_GENERIC_DIGEST_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "types.h"

/**
 * @brief
 * Generic digest initialization function.
 * Returns a context for use by the update and finalize functions.
 * The supplier of the generic digest override has full control over the context; the returned context is treated as
 * opaque by the XMSS library.
 *
 * The library will eventually call the finalize function exactly once for this context.
 *
 * @returns An opaque context (may be NULL) for a single digest calculation.
 */
typedef void *(*XmssGenericDigestInit)(void);

/**
 * @brief
 * Generic digest update function.
 * Updates the internal hash state for a single digest calculation with the additional data supplied.
 *
 * @param[in] context   An opaque context, i.e., the result of the most recent call to the initialization function on
 *                      this thread.
 * @param[in] data   The byte stream of additional data to be included in the message; may be NULL if and only if
 *                   `data_length` is zero.
 * @param[in] data_length   The number of bytes pointed to by `data`.
 */
typedef void (*XmssGenericDigestUpdate)(void *context, const uint8_t *data, size_t data_length);

/**
 * @brief
 * Generic digest finalize function.
 * Outputs the digest and disposes the context.
 *
 * @param[in] context   An opaque context, i.e., the result of the most recent call to the initialization function on
 *                      this thread.
 * @param[out] digest   The output of the hash function.
 */
typedef void (*XmssGenericDigestFinalize)(void *context, XmssValue256 *digest);

#endif /* !XMSS_GENERIC_DIGEST_H_INCLUDED */
