/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * XMSS hash functions for SHAKE256/256 using the generic interface.
 */

#pragma once

#ifndef XMSS_SHAKE256_256_GENERIC_XMSS_HASHES_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_SHAKE256_256_GENERIC_XMSS_HASHES_H_INCLUDED

#include "config.h"

#if !XMSS_ENABLE_SHAKE256_256
#   error "SHAKE256/256 is disabled, so SHAKE256/256 related headers must not be included."
#endif
#if !XMSS_ENABLE_SHAKE256_256_GENERIC
#   error "SHAKE256/256 uses internal interface, so SHAKE256/256 related generic headers must not be included."
#endif

#include <stddef.h>
#include <stdint.h>

#include "generic_xmss_hashes.h"
#include "override_shake256_256_generic.h"

/**
 * @copydoc prototype_digest
 * @see prototype_digest
 *
 * @details
 * This is the specialization for the SHAKE256/256 algorithm using the generic interface.
 *
 * This function implements the SHAKE256($M$, 256) function as defined by NIST FIPS 202, Section 6.2.
 */
static inline void shake256_256_digest(XmssValue256 *restrict digest, const uint8_t *restrict const message,
    size_t message_length)
{
    generic_digest(shake256_256_init, shake256_256_update, shake256_256_finalize, digest, message, message_length);
}

/**
 * @copydoc prototype_native_digest
 * @see prototype_native_digest
 *
 * @details
 * This is the specialization for the SHAKE256/256 algorithm using the generic interface.
 */
static inline void shake256_256_native_digest(XmssNativeValue256 *restrict native_digest,
    const uint32_t *restrict const words, size_t word_count)
{
    generic_native_digest(shake256_256_init, shake256_256_update, shake256_256_finalize, native_digest, words,
        word_count);
}

/**
 * @copydoc prototype_F
 * @see prototype_F
 *
 * @details
 * This is the specialization for the SHAKE256/256 algorithm using the generic interface.
 */
static inline void shake256_256_F(XmssNativeValue256 *restrict const native_digest, const Input_F *restrict const input)
{
    generic_F(shake256_256_init, shake256_256_update, shake256_256_finalize, native_digest, input);
}

/**
 * @copydoc prototype_H
 * @see prototype_H
 *
 * @details
 * This is the specialization for the SHAKE256/256 algorithm using the generic interface.
 */
static inline void shake256_256_H(XmssNativeValue256 *restrict const native_digest, const Input_H *restrict const input)
{
    generic_H(shake256_256_init, shake256_256_update, shake256_256_finalize, native_digest, input);
}

/**
 * @copydoc prototype_H_msg
 * @see prototype_H_msg
 *
 * @details
 * This is the specialization for the SHAKE256/256 algorithm using the generic interface.
 */
static inline void shake256_256_H_msg(XmssNativeValue256 *restrict const native_digest,
    const Input_H_msg *restrict const input, const uint8_t *restrict const message, const size_t message_length)
{
    generic_H_msg(shake256_256_init, shake256_256_update, shake256_256_finalize, native_digest, input, message,
        message_length);
}

/**
 * @copydoc prototype_PRF
 * @see prototype_PRF
 *
 * @details
 * This is the specialization for the SHAKE256/256 algorithm using the generic interface.
 */
static inline void shake256_256_PRF(XmssNativeValue256 *restrict const native_digest,
    const Input_PRF *restrict const input)
{
    generic_PRF(shake256_256_init, shake256_256_update, shake256_256_finalize, native_digest, input);
}

/**
 * @copydoc prototype_PRFkeygen
 * @see prototype_PRFkeygen
 *
 * @details
 * This is the specialization for the SHAKE256/256 algorithm using the generic interface.
 */
static inline void shake256_256_PRFkeygen(XmssNativeValue256 *restrict const native_digest,
    const Input_PRFkeygen *restrict const input)
{
    generic_PRFkeygen(shake256_256_init, shake256_256_update, shake256_256_finalize, native_digest, input);
}

/**
 * @copydoc prototype_PRFindex
 * @see prototype_PRFindex
 *
 * @details
 * This is the specialization for the SHAKE256/256 algorithm using the generic interface.
 */
static inline void shake256_256_PRFindex(XmssNativeValue256 *restrict const native_digest,
    const Input_PRFindex *restrict const input)
{
    generic_PRFindex(shake256_256_init, shake256_256_update, shake256_256_finalize, native_digest, input);
}

#endif /* !XMSS_SHAKE256_256_GENERIC_XMSS_HASHES_H_INCLUDED */
