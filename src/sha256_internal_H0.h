/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * The initial state of SHA-256.
 */

#pragma once

#ifndef XMSS_SHA256_INTERNAL_H0_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_SHA256_INTERNAL_H0_H_INCLUDED

#include "config.h"

#if !XMSS_ENABLE_SHA256
#   error "SHA-256 is disabled, so SHA-256 related headers must not be included."
#endif
#if XMSS_ENABLE_SHA256_GENERIC
#   error "SHA-256 uses generic interface, so SHA-256 related internal headers must not be included."
#endif

#include "libxmss.h"
#include "types.h"


#if LIBXMSS

/*
 * It is not possible to forward-declare static data.
 * For our amalgamated library source, we define the data right here and now.
 */
#   include "sha256_internal_H0.c"

#else

/**
 * @brief
 * The initial native SHA-256 hash value as defined by the standard.
 *
 * @details
 * See NIST FIPS 180-4, Section 5.3.3.
 */
extern const XmssNativeValue256 sha256_H0;

#endif

#endif /* !XMSS_SHA256_INTERNAL_H0_H_INCLUDED */
