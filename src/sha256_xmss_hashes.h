/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * Abstraction layer for SHA-256.
 */

#pragma once

#ifndef XMSS_SHA256_XMSS_HASHES_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_SHA256_XMSS_HASHES_H_INCLUDED

#include "config.h"

#if !XMSS_ENABLE_SHA256
#   error "SHA-256 is disabled, so SHA-256 related headers must not be included."
#endif

#if XMSS_ENABLE_SHA256_GENERIC
#   include "sha256_generic_xmss_hashes.h"
#else
#   include "sha256_internal_xmss_hashes.h"
#endif

#if XMSS_ENABLE_HASH_ABSTRACTION

#   include "libxmss.h"
#   include "xmss_hashes_base.h"

#   if LIBXMSS

/*
 * It is not possible to forward-declare static data.
 * For our amalgamated library source, we define the data right here and now.
 */
#       include "sha256_xmss_hashes.c"

#   else

/**
 * @brief
 * Contains all SHA-256 hash functions in a single abstraction structure.
 *
 * @details
 * If abstraction is disabled (i.e., if SHA-256 is the only enabled hash algorithm),
 * then this structure is not defined. Instead, the XMSS_xxx() helper macros will
 * directly expand into the sha256_xxx() specialized hash functions. This allows the compiler to optimize: it saves
 * an indirection, and possibly eliminates instantiating the sha256_xxx() functions by inlining them.
 */
extern const xmss_hashes sha256_xmss_hashes;

#   endif

#endif

#endif /* !XMSS_SHA256_XMSS_HASHES_H_INCLUDED */
