/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * Abstraction layer for SHAKE256/256.
 */

#pragma once

#ifndef XMSS_SHAKE256_256_XMSS_HASHES_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_SHAKE256_256_XMSS_HASHES_H_INCLUDED

#include "config.h"

#if !XMSS_ENABLE_SHAKE256_256
#   error "SHAKE256/256 is disabled, so SHAKE256/256 related headers must not be included."
#endif

#if XMSS_ENABLE_SHAKE256_256_GENERIC
#   include "shake256_256_generic_xmss_hashes.h"
#else
#   include "shake256_256_internal_xmss_hashes.h"
#endif

#if XMSS_ENABLE_HASH_ABSTRACTION

#   include "libxmss.h"
#   include "xmss_hashes_base.h"

#   if LIBXMSS

/*
 * It is not possible to forward-declare static data.
 * For our amalgamated library source, we define the data right here and now.
 */
#       include "shake256_256_xmss_hashes.c"

#   else

/**
 * @brief
 * Contains all SHAKE256/256 hash functions in a single abstraction structure.
 *
 * @details
 * If abstraction is disabled (i.e., if SHAKE256/256 is the only enabled hash algorithm),
 * then this structure is not defined. Instead, the XMSS_xxx() helper macros will
 * directly expand into the shake256_256_xxx() specialized hash functions.
 */
extern const xmss_hashes shake256_256_xmss_hashes;

#   endif

#endif

#endif /* !XMSS_SHAKE256_256_XMSS_HASHES_H_INCLUDED */
