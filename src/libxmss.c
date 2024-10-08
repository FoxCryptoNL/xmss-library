/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * Amalgamated source of the entire library.
 *
 * @details
 * This source file includes all the library source files while LIBXMSS=1 is defined.
 * This ensures that:
 *
 * - All library internals with "external linkage" are actually static (i.e., they are not external after all).
 *   Hence, they do not show up in the external symbols of the resulting library.
 * - Compilers that do not use link time optimization (LTO) have an opportunity to optimize code spread out over
 *   multiple .c files.
 * - We do not have to use weird namespaces such as `_xmss` or `__xmss` for non-API external symbols.
 */

#ifndef DOXYGEN

#define LIBXMSS 1
#include "libxmss.h"

#include "config.h"

/*
 * Note that we do not explicitly include the following source files:
 *
 *      sha256_internal_H0.c
 *      sha256_xmss_hashes.c
 *      shake256_256_xmss_hashes.c
 *
 * These define data, which for our amalgamated library source needs to be static. Therefore, these files are included
 * by their corresponding header, so the data gets defined at first inclusion. The reason is that static data cannot be
 * forward-declared.
 */

#if XMSS_ENABLE_SHA256
#   if XMSS_ENABLE_SHA256_DEFAULT
#       include "sha256_internal_default.c"
#   endif
#   if !XMSS_ENABLE_SHA256_GENERIC
#       include "sha256_internal_xmss_hashes.c"
#   endif
#endif

#if XMSS_ENABLE_SHAKE256_256
#   if XMSS_ENABLE_SHAKE256_256_DEFAULT
    #   include "shake256_256_internal_default.c"
#   endif
#   if !XMSS_ENABLE_SHAKE256_256_GENERIC
    #   include "shake256_256_internal_xmss_hashes.c"
#   endif
#endif

#include "xmss_hashes.c"
#include "utils.c"
#include "rand_hash.c"
#include "xmss_ltree.c"
#include "wotsp.c"
#include "wotsp_verification.c"
#include "verification.c"
#include "version.c"
#include "errors.c"

#if XMSS_ENABLE_SIGNING
#   include "zeroize.c"
#   include "wotsp_signing.c"
#   include "xmss_tree.c"
#   include "index_permutation.c"
#   include "signing.c"
#endif

#endif /* !DOXYGEN */
