/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#include "libxmss.c"

#if XMSS_ENABLE_SIGNING
#   define reference_digest sha256_digest
#else
#   define REFERENCE_DIGEST_SHA256
#   include "reference-digest.inc"
#endif

#include "test-xmss_hashes.inc"

#if XMSS_ENABLE_HASH_ABSTRACTION

#   include "sha256_xmss_hashes.h"

const xmss_hashes *const hash_functions = &sha256_xmss_hashes;

#endif
