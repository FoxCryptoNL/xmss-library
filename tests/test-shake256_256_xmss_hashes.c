/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#include "config.h"

#if XMSS_ENABLE_HASH_ABSTRACTION

#   include "shake256_256_xmss_hashes.h"
#   include "test-xmss_hashes.h"

const xmss_hashes *const test_xmss_hashes = &shake256_256_xmss_hashes;

#endif
