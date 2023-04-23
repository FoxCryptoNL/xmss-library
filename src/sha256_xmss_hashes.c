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

#include "config.h"

#if !XMSS_ENABLE_SHA256
#   error "SHA-256 is disabled, so SHA-256 related source files must not be compiled."
#endif

#if XMSS_ENABLE_SHA256_GENERIC
#   include "sha256_generic_xmss_hashes.h"
#else
#   include "sha256_internal_xmss_hashes.h"
#endif

#if XMSS_ENABLE_HASH_ABSTRACTION

const xmss_hashes sha256_xmss_hashes = {
    .digest = sha256_digest,
    .native_digest = sha256_native_digest,
    .F = sha256_F,
    .H = sha256_H,
    .H_msg = sha256_H_msg,
    .PRF = sha256_PRF,
    .PRFkeygen = sha256_PRFkeygen,
    .PRFindex = sha256_PRFindex
};

#endif
