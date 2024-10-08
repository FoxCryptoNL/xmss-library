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

#if !XMSS_ENABLE_HASH_ABSTRACTION
#   error "Hash abstraction is disabled, so this source file must not be compiled."
#endif

#include "libxmss.h"

#if XMSS_ENABLE_SHA256_GENERIC
#   include "sha256_generic_xmss_hashes.h"
#else
#   include "sha256_internal_xmss_hashes.h"
#endif

LIBXMSS_STATIC
const xmss_hashes sha256_xmss_hashes = {
    .F = sha256_F,
    .H = sha256_H,
    .H_msg_init = sha256_H_msg_init,
    .H_msg_update = sha256_H_msg_update,
    .H_msg_finalize = sha256_H_msg_finalize,
    .PRF = sha256_PRF
#if XMSS_ENABLE_SIGNING
    ,
    .PRFkeygen = sha256_PRFkeygen,
    .PRFindex = sha256_PRFindex,
    .digest = sha256_digest,
    .native_digest = sha256_native_digest
#endif
};
