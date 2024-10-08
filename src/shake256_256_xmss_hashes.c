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

#include "config.h"

#if !XMSS_ENABLE_HASH_ABSTRACTION
#   error "Hash abstraction is disabled, so this source file must not be compiled."
#endif

#include "libxmss.h"
#include "shake256_256_xmss_hashes.h"

LIBXMSS_STATIC
const xmss_hashes shake256_256_xmss_hashes = {
    .F = shake256_256_F,
    .H = shake256_256_H,
    .H_msg_init = shake256_256_H_msg_init,
    .H_msg_update = shake256_256_H_msg_update,
    .H_msg_finalize = shake256_256_H_msg_finalize,
    .PRF = shake256_256_PRF
#if XMSS_ENABLE_SIGNING
    ,
    .PRFkeygen = shake256_256_PRFkeygen,
    .PRFindex = shake256_256_PRFindex,
    .digest = shake256_256_digest,
    .native_digest = shake256_256_native_digest
#endif
};
