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

#if !XMSS_ENABLE_SHAKE256_256
#   error "SHAKE256/256 is disabled, so SHAKE256/256 related source files must not be compiled."
#endif

#include "shake256_256_xmss_hashes.h"

#if XMSS_ENABLE_HASH_ABSTRACTION

const xmss_hashes shake256_256_xmss_hashes = {
    .digest = shake256_256_digest,
    .native_digest = shake256_256_native_digest,
    .F = shake256_256_F,
    .H = shake256_256_H,
    .H_msg = shake256_256_H_msg,
    .PRF = shake256_256_PRF,
    .PRFkeygen = shake256_256_PRFkeygen,
    .PRFindex = shake256_256_PRFindex
};

#endif
