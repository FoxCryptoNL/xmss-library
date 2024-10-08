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

#include "config.h"

#if !XMSS_ENABLE_SHA256
#   error "SHA-256 is disabled, so SHA-256 related source files must not be compiled."
#endif
#if XMSS_ENABLE_SHA256_GENERIC
#   error "SHA-256 uses generic interface, so SHA-256 related internal source files must not be compiled."
#endif

#include "sha256_internal_H0.h"


LIBXMSS_STATIC
const XmssNativeValue256 sha256_H0 = { {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
} };
