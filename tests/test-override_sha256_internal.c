/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#define OPENSSL_API_COMPAT 10101
#include <openssl/sha.h>

#include "override_sha256_internal.h"


void xmss_sha256_process_block(XmssNativeValue256 *const Hi, const uint32_t *const Mi)
{
    uint32_t block[16];
    for (int i = 0; i < 16; ++i) {
        block[i] = htonl(Mi[i]);
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    memcpy(sha256.h, Hi, 32);
    SHA256_Update(&sha256, block, sizeof(block));
    memcpy(Hi, sha256.h, 32);
}
