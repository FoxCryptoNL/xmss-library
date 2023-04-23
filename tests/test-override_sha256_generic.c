/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#include <stddef.h>

#include <openssl/evp.h>

#include "override_sha256_generic.h"

void *sha256_init(void)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    return ctx;
}

void sha256_update(void *context, const uint8_t *restrict data, size_t data_length)
{
    EVP_MD_CTX *restrict ctx = (EVP_MD_CTX *)context;
    EVP_DigestUpdate(ctx, data, data_length);
}

void sha256_finalize(void *context, XmssValue256 *restrict digest)
{
    EVP_MD_CTX *restrict ctx = (EVP_MD_CTX *restrict)context;
    EVP_DigestFinal(ctx, digest->data, NULL);
    EVP_MD_CTX_free(ctx);
}
