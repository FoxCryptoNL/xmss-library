/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#include <stddef.h>

#include <openssl/evp.h>

#include "override_sha256_generic.h"

void *xmss_sha256_init(void)
{
    EVP_MD_CTX *const ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    return ctx;
}

void xmss_sha256_update(void *const context, const uint8_t *const data, const size_t data_length)
{
    EVP_MD_CTX *const ctx = (EVP_MD_CTX *)context;
    EVP_DigestUpdate(ctx, data, data_length);
}

void xmss_sha256_finalize(void *const context, XmssValue256 *const digest)
{
    EVP_MD_CTX *const ctx = (EVP_MD_CTX *)context;
    EVP_DigestFinal(ctx, digest->data, NULL);
    EVP_MD_CTX_free(ctx);
}
