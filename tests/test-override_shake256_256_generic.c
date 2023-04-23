/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#include <stddef.h>

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

#include "override_shake256_256_generic.h"

void *shake256_256_init(void)
{
    static unsigned int xoflen = 32;
    static const OSSL_PARAM params[2] = {
        {
            .key = OSSL_DIGEST_PARAM_XOFLEN,
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .data = &xoflen,
            .data_size = sizeof(xoflen)
        },
        { 0 }
    };
    EVP_MD_CTX *restrict ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
    EVP_MD_CTX_set_params(ctx, params);
    return ctx;
}

void shake256_256_update(void *context, const uint8_t *restrict data, size_t data_length)
{
    EVP_MD_CTX *restrict ctx = (EVP_MD_CTX *restrict)context;
    EVP_DigestUpdate(ctx, data, data_length);
}

void shake256_256_finalize(void *context, XmssValue256 *restrict digest)
{
    EVP_MD_CTX *restrict ctx = (EVP_MD_CTX *restrict)context;
    EVP_DigestFinal(ctx, digest->data, NULL);
    EVP_MD_CTX_free(ctx);
}
