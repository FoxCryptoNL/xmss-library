/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "nist-test-vectors.h"
#include "shake256_256_xmss_hashes.h"

void on_test_vector(XmssValue256 *digest, const uint8_t *message, size_t message_length)
{
    shake256_256_digest(digest, message, message_length);
}

int main(void)
{
    bool success = true;

    /*
     * It is assumed that the current working directory contains the NIST test vector files.
     */
    success = success && parse_nist_test_vectors("SHAKE256ShortMsg.rsp", 273);
    success = success && parse_nist_test_vectors("SHAKE256LongMsg.rsp", 100);

    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
