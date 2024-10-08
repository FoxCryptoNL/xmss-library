/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#include "libxmss.c"

#if XMSS_ENABLE_SIGNING
#   define reference_digest sha256_digest
#else
#   define REFERENCE_DIGEST_SHA256
#   include "reference-digest.inc"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nist-test-vectors.h"

void on_test_vector(XmssValue256 *digest, const uint8_t *message, size_t message_length)
{
    reference_digest(digest, message, message_length);
}

static bool monte_carlo_test(const char *const filename)
{
    /* Maximum line length: "Seed = " + 2 * 32 hex digits + "\r\n" + NUL. */
    char buffer[7 + 2 * 32 + 3] = { 0 };
    /* The seed of the initial message. */
    XmssValue256 seed = { 0 };
    /* The calculated digest to test. */
    XmssValue256 digest = { 0 };
    /* Three consecutive digests, MD[j] || MD[j+1] || MD[j+2]. */
    uint8_t message[3 * sizeof(XmssValue256)] = { 0 };

    printf("Testing vectors from file '%s'.\n", filename);

    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Unable to open file.\n");
        return false;
    }

    do {
        /* Read lines until the line starts with "Seed = ". */
        if (fgets(buffer, sizeof(buffer), file) == NULL) {
            fprintf(stderr, "Unable to read seed.\n");
            return false;
        }
    } while (!feof(file) && (strncmp(buffer, "Seed = ", 7) != 0));
    if (!decode_hex(seed.data, sizeof(XmssValue256), buffer)) {
        fprintf(stderr, "Unable to decode seed.\n");
        return false;
    }

    for (unsigned int count = 0; count < 100; ++count) {
        /* Initial condition: MD[0] = MD[1] = MD[2] = Seed. */
        memcpy(message, &seed, sizeof(XmssValue256));
        memcpy(message + sizeof(XmssValue256), &seed, sizeof(XmssValue256));
        memcpy(message + 2 * sizeof(XmssValue256), &seed, sizeof(XmssValue256));

        /* read: empty line (ignored) & COUNT line (ignored) & expected output (MD == next seed). */
        if ((fgets(buffer, sizeof(buffer), file) == NULL)
            || (fgets(buffer, sizeof(buffer), file) == NULL)
            || (fgets(buffer, sizeof(buffer), file) == NULL)
            || !decode_hex(seed.data, sizeof(XmssValue256), buffer)) {
            fprintf(stderr, "Unable to read MD (== next seed) for COUNT = %u.\n", count);
            return false;
        }

        for (int j = 3; j <= 1002; ++j) {
            /* Calculate MD[j]. */
            reference_digest(&digest, message, 3 * sizeof(XmssValue256));
            /* Rotate message: MD[j-3] || MD[j-2] || MD[j-1] -> MD[j-2] || MD[j-1] || MD[j]. */
            memmove(message, message + sizeof(XmssValue256), 2 * sizeof(XmssValue256));
            memcpy(message + 2 * sizeof(XmssValue256), &digest, sizeof(XmssValue256));
        }
        if (memcmp(&digest, &seed, sizeof(XmssValue256)) != 0)
        {
            fprintf(stderr, "Mismatch during COUNT = %u.\n", count);
            return false;
        }
    }

    if (fclose(file)) {
        fprintf(stderr, "Unable to close file.\n");
        return false;
    }

    return true;
}

int main(void)
{
    bool success = true;

    /*
     * It is assumed that the current working directory contains the NIST test vector files.
     */
    success = success && parse_nist_test_vectors("SHA256ShortMsg.rsp", 65);
    success = success && parse_nist_test_vectors("SHA256LongMsg.rsp", 64);
    success = success && monte_carlo_test("SHA256Monte.rsp");

    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
