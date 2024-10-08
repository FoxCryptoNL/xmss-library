/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nist-test-vectors.h"

/*
 * All NIST test vector files are parsed line-by-line. Each test case starts with a line starting with "Len = ",
 * immediately followed by a line with "Msg = ", immediately followed by a line with either "MD = " or "Output = ".
 * All other lines are ignored (the files also contain spacer lines and comment lines).
 *
 * So:
 *
 * <other lines>
 * Len = <number of bits, multiple of 8>
 * Msg = <2 * (Len/8) hex digits>
 * MD = <2 * 32 hex digits>
 * <other lines>
 * ...
 *
 * Or:
 *
 * <other lines>
 * Len = <number of bits, multiple of 8>
 * Msg = <2 * (Len/8) hex digits>
 * Output = <2 * 32 hex digits>
 * <other lines>
 * ...
 */

bool decode_hex(uint8_t *dst, size_t dst_size, const char *src)
{
    /*
     * Assumed input format:
     *
     * Label = <2 * dst_size hex digits>\r\n
     *
     * We don't do much input validation. The vector will fail if parsing was wrong.
     */
    src = strstr(src, " = ");
    if (src == NULL) {
        return false;
    }
    src += 3;
    char buffer[3] = { 0 };
    for (; dst_size > 0; src += 2, ++dst, --dst_size) {
        if (!isxdigit((int)src[0]) || !isxdigit((int)src[1])) {
            return false;
        }
        buffer[0] = src[0];
        buffer[1] = src[1];
        *dst = (uint8_t)strtoul(buffer, NULL, 16);
    }
    return true;
}

bool parse_nist_test_vectors(const char *const filename, const unsigned int expected_vector_count)
{
    /* Maximum line length: "Msg = " + 2 * message_length (hex encoded) + "\r\n" + NUL. */
    char buffer[6 + 2 * MAX_MESSAGE_LENGTH + 3] = { 0 };
    /* First item in the vector is the message length ("Len = "). */
    unsigned int message_length = 0;
    /*
     * Second item in the test vector is the message ("Msg = ").
     * The message length has an upper bound of the maximum line length divided by 2.
     */
    uint8_t message[MAX_MESSAGE_LENGTH] = { 0 };
    /* Third and last item in the test vector is the digest ("MD = " or "Output = "). */
    XmssValue256 expected_digest = { 0 };
    /* The digest produced by the hash function under test. */
    XmssValue256 test_digest = { 0 };
    /* The number of test vectors encountered in the file. */
    unsigned int vector_count = 0;

    printf("Testing vectors from file '%s'.\n", filename);

    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Unable to open file.\n");
        return false;
    }

    /* Read test vectors until EOF. */
    do {
        do {
            /* Read lines until either EOF, or the line starts with "Len = ". */
            if (fgets(buffer, sizeof(buffer), file) == NULL) {
                if (!feof(file)) {
                    fprintf(stderr, "Error reading file.\n");
                    return false;
                }
            }
        } while (!feof(file) && (strncmp(buffer, "Len = ", 6) != 0));
        if (feof(file)) {
            break;
        }

        /* We found a new test case, starting with "Len = ". */
        if (sscanf(buffer + 6, "%u", &message_length) != 1) {
            fprintf(stderr, "Unable to parse message length: '%s'.\n", buffer);
            return false;
        }
        /* Note: the test vector lengths are specified in bits, but we use bytes. */
        message_length /= 8;
        if (message_length > MAX_MESSAGE_LENGTH) {
            fprintf(stderr, "Test vector message too long (%u > %u).\n", message_length, MAX_MESSAGE_LENGTH);
            return false;
        }
        printf("vector found with message length of %u bytes.\n", message_length);

        /* Now read the "Msg = " line and decode into message. */
        if ((fgets(buffer, sizeof(buffer), file) == NULL) || !decode_hex(message, message_length, buffer)) {
            fprintf(stderr, "Error reading message.\n");
            return false;
        }

        /* Now read the "MD = " or  line and decode into digest. */
        if ((fgets(buffer, sizeof(buffer), file) == NULL)
                || !decode_hex(expected_digest.data, sizeof(XmssValue256), buffer)) {
            fprintf(stderr, "Error reading digest.\n");
            return false;
        }

        ++vector_count;
        memset(&test_digest, 0, sizeof(XmssValue256));
        on_test_vector(&test_digest, message, message_length);
        if (memcmp(&test_digest, &expected_digest, sizeof(XmssValue256)) != 0) {
            fprintf(stderr, "Failed test vector %u.\n", vector_count);
            return false;
        }
    } while (!feof(file));

    if (fclose(file)) {
        fprintf(stderr, "Unable to close file.\n");
        return false;
    }

    if (vector_count != expected_vector_count) {
        fprintf(stderr, "Found %u test vectors, expected %u.\n", vector_count, expected_vector_count);
        return false;
    }

    return true;
}
