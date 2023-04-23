/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#pragma once

#ifndef XMSS_NIST_TEST_VECTORS_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_NIST_TEST_VECTORS_H_INCLUDED

#include <stdint.h>

#include "types.h"

/* All NIST test vector messages fit in 16 kiB. */
#define MAX_MESSAGE_LENGTH (16 * 1024)

/*
 * @brief The test program callback per test vector. Must be defined by the test program.
 *
 * @param[out] digest   The digest (32 bytes) produced by the hash function under test.
 * @param[in] message   The test vector message data.
 * @param[in] message_length   The test vector message data length in bytes.
 */
void on_test_vector(XmssValue256 *digest, const uint8_t *message, size_t message_length);

/*
 * @brief Helper function to decode a line of data in the NIST test vector files.
 *
 * @param[out] dst   The decoded output data.
 * @param[in] dst_size   The number of bytes to decode.
 * @param[in] src   A line in a test vector file, in the format "<Some-Label> = <1 or more hex encoded bytes>\r\n".
 *
 * @return   true, if and only if dst_size bytes were decoded; false otherwise.
 */
bool decode_hex(uint8_t *dst, size_t dst_size, const char *src);

/*
 * @brief Parses the given filename and calls on_test_vector() for every vector.
 *
 * @param[in] filename   The name of the NIST test vector file, assumed to exist in the current working directory.
 * @param[in] expected_vector_count   The number of vectors in the file.
 *
 * @return   true, if and only if all vectors succeed (i.e., on_test_vector() returns true) and the total number
 *           of vectors found in the file equals expected_vector_count; false otherwise.
 */
bool parse_nist_test_vectors(const char *filename, unsigned int expected_vector_count);

#endif /* !XMSS_NIST_TEST_VECTORS_H_INCLUDED */
