/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "endianness.h"

#define TEST_COUNT 3

static const uint8_t test_big_endian_data[TEST_COUNT * 4] = {
    0x11, 0x12, 0x13, 0x14,
    0x21, 0x22, 0x23, 0x24,
    0x31, 0x32, 0x33, 0x34
};

static const uint32_t test_native_data[TEST_COUNT] = {
    0x11121314,
    0x21222324,
    0x31323334
};

static bool test_big_endian_to_native_count(unsigned int count)
{
    /* 1 more than the test data to check for overruns */
    uint32_t dst[TEST_COUNT + 1] = { 0 };
    big_endian_to_native(dst, test_big_endian_data, count);

    /* verify that the conversion is correct */
    for (unsigned int i = 0 ; i < count; ++i) {
        if (dst[i] != test_native_data[i]) {
            return false;
        }
    }
    /* verify that the conversion does not overrun */
    for (unsigned int i = count ; i < TEST_COUNT + 1; ++i) {
        if (dst[i] != 0) {
            return false;
        }
    }
    return true;
}

static bool test_big_endian_to_native(void)
{
    bool success = true;

    for (unsigned int count = 0; count <= TEST_COUNT ; ++count) {
        if (!test_big_endian_to_native_count(count)) {
            fprintf(stderr, "big_endian_to_native() failed for count %u\n", count);
            success = false;
        }
    }

    return success;
}

static bool test_inplace_big_endian_to_native_count(uint_fast16_t count)
{
    /* 1 more than the test data to check for overruns */
    uint32_t buf[TEST_COUNT] = { 0 };
    memcpy(buf, test_big_endian_data, (size_t)count * 4);
    inplace_big_endian_to_native(buf, count);

    /* verify that the conversion is correct */
    for (unsigned int i = 0 ; i < count; ++i) {
        if (buf[i] != test_native_data[i]) {
            return false;
        }
    }
    return true;
}

static bool test_inplace_big_endian_to_native(void)
{
    bool success = true;

    for (unsigned int count = 0; count <= TEST_COUNT ; ++count) {
        if (!test_inplace_big_endian_to_native_count(count)) {
            fprintf(stderr, "inplace_big_endian_to_native() failed for count %u\n", count);
            success = false;
        }
    }

    return success;
}

static bool test_native_to_big_endian_count(unsigned int count)
{
    /* 4 more than the test data to check for overruns */
    uint8_t dst[TEST_COUNT * 4 + 4] = { 0 };
    native_to_big_endian(dst, test_native_data, count);

    /* verify that the conversion is correct */
    for (unsigned int i = 0; i < count * 4; ++i) {
        if (dst[i] != test_big_endian_data[i]) {
            return false;
        }
    }
    /* verify that the conversion does not overrun */
    for (unsigned int i = count * 4; i < TEST_COUNT * 4 + 4; ++i) {
        if (dst[i] != 0) {
            return false;
        }
    }
    return true;
}

static bool test_native_to_big_endian(void)
{
    bool success = true;

    for (unsigned int count = 0; count <=3 ; ++count) {
        if (!test_native_to_big_endian_count(count)) {
            fprintf(stderr, "native_to_big_endian() failed for count %u\n", count);
            success = false;
        }
    }

    return success;
}

int main(void)
{
    bool success = true;

    if (!test_big_endian_to_native()) {
        success = false;
    }
    if (!test_inplace_big_endian_to_native()) {
        success = false;
    }
    if (!test_native_to_big_endian()) {
        success = false;
    }

    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
