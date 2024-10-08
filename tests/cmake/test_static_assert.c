/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#include "compat.h"

int main(void)
{
    return 0;
}

/*
 * This compile-time test checks if the static assert detected by CMake actually works.
 *
 * Compiling this with ASSERT_VALUE=1 must always succeed, even when static asserts are not available.
 * Compiling this with ASSERT_VALUE=0 must fail if and only if CMake detected that static asserts are available.
 */
XMSS_STATIC_ASSERT(ASSERT_VALUE, "This assertion is part of a test. This is not a bug.");
