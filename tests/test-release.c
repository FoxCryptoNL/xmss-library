/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#include <stdio.h>
#include <stdlib.h>

#include "test-build_type.h"

int main(void)
{
    bool success = test_NDEBUG_defined() && !test_assert_enabled();

    puts(success ? "PASS" : "FAIL");

    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
