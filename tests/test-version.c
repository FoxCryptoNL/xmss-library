/*
 * SPDX-FileCopyrightText: 2024 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#include "version.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    bool success = true;

    // Test the availability of all the macro's (compile-time tests).
    (void)XMSS_LIBRARY_VERSION;
    (void)XMSS_LIBRARY_VERSION_MAJOR;
    (void)XMSS_LIBRARY_VERSION_MINOR;
    (void)XMSS_LIBRARY_VERSION_PATCH;
    (void)XMSS_LIBRARY_VERSION_CONSTRUCT(1,2,3);

    // Test the runtime.
    uint32_t runtime_version = xmss_library_get_version();
    success = success && (runtime_version == XMSS_LIBRARY_VERSION);

    puts(success ? "PASS" : "FAIL");
    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
