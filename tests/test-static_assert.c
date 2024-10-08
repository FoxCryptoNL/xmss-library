/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/*
 * NOTE: Do not include any standard C headers, to avoid them somehow defining _Static_assert to something non-standard.
 */

#include "compat.h"

int main(void)
{
    /*
     * This cannot be tested at runtime (by definition, _Static_assert works at compile time).
     * This test only exists to show up in the test report.
     * NOTE: This test should only be enabled if CMake figured out _Static_assert is somehow available.
     */

    /*
     * The best we can do is replicate the logic of "compat.h", so at least the test fails to compile if you
     * enabled it (for showing up in the test report) under the wrong conditions.
     */

    /* <stdbool.h> was deliberately not included, so bool cannot be used. */
    int have_static_assert = 0;

#if __STDC_VERSION__ >= 201112L
    /* C11 (and later) defines _Static_assert, so this must compile successfully. */
    _Static_assert(1, "");
    have_static_assert = 1;
#endif
#if XMSS_CAN_USE_STATIC_ASSERT
    /* CMake determined this works, so this must compile successfully. */
    _Static_assert(1, "");
    have_static_assert = 1;
#endif
#if XMSS_CAN_USE_EXTENSION_STATIC_ASSERT
    /* CMake determined this works, so this must compile successfully. */
    __extension__ _Static_assert(1, "");
    have_static_assert = 1;
#endif

    /* This should always compile (this is what compat.h is for). */
    XMSS_STATIC_ASSERT(1, "");

    /* <stdlib.h> was deliberately not included, so EXIT_XXX cannot be used. */
    return have_static_assert ? 0 : 1;
}
