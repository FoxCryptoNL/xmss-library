/*
 * SPDX-FileCopyrightText: 2024 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Max Fillinger
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * Utility and convenience functions.
 */

#include "utils.h"

ValueCompareResult compare_32_bytes(const uint8_t *const array1, const uint8_t *const array2)
{
    /* Double volatile: we want the original pointer to be used for every indirection, and prevent caching of the
     * pointed-to values. */
    volatile const uint8_t *volatile const p1 = array1;
    volatile const uint8_t *volatile const p2 = array2;
    volatile uint_fast8_t difference = 0;

    if ((p1 == NULL) || (p2 == NULL) || (p1 == p2))
    {
        /* If the addresses differ by a power of two, then a single bit error in the pointer value could result in them
         * pointing to the same memory (which in turn would lead to a false positive).
         * Such a bit error is handled by this function as if the memory does not compare equal.
         */
        return VALUES_ARE_NOT_EQUAL;
    }

    for (size_t i = 0; i < 32; i++) {
        difference |= (uint_fast8_t)(p1[i] ^ p2[i]);
    }
    if (difference) {
        return VALUES_ARE_NOT_EQUAL;
    }

    /* Repeat the check so that a single bit error cannot cause us to wrongly output VALUES_ARE_EQUAL.
     * Because every loop iteration reads volatile data and updates a volatile variable, the compiler is not allowed
     * to optimize away this second loop. */
    for (size_t i = 0; i < 32; i++) {
        difference |= (uint_fast8_t)(p1[i] ^ p2[i]);
    }
    if (difference) {
        return VALUES_ARE_NOT_EQUAL;
    }

    /* Repeat the check to ensure p1, p2, and size did not alter since the first time we checked. */
    if ((p1 == NULL) || (p2 == NULL) || (p1 == p2))
    {
        return VALUES_ARE_NOT_EQUAL;
    }

    return VALUES_ARE_EQUAL;
}
