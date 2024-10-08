/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#include "zeroize.c"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief
 * Volatile pointer to some volatile character object.
 *
 * - Assigning the address of a character object to this (volatile!) pointer ensures that the object must exist in
 *   physical memory (i.e., its physical existence in memory cannot be optimized away).
 * - Writing to the pointed-to object (as an indirect way to assign a value to the original character object) ensures
 *   that the physical memory location is actually written to (i.e., the "assignment" cannot be optimized away).
 * - Reading the pointed-to object (as an indirect way to access the value of the object) ensures
 *   that the physical memory location is actually read.
 *
 * NOTE: Any access (read or write) through this pointer outside the storage duration of the original pointed-to object
 *       is, of course, formally undefined behavior.
 */
static volatile char *volatile stack_location;

/**
 * @brief
 * Macro that:
 * - Defines a single, uninitialized character object with automatic storage duration.
 *   For the purpose of these tests, this is a so called "stack variable" (note that "stack" is not C terminology).
 * - Takes the address of the character object, so the compiler cannot optimize it away.
 * - Stores the address in a global volatile pointer, so the compiler cannot make assumptions about the pointer later.
 * - Stores the value 'X' in the object via the volatile pointer, so the compiler cannot optimize it away.
 *
 * Result: there *is* a character object named 'data', at some physical memory location, and it *has* the value 'X'.
 */
#define SETUP_DATA_AND_STACK_LOCATION() \
    char data; \
    stack_location = &data; \
    *stack_location = 'X';

/**
 * @brief
 * Performs:
 * - Sets up a stack location with an 'X'.
 * - Does not clear the memory before the end of the function scope.
 */
static void setup_stack_none(void)
{
    SETUP_DATA_AND_STACK_LOCATION();
}

/**
 * @brief
 * Performs:
 * - Sets up a stack location with an 'X'.
 * - Attempts to clear the data before the end of the function scope, using standard memset().
 */
static void setup_stack_memset(void)
{
    SETUP_DATA_AND_STACK_LOCATION();
    /* Since data is going out of scope, this call may be optimized away by the compiler. */
    memset(&data, 0, 1);
}

/**
 * @brief
 * Performs:
 * - Sets up a stack location with an 'X'.
 * - Attempts to clear the data before the end of the function scope, using specialized xmss_zeroize().
 */
static void setup_stack_zeroize(void)
{
    SETUP_DATA_AND_STACK_LOCATION();
    /*
     * Since data is going out of scope, this call could be optimized away by the compiler.
     * However, xmss_zeroize() is designed to prevent such optimization.
     */
    xmss_zeroize(&data, 1);
}

/**
 * @brief
 * Defines a volatile function pointer to the given function that can be used to
 * call the given function without inlining.
 *
 * @param[in] return_type     The return type of function.
 * @param[in] function_name   The name of the function.
 * @returns   A volatile function pointer definition with the postfix _noinline added to function_name.
 */
#define VOLATILE_FUNCTION_NOINLINE(return_type, function_name) \
    static return_type (*const volatile function_name ## _noinline)(void) = function_name

VOLATILE_FUNCTION_NOINLINE(void, setup_stack_none);
VOLATILE_FUNCTION_NOINLINE(void, setup_stack_memset);
VOLATILE_FUNCTION_NOINLINE(void, setup_stack_zeroize);

/*
 * Each test function performs the following:
 * - Calls (without inlining) one of the setup_xxx() functions.
 * - After return of the setup_xxx() function, tests the content of the (now stale) stack location.
 *
 * NOTE:
 * This is formally undefined behavior: dereferencing stack_location which no longer points to an existing object.
 * However, most platforms are stack based. The test function itself does not use stack memory; at
 * least not after the setup_xxx() call. As long as the test_xxx() function itself is also not inlined, the pointed-to
 * memory has not been used for anything else.
 *
 * To obtain the highest confidence level for this method:
 * - The test function itself should be called without inlining.
 *   This ensures that the stack location is not re-used for anything else before examining the test value.
 * - The test function should not take parameters (void).
 *   This prevents the stack being used for parameter passing.
 * - The setup function should be called without inlining.
 * - The setup function should not take parameters (void).
 *
 * Stack usage:
 * Test caller: unknown
 *   -> calls test_xxx_noinline() without parameters: new stack
 *      -> no local variables: no stack usage
 *      -> calls setup_xxx_noinline() without parameters: new stack
 *          -> Sets up a stack variable with content 'X'
 *          -> (optional) clears the stack variable, which could be optimized away
 *          -> returns (void)
 *      -> tests stale location (now either 'X' or 0)
 *          (this assumes the location was not reused and is still accessible; formally undefined behavior)
 *      -> returns result
 *   -> reports result
 */

static bool test_none(void)
{
    /* Setup */

    setup_stack_none_noinline();

    /* Test */

    /*
     * NOTE: This formally is undefined behavior: dereferencing a stale pointer to a no longer existing object.
     * In real life, this checks to see if the old stack was setup in the usual way.
     * This probably works. If it ever fails ... interesting platform ... but it is only a test.
     */
    return *stack_location == 'X';
}

static bool test_memset(void)
{
    /* Setup */

    setup_stack_memset_noinline();

    /* Test */

    /*
     * NOTE: This formally is undefined behavior: dereferencing a stale pointer to a no longer existing object.
     * In real life, this checks to see if the old stack was cleared.
     */
    return *stack_location == 0;
}

static bool test_zeroize(void)
{
    /* Setup */

    setup_stack_zeroize_noinline();

    /* Test */

    /*
     * NOTE: This formally is undefined behavior: dereferencing a stale pointer to a no longer existing object.
     * In real life, this checks to see if the old stack was cleared.
     */
    return *stack_location == 0;
}

VOLATILE_FUNCTION_NOINLINE(bool, test_none);
VOLATILE_FUNCTION_NOINLINE(bool, test_memset);
VOLATILE_FUNCTION_NOINLINE(bool, test_zeroize);

int main(void)
{
    if (!test_none_noinline()) {
        fprintf(stderr, "This platform handles its stack unconventionally. Test skipped (marked as failed).\n");
        return EXIT_FAILURE;
    }

    bool success = true;
    bool test_result;

    test_result = test_memset_noinline();
    printf("informational: memset() : %s\n", test_result ? "cleared" : "not cleared");

    test_result = test_zeroize_noinline();
    printf("test: xmss_zeroize()    : %s\n", test_result ? "cleared" : "not cleared");
    success = success && test_result;

    puts(success ? "PASS" : "FAIL");
    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
