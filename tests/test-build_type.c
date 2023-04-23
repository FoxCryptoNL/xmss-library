/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#include <assert.h>
#include <setjmp.h>
#include <signal.h>

#include "test-build_type.h"

bool test_NDEBUG_defined(void)
{
#ifdef NDEBUG
    return true;
#else
    return false;
#endif
}

static jmp_buf abort_handled;

static void signal_handler(int sig)
{
    if (sig != SIGABRT) {
        return;
    }
    longjmp(abort_handled, 1);
}

bool test_assert_enabled(void)
{
    /* Setup */

    signal(SIGABRT, signal_handler);

    /* Test */

    if (setjmp(abort_handled) == 1) {
        /* Only reached if SIGABRT was received -> implies assert() tripped -> implies assert() was enabled. */
        return true;
    }
#if defined(_MSC_VER) && defined(_DEBUG)
    /*
     * On Windows, when linking to the debug CRT, assert() will always show a dialog box.
     * See: https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/abort.
     * This would interfere with automated testing. Instead, we raise SIGABRT manually.
     * NOTE: Effectively, this skips the test for debug builds on Windows.
     */
    raise(SIGABRT);
#else
    assert(((void)"This assertion is part of a test. This is not a bug.", 0));
#endif
    /* Only reached if assert() did not trip -> implies assert() was not enabled. */
    return false;
}
