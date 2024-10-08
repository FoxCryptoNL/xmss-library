/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Max Fillinger
 */

/**
 * @file
 * @brief
 * Securely purge memory.
 */

#include <stddef.h>
#include <string.h>

#include "config.h"

#include "zeroize.h"

/**
 * @brief
 * Volatile pointer to the standard C library memset() function.
 */
static void * (* volatile const memset_p)(void *, int, size_t) = memset;

#if XMSS_CAN_USE_PRAGMA_OPTIMIZE
#pragma optimize("", off)
#endif

#if XMSS_CAN_USE_PRAGMA_GCC_OPTIMIZE
#pragma GCC push_options
#pragma GCC optimize("O0")
#endif

#if XMSS_CAN_USE_PRAGMA_CLANG_OPTIMIZE
#pragma clang optimize off
#endif
void xmss_zeroize(void * const ptr, const size_t size)
{
    /*
     * We need to ensure that the memset call in this function cannot be optimized away. For GCC and Clang, we use
     * pragmas to disable optimization for this function, because these compilers are our primary target and this
     * approach can not be defeated by future improvements to their optimization techniques.
     *
     * To have a solution that works on almost all compilers, we access memset through a volatile pointer memset_p.
     * Because it is volatile, the compiler is not allowed to assume that it still points to memset.
     *
     * It is still technically allowed to optimize the function call below to
     *
     *     if (memset_p != memset) {
     *         memset_p(ptr, 0, size);
     *     }
     *
     * so the standard does not guarantee that this works.
     *
     * See also:
     * https://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html
     * https://www.daemonology.net/blog/2014-09-05-erratum.html
     * https://www.daemonology.net/blog/2014-09-06-zeroing-buffers-is-insufficient.html
     */
    memset_p(ptr, 0, size);
}

#if XMSS_CAN_USE_PRAGMA_OPTIMIZE
#pragma optimize("", on)
#endif

#if XMSS_CAN_USE_PRAGMA_GCC_OPTIMIZE
#pragma GCC pop_options
#endif

#if XMSS_CAN_USE_PRAGMA_CLANG_OPTIMIZE
#pragma clang optimize off
#endif
