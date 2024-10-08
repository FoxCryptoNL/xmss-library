/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Pepijn Westen
 */

/**
 * @file
 * @brief
 * Atomics compatibility layer.
 */

#pragma once

#ifndef XMSS_COMPAT_STDATOMIC_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_COMPAT_STDATOMIC_H_INCLUDED

#include "config.h"

#if (__STDC_VERSION__ < 201112L) || defined(__STDC_NO_ATOMICS__) || defined(DOXYGEN)
/**
 * @brief
 * No-op macro, in case C11 _Atomic is not supported.
 *
 * @details
 * Atomics did not exist before C11; even in C11 support is optional.
 * When supported, _Atomic is a keyword and no header inclusion is required. However, within the library source code,
 * we require that compat_stdatomic.h is included. Note that we cannot simply define _Atomic itself, as the namespace
 * (underscore) is reserved. Besides, some implementations (e.g., newlib) already define _Atomic in a non-standard way.
 */
#   define ATOMIC
#else
#   define ATOMIC _Atomic
#endif

#if ((__STDC_VERSION__ < 201112L) || defined(__STDC_NO_ATOMICS__)) && !defined(DOXYGEN)
/* Behaves like atomic_compare_exchange_strong, without the atomicity. */
#   define min_sizeof(x, y) ((sizeof(x) < sizeof(y)) ? sizeof(x) : sizeof(y))
#   define atomic_compare_exchange_strong(obj, expected, desired) \
        ((memcmp((obj), (expected), min_sizeof(*(obj), *(expected))) == 0) \
        ? (memcpy((obj), &(desired), sizeof(desired)), (_Bool)1) \
        : (memcpy((expected), (obj), sizeof(*(obj))), (_Bool)0))
#else
    #include <stdatomic.h>
#endif

#endif /* !XMSS_COMPAT_STDATOMIC_H_INCLUDED */
