/*
 * SPDX-FileCopyrightText: 2022 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 */

/**
 * @file
 * @brief
 * C99 compatibility layer.
 *
 * @details
 * There is no need to include this header explicitly. Instead, include either verification.h or signing.h.
 *
 * The XMSS library is compatible with C99 compilers, but it also allows certain C11 features if they are available
 * for the compiler at hand. This header ensures that the code does not get cluttered with preprocessor `#if`s.
 * You can simply use the compatibility macros defined here, which will automatically either use the C11 feature
 * (when available) or become a no-op (when not available).
 */

#pragma once

#ifndef XMSS_COMPAT_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_COMPAT_H_INCLUDED

#include "xmss_config.h"

/**
 * @brief
 * Syntactical equivalent of `_Static_assert()`, which is C11.
 *
 * @details
 * C11 supports `_Static_assert()`. CMake can detect if it is available anyway, even if the compiler is not C11.
 * If CMake detects that static asserts are not supported, then this macro is a no-op.
 *
 * @see XMSS_CAN_USE_STATIC_ASSERT
 * @see XMSS_CAN_USE_EXTENSION_STATIC_ASSERT
 */
#if (__STDC_VERSION__ >= 201112L) || XMSS_CAN_USE_STATIC_ASSERT || defined(DOXYGEN)
#   define XMSS_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#elif XMSS_CAN_USE_EXTENSION_STATIC_ASSERT
#   define XMSS_STATIC_ASSERT(cond, msg) __extension__ _Static_assert(cond, msg)
#else
#   define XMSS_STATIC_ASSERT(cond, msg) struct xmss_static_assert_unsupported
#endif

#endif /* !XMSS_COMPAT_H_INCLUDED */
