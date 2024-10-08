/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * Helpers to hide symbols in the resulting library with external linkage that are not part of the public API.
 *
 * @details
 * These are implementation details that should *not* be considered stable.
 */

#pragma once

#ifndef XMSS_LIBXMSS_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_LIBXMSS_H_INCLUDED

#if !defined(LIBXMSS) || !LIBXMSS
#   undef LIBXMSS
    /**
     * @brief
     * When compiling the amalgamated library (libxmss.c), this macro is defined as 1 (true); it is 0 (false) otherwise.
     */
#   define LIBXMSS 0
    /**
     * @brief
     * Helper macro to hide symbols with external linkage that are not part of the public API.
     *
     * @details
     * When compiling the amalgamated library (libxmss.c), this macro is defined as `static`, such that library
     * internals do not end up as external symbols.
     */
#   define LIBXMSS_STATIC
#else
#   undef LIBXMSS
#   define LIBXMSS 1
#   define LIBXMSS_STATIC static
#endif

#endif /* !XMSS_LIBXMSS_H_INCLUDED */
