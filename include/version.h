/*
 * SPDX-FileCopyrightText: 2024 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * Public API for XMSS library version control.
 *
 * The macros and functions are currently all prefixed with `XMSS_LIBRARY_` and `xmss_library_` as currently only the
 * library implementation is versioned, not the XMSS algorithm itself.
 */

#pragma once

#ifndef XMSS_VERSION_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_VERSION_H_INCLUDED

#include "xmss_config.h"

#include <stdint.h>

#include "compat.h"

/** @private */
XMSS_STATIC_ASSERT(XMSS_LIBRARY_VERSION_MAJOR >= 1 && XMSS_LIBRARY_VERSION_MAJOR <= 255,
    "XMSS_LIBRARY_VERSION inconsistent");
/** @private */
XMSS_STATIC_ASSERT(XMSS_LIBRARY_VERSION_MINOR >= 0 && XMSS_LIBRARY_VERSION_MINOR <= 255,
    "XMSS_LIBRARY_VERSION inconsistent");
/** @private */
XMSS_STATIC_ASSERT(XMSS_LIBRARY_VERSION_PATCH >= 0 && XMSS_LIBRARY_VERSION_PATCH <= 255,
    "XMSS_LIBRARY_VERSION inconsistent");

/**
 * @brief
 * Construct an amalgamated semantic version from parts.
 *
 * @details
 * The resulting value may be compared directly against #XMSS_LIBRARY_VERSION (intended for compile-time checks) and/or
 * xmss_library_get_version() (intended for run time checks).
 *
 * @remarks
 * The individual parts will be silently truncated to uint8_t; i.e., their values must be between 0 and 255 (inclusive).
 *
 * @param[in] major The major version.
 * @param[in] minor The minor version.
 * @param[in] patch The patch version.
 * @returns The amalgamated semantic version, as an uint32_t.
 */
#define XMSS_LIBRARY_VERSION_CONSTRUCT(major, minor, patch) \
    ((((uint32_t)(uint8_t)(major)) << 16) \
    | (((uint32_t)(uint8_t)(minor)) << 8) \
    | ((uint32_t)(uint8_t)(patch)))

/**
 * @brief
 * The amalgamated semantic version (SemVer 2.0) of the library headers.
 *
 * @details
 * To verify at compile-time that you are compiling against the expected library version, compare this value against
 * the expected value constructed with #XMSS_LIBRARY_VERSION_CONSTRUCT(). For example:
 *
 * ```
 * static_assert(XMSS_LIBRARY_VERSION == XMSS_LIBRARY_VERSION_CONSTRUCT(1,2,3), "Unexpected library version");
 * ```
 *
 * Alternatively, compare the values of the individual parts. For example:
 *
 * ```
 * static_assert(XMSS_LIBRARY_VERSION_MAJOR == 2, "Unexpected library version");
 * ```
 *
 * @see xmss_library_get_version()
 */
#define XMSS_LIBRARY_VERSION (XMSS_LIBRARY_VERSION_CONSTRUCT(XMSS_LIBRARY_VERSION_MAJOR, XMSS_LIBRARY_VERSION_MINOR, \
    XMSS_LIBRARY_VERSION_PATCH))

/**
 * @brief
 * Retrieve the major version from an amalgamated semantic version.
 *
 * @see #XMSS_LIBRARY_VERSION
 * @see xmss_library_get_version()
 *
 * @param[in] version   An amalgamated semantic version.
 * @returns The major version, as an uint8_t.
 */
#define XMSS_LIBRARY_GET_VERSION_MAJOR(version) ((uint8_t)((((uint32_t)(version)) >> 16) & UINT8_MAX))

/**
 * @brief
 * Retrieve the minor version from an amalgamated semantic version.
 *
 * @see #XMSS_LIBRARY_VERSION
 * @see xmss_library_get_version()
 *
 * @param[in] version   An amalgamated semantic version.
 * @returns The minor version, as an uint8_t.
 */
#define XMSS_LIBRARY_GET_VERSION_MINOR(version) ((uint8_t)((((uint32_t)(version)) >> 8) & UINT8_MAX))

/**
 * @brief
 * Retrieve the patch version from an amalgamated semantic version.
 *
 * @see #XMSS_LIBRARY_VERSION
 * @see xmss_library_get_version()
 *
 * @param[in] version   An amalgamated semantic version.
 * @returns The patch version, as an uint8_t.
 */
#define XMSS_LIBRARY_GET_VERSION_PATCH(version) ((uint8_t)(((uint32_t)(version)) & UINT8_MAX))

/** @private */
XMSS_STATIC_ASSERT(XMSS_LIBRARY_GET_VERSION_MAJOR(XMSS_LIBRARY_VERSION) == XMSS_LIBRARY_VERSION_MAJOR,
    "XMSS_LIBRARY_VERSION inconsistent");
/** @private */
XMSS_STATIC_ASSERT(XMSS_LIBRARY_GET_VERSION_MINOR(XMSS_LIBRARY_VERSION) == XMSS_LIBRARY_VERSION_MINOR,
    "XMSS_LIBRARY_VERSION inconsistent");
/** @private */
XMSS_STATIC_ASSERT(XMSS_LIBRARY_GET_VERSION_PATCH(XMSS_LIBRARY_VERSION) == XMSS_LIBRARY_VERSION_PATCH,
    "XMSS_LIBRARY_VERSION inconsistent");

/**
 * @brief
 * Retrieve, at application runtime, the amalgamated semantic version (SemVer 2.0) of the library at build-time of the
 * library.
 *
 * @details
 * To verify at runtime that you are using the expected (binary) library version, compare this value against the
 * expected value constructed with #XMSS_LIBRARY_VERSION_CONSTRUCT(), or against #XMSS_LIBRARY_VERSION. For example:
 *
 * ```
 * if (xmss_library_get_version() != XMSS_LIBRARY_VERSION) {
 *     // handle library version mismatch
 * }
 * ```
 *
 * Alternatively, compare individual parts using #XMSS_LIBRARY_GET_VERSION_MAJOR(), #XMSS_LIBRARY_GET_VERSION_MINOR(),
 * and/or #XMSS_LIBRARY_GET_VERSION_MINOR(). For example:
 *
 * ```
 * if (XMSS_LIBRARY_GET_VERSION_MAJOR(xmss_library_get_version()) != XMSS_LIBRARY_VERSION_MAJOR)
 * {
 *     // handle library version mismatch
 * }
 * ```
 *
 * @returns The library version.
 */
uint32_t xmss_library_get_version(void);

#endif /* !XMSS_VERSION_H_INCLUDED */
