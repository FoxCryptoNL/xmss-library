/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * The configurable CMake options that affect the internal parts of the library.
 *
 * @details
 * For convenience, this header includes xmss_config.h (the public part of the configurable options) even though
 * this header itself does not use it. Internal sources can simply include this file and get all options at once.
 */

#pragma once

#ifndef XMSS_CONFIG_H
/** @private @brief Include guard. */
#define XMSS_CONFIG_H

#include "xmss_config.h"

/**
 * @brief
 * Indicates whether SHA-256 support is enabled.
 *
 * @details
 * By default, SHA-256 is enabled. This macro is defined with the value 0 if you compile the library with
 * ```
 * cmake -DXMSS_SHA256=Disabled
 * ```
 */
#cmakedefine01 XMSS_ENABLE_SHA256

/**
 * @brief
 * Indicates whether the SHA-256 default implementation is enabled.
 *
 * @details
 * This macro is defined with the value 0 if you compile the library with
 * ```
 * cmake -DXMSS_SHA256={Disabled | OverrideInternal | OverrideGeneric}
 * ```
 */
#cmakedefine01 XMSS_ENABLE_SHA256_DEFAULT

/**
 * @brief
 * Indicates whether SHA-256 uses the generic interface.
 *
 * @details
 * By default, SHA-256 uses the internal interface.
 * This macro is defined with the value 1 if you compile the library with
 * ```
 * cmake -DXMSS_SHA256=OverrideGeneric
 * ```
 */
#cmakedefine01 XMSS_ENABLE_SHA256_GENERIC

/**
 * @brief
 * Indicates whether SHAKE256/256 support is enabled.
 *
 * @details
 * By default, SHAKE256/256 is enabled. This macro is defined with the value 0 if you compile the library with
 * ```
 * cmake -DXMSS_SHAKE256_256=Disabled
 * ```
 */
#cmakedefine01 XMSS_ENABLE_SHAKE256_256

/**
 * @brief
 * Indicates whether the SHAKE256/256 default implementation is enabled.
 *
 * @details
 * This macro is defined with the value 0 if you compile the library with
 * ```
 * cmake -DXMSS_SHAKE256_256={Disabled | OverrideInternal | OverrideGeneric}
 * ```
 */
#cmakedefine01 XMSS_ENABLE_SHAKE256_256_DEFAULT

/**
 * @brief
 * Indicates whether SHAKE256/256 uses the generic interface.
 *
 * @details
 * By default, SHAKE256/256 uses the internal interface.
 * This macro is defined with the value 1 if you compile the library with
 * ```
 * cmake -DXMSS_SHAKE256_256=OverrideGeneric
 * ```
 */
#cmakedefine01 XMSS_ENABLE_SHAKE256_256_GENERIC

/**
 * @brief
 * Indicates whether the compiler supports `#pragma optimize`.
 *
 * @details
 * This option is automatically detected by CMake.
 */
#cmakedefine01 XMSS_CAN_USE_PRAGMA_OPTIMIZE

/**
 * @brief
 * Indicates whether the compiler supports `#pragma GCC optimize`.
 *
 * @details
 * This option is automatically detected by CMake.
 */
#cmakedefine01 XMSS_CAN_USE_PRAGMA_GCC_OPTIMIZE

/**
 * @brief
 * Indicates whether the compiler supports `#pragma clang optimize`.
 *
 * @details
 * This option is automatically detected by CMake.
 */
#cmakedefine01 XMSS_CAN_USE_PRAGMA_CLANG_OPTIMIZE

/**
 * @brief
 * Indicates whether both SHA-256 and SHAKE256/256 are enabled.
 *
 * @details
 * By default, both hash algorithms are enabled.
 * This macro is defined with the value 0 if either one of the hash algorithms is disabled.
 * @see XMSS_ENABLE_SHA256
 * @see XMSS_ENABLE_SHAKE256_256
 */
#if XMSS_ENABLE_SHA256 && XMSS_ENABLE_SHAKE256_256
#   define XMSS_ENABLE_HASH_ABSTRACTION 1
#else
#   define XMSS_ENABLE_HASH_ABSTRACTION 0
#endif

/**
 * @brief
 * Allows compilation of otherwise empty translation units.
 *
 * @details
 * Some source files include this file and, as a result of `#if`s based on configuration options defined here, end up
 * empty. C99 does not allow empty translation units. This typedef makes such source files officially non-empty
 * (even though it does not generate anything) and allows them to compile correctly.
 */
typedef int xmss_prevent_empty_translation_unit;

#endif /* !XMSS_CONFIG_H */
