/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * The configurable CMake options that affect the public API.
 *
 * @details
 * There is no need to include this header explicitly. Instead, include either verification.h or signing.h.
 */

#pragma once

#ifndef XMSS_XMSS_CONFIG_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_XMSS_CONFIG_H_INCLUDED

/**
 * @brief
 * Indicates whether the compiler supports `_Static_assert()`.
 *
 * @details
 * This option is automatically detected by CMake.
 *
 * @see STATIC_ASSERT
 */
#cmakedefine01 XMSS_CAN_USE_STATIC_ASSERT

/**
 * @brief
 * Indicates whether the compiler supports `__extension__ _Static_assert()`.
 *
 * @details
 * This option is automatically detected by CMake.
 *
 * @see STATIC_ASSERT
 */
#cmakedefine01 XMSS_CAN_USE_EXTENSION_STATIC_ASSERT

#endif /* !XMSS_XMSS_CONFIG_H_INCLUDED */
