/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#pragma once

#ifndef XMSS_TEST_BUILD_TYPE_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_TEST_BUILD_TYPE_H_INCLUDED

#include <stdbool.h>

/**
 * @brief
 * Runtime check to see whether NDEBUG was defined at compile time.
 *
 * @returns true if and only if NDEBUG was defined.
 */
bool test_NDEBUG_defined(void);

/**
 * @brief
 * Runtime check to see whether assert() was enabled at compile time.
 *
 * @returns true if and only if assert() was enabled.
 */
bool test_assert_enabled(void);

#endif /* !XMSS_TEST_BUILD_TYPE_H_INCLUDED */
