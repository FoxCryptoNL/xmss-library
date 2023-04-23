/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#pragma once

#ifndef XMSS_TEST_XMSS_HASHES_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_TEST_XMSS_HASHES_H_INCLUDED

#include "config.h"

#if XMSS_ENABLE_HASH_ABSTRACTION

#   include "xmss_hashes.h"

extern const xmss_hashes *const test_xmss_hashes;

#endif

#endif /* !XMSS_TEST_XMSS_HASHES_H_INCLUDED */
