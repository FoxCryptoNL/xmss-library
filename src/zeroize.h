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

#pragma once

#ifndef XMSS_ZEROIZE_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_ZEROIZE_H_INCLUDED

#include <stddef.h>

#include "libxmss.h"

/**
 * @copydoc XmssZeroizeFunction
 * @see XmssZeroizeFunction
 *
 * @details
 * In pure C99, there is no way to implement a zeroize function that cannot be optimized away. This implementation is a
 * best-effort solution that is known to work on almost all compilers.
 */
LIBXMSS_STATIC
void xmss_zeroize(void * const ptr, const size_t size);

#endif /* !XMSS_ZEROIZE_H_INCLUDED */
