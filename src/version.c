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
 */

#include "version.h"

uint32_t xmss_library_get_version(void)
{
    return XMSS_LIBRARY_VERSION;
}
