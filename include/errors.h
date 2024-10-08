/*
 * SPDX-FileCopyrightText: 2024 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Thomas Schaap
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * Public API for XMSS error handling.
 */

#pragma once

#ifndef XMSS_ERRORS_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_ERRORS_H_INCLUDED

#include <types.h>


/**
 * Translate an XMSS error to the string with the enumeration-constant name.
 *
 * @details
 * As an example, `xmss_error_to_name(XMSS_OKAY)` returns `"XMSS_OKAY"`.
 *
 * @remark
 * This function returns `"XmssError_Undefined"` for values of `error` that are not defined in #XmssError.
 *
 * @param[in]   error   The error to translate.
 *
 * @returns A pointer to a static string with the enumeration-constant name corresponding to `error`.
 */
const char *xmss_error_to_name(XmssError error);


/**
 * Translate an XMSS error to a human-readable message.
 *
 * @param[in]   error   The error to translate.
 *
 * @returns A pointer to a static string with a message corresponding to `error`.
 */
const char *xmss_error_to_description(XmssError error);


#endif /* !XMSS_ERRORS_H_INCLUDED */
