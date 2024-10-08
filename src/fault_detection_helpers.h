/*
 * SPDX-FileCopyrightText: 2024 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Max Fillinger
 */

/**
 * @file
 * @brief
 * Helper macros to detect accidental or induced faults.
 */

#pragma once

#ifndef XMSS_FAULT_DETECTION_HELPERS_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_FAULT_DETECTION_HELPERS_H_INCLUDED

/**
 * @brief
 * Make the function that uses the macro return return_value if condition is true.
 *
 * @details
 * The condition is checked twice to ensure that a fault cannot cause the return to be skipped. To ensure that the
 * compiler cannot optimize the second if-statement away, the condition should involve a volatile variable.
 *
 * @param[in] condition     The condition to check, should involve a volatile variable.
 * @param[in] return_value  Value for the function to return if the condition is true.
 */
#define REDUNDANT_RETURN_IF(condition, return_value) \
    {                                                \
        if (condition) {                             \
            return return_value;                     \
        }                                            \
        if (condition) {                             \
            return return_value;                     \
        }                                            \
    }

/**
 * @brief
 * This macro checks if result is XMSS_OKAY. If not, it makes the function that uses the macro return result.
 *
 * @details
 * This macro checks result multiple times for fault resilience. To make sure that the compiler cannot optimize
 * away the redundant checks, result should be a volatile variable. If a fault causes the program to end up in the
 * result != XMSS_OKAY arm when actually result == XMSS_OKAY, or when the first if-statement is skipped even though
 * result != XMSS_OKAY, XMSS_ERR_FAULT_DETECTED is returned.
 *
 * @param[in] result    XmssError to check. Must be stored in a volatile variable.
*/
#define REDUNDANT_RETURN_ERR(result)                \
    {                                               \
        if ((result) != XMSS_OKAY) {                \
            if ((result) == XMSS_OKAY) {            \
                return XMSS_ERR_FAULT_DETECTED;     \
            }                                       \
            return result;                          \
        }                                           \
        if ((result) != XMSS_OKAY) {                \
            return XMSS_ERR_FAULT_DETECTED;         \
        }                                           \
    }

#endif /* !XMSS_FAULT_DETECTION_HELPERS_H_INCLUDED */
