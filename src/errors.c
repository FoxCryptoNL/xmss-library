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

#include "errors.h"

const char *xmss_error_to_name(const XmssError error)
{
    switch (error) {
        case XMSS_OKAY:
            return "XMSS_OKAY";
        case XMSS_ERR_NULL_POINTER:
            return "XMSS_ERR_NULL_POINTER";
        case XMSS_ERR_INVALID_SIGNATURE:
            return "XMSS_ERR_INVALID_SIGNATURE";
        case XMSS_ERR_ARGUMENT_MISMATCH:
            return "XMSS_ERR_ARGUMENT_MISMATCH";
        case XMSS_ERR_ALLOC_ERROR:
            return "XMSS_ERR_ALLOC_ERROR";
        case XMSS_ERR_INVALID_BLOB:
            return "XMSS_ERR_INVALID_BLOB";
        case XMSS_ERR_BAD_CONTEXT:
            return "XMSS_ERR_BAD_CONTEXT";
        case XMSS_ERR_INVALID_ARGUMENT:
            return "XMSS_ERR_INVALID_ARGUMENT";
        case XMSS_ERR_PARTITION_DONE:
            return "XMSS_ERR_PARTITION_DONE";
        case XMSS_ERR_UNFINISHED_PARTITIONS:
            return "XMSS_ERR_UNFINISHED_PARTITIONS";
        case XMSS_ERR_TOO_FEW_SIGNATURES_AVAILABLE:
            return "XMSS_ERR_TOO_FEW_SIGNATURES_AVAILABLE";
        case XMSS_ERR_PARTITIONS_NOT_CONSECUTIVE:
            return "XMSS_ERR_PARTITIONS_NOT_CONSECUTIVE";
        case XMSS_ERR_NO_PUBLIC_KEY:
            return "XMSS_ERR_NO_PUBLIC_KEY";
        case XMSS_ERR_FAULT_DETECTED:
            return "XMSS_ERR_FAULT_DETECTED";
        case XMSS_UNINITIALIZED:
            return "XMSS_UNINITIALIZED";
        default:
            return "XmssError_Undefined";
    }
}

const char *xmss_error_to_description(const XmssError error)
{
    /* NOTE to developers
     * ==================
     *
     * Keep the returned strings synchronized with the Doxygen descriptions for the XmssError enum values.
     */

    switch (error) {
        case XMSS_OKAY:
            return "Success";
        case XMSS_ERR_NULL_POINTER:
            return "An unexpected NULL pointer was passed";
        case XMSS_ERR_INVALID_SIGNATURE:
            return "The signature is invalid";
        case XMSS_ERR_ARGUMENT_MISMATCH:
            return "A mismatch was detected between arguments";
        case XMSS_ERR_ALLOC_ERROR:
            return "An error occurred with memory allocation";
        case XMSS_ERR_INVALID_BLOB:
            return "A blob structure was found to be invalid";
        case XMSS_ERR_BAD_CONTEXT:
            return "The passed context is in an incorrect state";
        case XMSS_ERR_INVALID_ARGUMENT:
            return "The value of an argument was invalid";
        case XMSS_ERR_PARTITION_DONE:
            return "The calculations for the key generation partition were already performed";
        case XMSS_ERR_UNFINISHED_PARTITIONS:
            return "Not all key generation partition calculations were completed";
        case XMSS_ERR_TOO_FEW_SIGNATURES_AVAILABLE:
            return "There are not enough signatures available to allow the operation";
        case XMSS_ERR_PARTITIONS_NOT_CONSECUTIVE:
            return "Partitions are not consecutive";
        case XMSS_ERR_NO_PUBLIC_KEY:
            return "The key context does not have a public key loaded";
        case XMSS_ERR_FAULT_DETECTED:
            return "A fault was detected";
        case XMSS_UNINITIALIZED:
            return "Function returned prematurely";
        default:
            return "Invalid error code";
    }
}
