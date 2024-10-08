/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Max Fillinger
 */

/**
 * @file
 * @brief
 * Common WOTS+ functionality, private for the implementations of both signatures and verification.
 */

#pragma once

#ifndef XMSS_WOTSP_PRIVATE_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_WOTSP_H_INCLUDED

#include <assert.h>
#include <stdint.h>

#include "compat.h"
#include "types.h"


/**
 * @brief
 * Winternitz parameter for WOTS+, set to 16 as specified in RFC-8391, Section 5.3.
 *
 * @details
 * WOTS+ processes the input to be signed in base-W digits. See RFC-8391, Section 3.1.1.
 */
#define W 16
/**
 * @brief
 * The length of the base-W representation of the message digest to sign or verify.
 *
 * @details
 * Since we sign 256-bit message digests, there are 64 digits. See RFC-8391, Section 3.1.1.
 */
#define LEN_1 64
/**
 * @brief
 * The length of the base-W representation of the checksum that is calculated during signing and verification.
 *
 * @details
 * The maximum checksum value is LEN_1 * (W - 1) = 960, which needs 3 base-16 digits to represent.
 * See RFC-8391, Section 3.1.1.
 */
#define LEN_2 3
/**
 * @brief
 * The number of hashes that make up a WOTS+ private key, public key or signature. See RFC-8391, Section 3.1.1.
 */
#define LEN (LEN_1 + LEN_2)

/** @private */
XMSS_STATIC_ASSERT(LEN == XMSS_WOTSP_LEN, "Mismatch in WOTS+ output length.");

/**
 * @brief
 * Amount to shift csum in RFC-8391, Algorithms 5 and 6, to get the base-W digits msg[i] for LEN_1 <= i < LEN.
 */
#define CSUM_BITSHIFT(i) (4 * (LEN_2 - 1 - (i - LEN_1)))

/**
 * @brief
 * Fill input_prf with the values that don't change between calls to chain.
 *
 * @param[out] input_prf    The input_prf struct to fill. It is assumed to be initialized with INIT_INPUT_PRF.
 * @param[in]  seed         Public seed for the PRF.
 * @param[in]  ots_address  Index of the OTS key pair in the larger XMSS scheme.
 */
inline static void prepare_input_prf_for_chain(Input_PRF *const input_prf, const XmssNativeValue256 *const seed,
    const uint32_t ots_address)
{
    input_prf->KEY = *seed;
    input_prf->M.ADRS.type = ADRS_type_OTS_Hash_Address;
    input_prf->M.ADRS.typed.OTS_Hash_Address.OTS_address = ots_address;
}

/**
 * @brief
 * Returns the ith base-W digit in the message-digest, in big-endian byte order.
 *
 * @details
 * Conceptually, this corresponds to accessing msg[i] for i < LEN_1 in the WOTS+ algorithms in RFC-8391, where msg is
 * the base-W representation of the message being signed. Since we use W = 16, each base-W digit is four bits, which
 * makes it easy to calculate the digits on the fly without computing the entire base-W representation ahead of time.
 *
 * @param[in] message_digest    The message digest.
 * @param[in] i                 Index of the four-bit chunk.
 *
 * @returns The ith base-W digit.
 */
inline static uint_fast8_t get_msg_i(const XmssNativeValue256 *const message_digest, const uint32_t i)
{
    assert(i < LEN_1);
    uint_fast8_t shift = (7 - (i % 8)) * 4;
    return (uint_fast8_t)(message_digest->data[i / 8] >> shift) & 0x0f;
}

#endif /* !XMSS_WOTSP_PRIVATE_H_INCLUDED */
