/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Max Fillinger
 */

/**
 * @file
 * @brief
 * WOTS+ verification.
 */

#include <assert.h>
#include <stdint.h>

#include "wotsp_verification.h"

#include "fault_detection_helpers.h"
#include "utils.h"
#include "types.h"
#include "wotsp_private.h"
#include "xmss_hashes.h"


XmssError wotsp_calculate_expected_public_key(HASH_FUNCTIONS_PARAMETER WotspPublicKey *const expected_public_key,
    const XmssNativeValue256 *const message_digest, const WotspSignature *const signature,
    const XmssNativeValue256 *const public_seed, const uint32_t ots_address)
{
    /*
     * Variables related to fault detection, not part of the algorithm.
     */
    volatile XmssError result = XMSS_UNINITIALIZED;
    uint_fast8_t chain_steps = 0;
    volatile uint_fast16_t expected_total_chain_steps = 0;
    volatile uint_fast16_t total_chain_steps = 0;
    volatile uint_fast16_t redundant_csum = LEN_1 * (W - 1);
    volatile uint_fast8_t redundant_msg_i = 0;

    /*
     * Unlike in RFC-8391, Algorithm 6, we don't calculate the entire base-W representation of the message digest ahead
     * of time. Instead, we generate these values when they are needed and reserve space for them here.
     */
    uint_fast8_t msg_i = 0;
    /*
     * In RFC-8391, Algorithm 6, the checksum csum starts at 0 and for every base-W digit msg[i] of the message digest,
     * W - 1 - msg[i] is added. It is equivalent to start with LEN_1 * (W - 1) and subtract each msg[i].
     */
    uint_fast16_t csum = LEN_1 * (W - 1);
    /*
     * Prepare the Input_PRF struct. This part does not correspond to anything in RFC-8391, Algorithm 6. Input_PRF is a
     * struct that holds SEED and ADRS for chain().
     */
    Input_PRF input_prf = INIT_INPUT_PRF;
    prepare_input_prf_for_chain(&input_prf, public_seed, ots_address);

    /*
     * Process the message digest. This combines the loop for calculating the checksum and the first LEN_1 iterations
     * of the final loop in RFC-8391, Algorithm 6.
     */
    for (uint32_t i = 0; i < LEN_1; i++) {
        chain_steps = 0;
        msg_i = get_msg_i(message_digest, i);
        csum -= msg_i;
        input_prf.M.ADRS.typed.OTS_Hash_Address.chain_address = i;
        chain_steps = chain(HASH_FUNCTIONS &expected_public_key->hashes[i], &input_prf, &signature->hashes[i],
            (uint32_t)msg_i, W - 1 - msg_i);

        /*
         * Fault detection: Check that the number of steps performed in chain() is as expected. Recalculate msg_i to
         * also protect against bit flips in this variable.
         *
         * This is not part of the algorithm but a countermeasure against fault injection attacks.
         */
        redundant_msg_i = get_msg_i(message_digest, i);
        redundant_csum -= redundant_msg_i;
        REDUNDANT_RETURN_IF(chain_steps != W - 1 - redundant_msg_i, XMSS_ERR_FAULT_DETECTED);
        total_chain_steps += chain_steps;
    }

    /*
     * Fault detection: Verify the checksum.
     *
     * This is not part of the algorithm but a countermeasure against fault injection attacks.
     */
    REDUNDANT_RETURN_IF(csum != redundant_csum, XMSS_ERR_FAULT_DETECTED);

    /*
     * Process the checksum. This corresponds to the last LEN_2 iterations of the final loop in RFC-8391, Algorithm 6.
     * Note that the bit shift of csum in Algorithm 6 is used only to line it up with the toByte function. The result is
     * the base-W digits of csum in big-endian order, which we calculate in a different way, using the fact that W = 16.
     */
    assert(csum <= 960);
    for (uint32_t i = LEN_1; i < LEN; i++) {
        chain_steps = 0;
        msg_i = (uint_fast8_t)(csum >> CSUM_BITSHIFT(i)) & 0x0f;
        input_prf.M.ADRS.typed.OTS_Hash_Address.chain_address = i;
        chain_steps = chain(HASH_FUNCTIONS &expected_public_key->hashes[i], &input_prf, &signature->hashes[i],
            (uint32_t)msg_i, W - 1 - msg_i);

        /*
         * Fault detection: Check that the number of steps performed in chain() is as expected. Recalculate msg_i to
         * also protect against bit flips in this variable.
         *
         * This is not part of the algorithm but a countermeasure against fault injection attacks.
         */
        redundant_msg_i = (uint_fast8_t)(redundant_csum >> CSUM_BITSHIFT(i)) & 0x0f;
        REDUNDANT_RETURN_IF(chain_steps != W - 1 - redundant_msg_i, XMSS_ERR_FAULT_DETECTED);
        total_chain_steps += chain_steps;
    }

    /*
     * Fault detection: Check that the total number of chain steps is as expected.
     * We can derive the expected number of chain steps from csum: By definition, csum is the total number of chain
     * steps during the message portion. The csum portion adds LEN_2 * (W - 1) minus the hex digits of csum.
     * We mix in both csum and redundant_csum in this calculation.
     *
     * This is not part of the algorithm but a countermeasure against fault injection attacks.
     */
    expected_total_chain_steps = redundant_csum + LEN_2 * (W - 1) - ((csum >> CSUM_BITSHIFT(LEN_1)) & 0x0f)
                                                                  - ((csum >> CSUM_BITSHIFT(LEN_1 + 1)) & 0x0f)
                                                                  - ((csum >> CSUM_BITSHIFT(LEN_1 + 2)) & 0x0f);
    REDUNDANT_RETURN_IF(total_chain_steps != expected_total_chain_steps, XMSS_ERR_FAULT_DETECTED);
    result = XMSS_OKAY;
    return result;
}
