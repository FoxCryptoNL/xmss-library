/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Max Fillinger
 */

/**
 * @file
 * @brief
 * WOTS+ common functionality.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "wotsp.h"

#include "utils.h"
#include "wotsp_private.h"
#include "xmss_hashes.h"


uint_fast8_t chain(HASH_FUNCTIONS_PARAMETER XmssNativeValue256 *const output, Input_PRF *input_prf,
    const XmssNativeValue256 *const input, const uint32_t start_index, const uint_fast8_t num_steps)
{
    /*
     * Prepare the Input_F struct. This does not correspond to anything in RFC-8391, Algorithm 2. It is a struct to
     * place the inputs for the hash function F.
     */
    Input_F input_f = INIT_INPUT_F;
    volatile uint_fast8_t chain_steps_done = 0;
    input_prf->M.ADRS.typed.OTS_Hash_Address.hash_address = start_index;

    assert(start_index + num_steps < W);

    /*
     * We use output to store the intermediate values for the chain computation.
     * The final "intermediate" value will be the actual output.
     */
    *output = *input;

    for (chain_steps_done = 0; chain_steps_done < num_steps; chain_steps_done++) {
        /* Get the key for the next F call and place it in input_f. */
        input_prf->M.ADRS.typed.OTS_Hash_Address.keyAndMask = 0;
        xmss_PRF(HASH_FUNCTIONS &input_f.KEY, input_prf);
        /*
         * The next input message for F is the output of the previous call to F XORed with a bitmask from PRF.
         * We provide the message part of input_f as an output buffer to PRF to place the bitmask there, and then XOR
         * the output from the previous call to F (which is in output) into it.
         */
        input_prf->M.ADRS.typed.OTS_Hash_Address.keyAndMask = 1;
        xmss_PRF(HASH_FUNCTIONS &input_f.M, input_prf);
        for (uint_fast8_t j = 0; j < XMSS_VALUE_256_WORDS; j++) {
            input_f.M.data[j] ^= output->data[j];
        }

        /* Calculate the next value in the chain and put it in native_digest. */
        xmss_F(HASH_FUNCTIONS output, &input_f);

        input_prf->M.ADRS.typed.OTS_Hash_Address.hash_address += 1;
    }

    return chain_steps_done;
}
