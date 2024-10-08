/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Max Fillinger
 */

/**
 * @file
 * @brief
 * WOTS+ signatures.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "config.h"
#include "wotsp_signing.h"

#include "fault_detection_helpers.h"
#include "signing_private.h"
#include "utils.h"
#include "wotsp_private.h"
#include "xmss_hashes.h"

/**
 * @brief
 * Prepare input_prfkeygen for generating the WOTS+ private key.
 *
 * @param[out] input_prfkeygen  The input_prf struct to fill. It is assumed to be initialized with INIT_INPUT_PRF.
 * @param[in]  secret_seed      Secret seed for PRFkeygen.
 * @param[in]  public_seed      Public seed for PRFkeygen.
 * @param[in]  ots_address      Index of the OTS key pair in the larger XMSS scheme.
 */
inline static void prepare_input_prfkeygen(Input_PRFkeygen *const input_prfkeygen,
    const XmssNativeValue256 *const secret_seed, const XmssNativeValue256 *const public_seed,
    const uint32_t ots_address)
{
    input_prfkeygen->S_XMSS = *secret_seed;
    input_prfkeygen->SEED = *public_seed;
    input_prfkeygen->ADRS.type = ADRS_type_OTS_Hash_Address;
    input_prfkeygen->ADRS.typed.OTS_Hash_Address.OTS_address = ots_address;
}

/**
 * @brief
 * Get the ith 256-bit block of the secret key, in native byte order.
 *
 * @details
 * Conceptually, this corresponds to accessing sk[i] in the WOTS+ public key generation and signing algorithms in
 * RFC-8391 (Algorithms 4 and 5). However, we do not keep the entire secret key in memory and instead calculate the
 * required part with PRFkeygen. See NIST SP 800-208, Algorithm 10' for the inputs to PRFkeygen.
 *
 * @param[in]     hash_functions    The hash functions to use.
 * @param[out]    sk_i              Place to store the secret key block.
 * @param[in,out] input_prfkeygen   Input_PRFkeygen containing the seeds and ADRS for generating the secret key.
 *                                  This function sets the chain_address in ADRS to i.
 * @param[in]     i                 Index of the secret key block to generate.
 */
inline static void get_sk_i(HASH_FUNCTIONS_PARAMETER XmssNativeValue256 *const sk_i,
    Input_PRFkeygen *const input_prfkeygen, const uint32_t i)
{
    input_prfkeygen->ADRS.typed.OTS_Hash_Address.chain_address = i;
    xmss_PRFkeygen(HASH_FUNCTIONS sk_i, input_prfkeygen);
}

void wotsp_gen_public_key(const XmssSigningContext *const context, WotspPublicKey *const public_key,
    const XmssNativeValue256 *const secret_seed, const XmssNativeValue256 *const public_seed,
    const uint32_t ots_address)
{
    /*
     * Unlike in RFC-8391, Algorithm 4, we don't have the entire secret key sk ahead of time. Instead, we generate the
     * blocks sk[i] of the secret key as they are needed. Here, we reserve the space to store one 256-bit block of it.
     * We leave it uninitialized for performance reasons.
     */
    XmssNativeValue256 sk_i;
    /*
     * Prepare the Input_PRF and Input_PRFkeygen structs. This part does not correspond to anything in RFC-8391,
     * Algorithm 4. Input_PRFkeygen is needed to generate the secret key blocks. Input_PRF is a struct that holds SEED
     * and ADRS for chain().
     */
    Input_PRFkeygen input_prfkeygen = INIT_INPUT_PRFKEYGEN;
    Input_PRF input_prf = INIT_INPUT_PRF;
    prepare_input_prfkeygen(&input_prfkeygen, secret_seed, public_seed, ots_address);
    prepare_input_prf_for_chain(&input_prf, public_seed, ots_address);

    for (uint32_t i = 0; i < LEN; i++) {
        /* Get the next block sk[i] of the secret key. */
        get_sk_i(HASH_FUNCTIONS_FROM(*context) &sk_i, &input_prfkeygen, i);

        /* Run W - 1 = 15 steps of the chain function on sk[i]. The result is pk[i] in RFC-8391, Algorithm 4. */
        input_prf.M.ADRS.typed.OTS_Hash_Address.chain_address = i;
        (void)chain(HASH_FUNCTIONS_FROM(*context) &public_key->hashes[i], &input_prf, &sk_i, 0, W - 1);
    }

    context->zeroize(&input_prfkeygen.S_XMSS, sizeof(input_prfkeygen.S_XMSS));
    context->zeroize(&sk_i, sizeof(sk_i));
}

XmssError wotsp_sign(const XmssSigningContext *const context, WotspSignature *const signature,
    const XmssNativeValue256 *const message_digest, const XmssNativeValue256 *const secret_seed,
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
     * Unlike in RFC-8391, Algorithm 5, we don't calculate the entire secret key sk and base-W representation of the
     * input msg ahead of time. Instead, we generate these values when they are needed and reserve space for them here.
     * We leave sk_i uninitialized for performance reasons.
     */
    XmssNativeValue256 sk_i;
    uint_fast8_t msg_i = 0;
    /*
     * In RFC-8391, Algorithm 5, the checksum csum starts at 0 and for every base-W digit msg[i] of the input,
     * W - 1 - msg[i] is added. It is equivalent to start with LEN_1 * (W - 1) and subtract each msg[i].
     */
    uint_fast16_t csum = LEN_1 * (W - 1);
    /*
     * Prepare the Input_PRF and Input_PRFkeygen structs. This part does not correspond to anything in RFC-8391,
     * Algorithm 5. Input_PRFkeygen is needed to generate the secret key blocks. Input_PRF is a struct that holds SEED
     * and ADRS for chain().
     */
    Input_PRFkeygen input_prfkeygen = INIT_INPUT_PRFKEYGEN;
    Input_PRF input_prf = INIT_INPUT_PRF;
    prepare_input_prfkeygen(&input_prfkeygen, secret_seed, public_seed, ots_address);
    prepare_input_prf_for_chain(&input_prf, public_seed, ots_address);

    /*
     * Process the message digest. This combines the loop for calculating the checksum and the first LEN_1 iterations
     * of the final loop in RFC-8391, Algorithm 5.
     */
    for (uint32_t i = 0; i < LEN_1; i++) {
        msg_i = get_msg_i(message_digest, i);
        get_sk_i(HASH_FUNCTIONS_FROM(*context) &sk_i, &input_prfkeygen, i);
        csum -= msg_i;

        /* Run msg[i] steps of the chain function on sk[i] as input. The result is sig[i] in RFC-8391, Algorithm 5. */
        input_prf.M.ADRS.typed.OTS_Hash_Address.chain_address = i;
        chain_steps = chain(HASH_FUNCTIONS_FROM(*context) &signature->hashes[i], &input_prf, &sk_i, 0, msg_i);

        /*
         * Fault detection: Check that the number of steps performed in chain() is as expected. Recalculate msg_i to
         * also protect against bit flips in this variable.
         *
         * This is not part of the algorithm but a countermeasure against fault injection attacks.
         */
        redundant_msg_i = get_msg_i(message_digest, i);
        redundant_csum -= redundant_msg_i;
        REDUNDANT_RETURN_IF(chain_steps != redundant_msg_i, XMSS_ERR_FAULT_DETECTED);
        total_chain_steps += chain_steps;
    }

    /*
     * Fault detection: Verify the checksum.
     *
     * This is not part of the algorithm but a countermeasure against fault injection attacks.
     */
    REDUNDANT_RETURN_IF(csum != redundant_csum, XMSS_ERR_FAULT_DETECTED);

    /*
     * Process the checksum. This corresponds to the last LEN_2 iterations of the final loop in RFC-8391, Algorithm 5.
     * Note that the bit shift of csum in Algorithm 5 is used only to line it up with the toByte function. The result is
     * the base-W digits of csum in big-endian order, which we calculate in a different way, using the fact that W = 16.
     */
    assert(csum <= 960);
    for (uint32_t i = LEN_1; i < LEN; i++) {
        msg_i = (uint_fast8_t)(csum >> CSUM_BITSHIFT(i)) & 0x0f;
        get_sk_i(HASH_FUNCTIONS_FROM(*context) &sk_i, &input_prfkeygen, i);

        input_prf.M.ADRS.typed.OTS_Hash_Address.chain_address = i;
        chain_steps = chain(HASH_FUNCTIONS_FROM(*context) &signature->hashes[i], &input_prf, &sk_i, 0, msg_i);

        /*
         * Fault detection: Check that the number of steps performed in chain() is as expected. Recalculate msg_i to
         * also protect against bit flips in this variable.
         *
         * This is not part of the algorithm but a countermeasure against fault injection attacks.
         */
        redundant_msg_i = (uint_fast8_t)(csum >> CSUM_BITSHIFT(i)) & 0x0f;
        REDUNDANT_RETURN_IF(chain_steps != redundant_msg_i, XMSS_ERR_FAULT_DETECTED);
        total_chain_steps += chain_steps;
    }

    /* Zeroize the secret seed stored in input_prfkeygen, and the secret key block that is still in memory. */
    context->zeroize(&input_prfkeygen.S_XMSS, sizeof(input_prfkeygen.S_XMSS));
    context->zeroize(&sk_i, sizeof(sk_i));

    /*
     * Fault detection: Check that the total number of chain steps is as expected.
     * The expected number of steps can be derived from csum: Because csum = LEN_1 * (W - 1) - sum_i(msg_i), the total
     * number of chain steps during the message portion is LEN_1 * (W-1) - csum. The checksum portion adds the hex
     * digits of csum to this total. We mix in both csum and redundant_csum in this calculation.
     *
     * This is not part of the algorithm but a countermeasure against fault injection attacks.
     */
    expected_total_chain_steps = LEN_1 * (W - 1) - redundant_csum + ((csum >> CSUM_BITSHIFT(LEN_1)) & 0x0f)
                                                                  + ((csum >> CSUM_BITSHIFT(LEN_1 + 1)) & 0x0f)
                                                                  + ((csum >> CSUM_BITSHIFT(LEN_1 + 2)) & 0x0f);
    REDUNDANT_RETURN_IF(total_chain_steps != expected_total_chain_steps, XMSS_ERR_FAULT_DETECTED);
    result = XMSS_OKAY;
    return result;
}
