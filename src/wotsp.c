/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Max Fillinger
 */

/**
 * @file
 * @brief
 * WOTS+ signatures and verification.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "config.h"
#include "wotsp.h"

#include "private.h"
#include "utils.h"
#include "xmss_hashes.h"

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
STATIC_ASSERT(LEN == XMSS_WOTSP_LEN, "Mismatch in WOTS+ output length.");

/**
 * @brief
 * Chaining function for WOTS+ signatures and verification.
 *
 * @details
 * Based on RFC-8391, Section 3.1.2. (Algorithm 2) with the following changes:
 *  - for-loop instead of recursive calls
 *  - instead of SEED and ADRS, pass an Input_PRF struct pre-filled with these values, because most of it does not
 *    change between chain calls within one public key generation, signing or verification process.
 *
 * @param[in]     hashes        The struct with the hash functions to be used.
 * @param[out]    output        Output.
 * @param[in,out] input_prf     Input_PRF struct filled with the PRF seed and ADRS.
 *                              At the end of this function, the values of the hash_address and keyAndMask fields in
 *                              ADRS are unspecified. The Input_PRF can still be used for further calls to chain(),
 *                              since it initializes those fields to the correct values.
 * @param[in]     input         Input. (Corresponds to X in Algorithm 2.)
 * @param[in]     start_index   Starting index for the chain. (Corresponds to i in Algorithm 2.)
 * @param[in]     num_steps     Number of chain steps to perform. (Corresponds to s in Algorithm 2.)
 */
static void chain(HASH_ABSTRACTION(const xmss_hashes *const restrict hashes) XmssNativeValue256 *const restrict output,
    Input_PRF *restrict input_prf, const XmssNativeValue256 *restrict input, const uint32_t start_index,
    const uint_fast8_t num_steps)
{
    /*
     * Prepare the Input_F struct. This does not correspond to anything in RFC-8391, Algorithm 2. It is a struct to
     * place the inputs for the hash function F.
     */
    Input_F input_f = INIT_INPUT_F;
    input_prf->M.ADRS.typed.OTS_Hash_Address.hash_address = start_index;

    assert(start_index + num_steps < W);

    /*
     * We use output to store the intermediate values for the chain computation.
     * The final "intermediate" value will be the actual output.
     */
    native_256_copy(output, input);

    for (uint_fast8_t i = 0; i < num_steps; i++) {
        /* Get the key for the next F call and place it in input_f. */
        input_prf->M.ADRS.typed.OTS_Hash_Address.keyAndMask = 0;
        xmss_PRF(HASH_ABSTRACTION(hashes) &input_f.KEY, input_prf);
        /*
         * The next input message for F is the output of the previous call to F XORed with a bitmask from PRF.
         * We provide the message part of input_f as an output buffer to PRF to place the bitmask there, and then XOR
         * the output from the previous call to F (which is in output) into it.
         */
        input_prf->M.ADRS.typed.OTS_Hash_Address.keyAndMask = 1;
        xmss_PRF(HASH_ABSTRACTION(hashes) &input_f.M, input_prf);
        for (uint_fast8_t j = 0; j < XMSS_VALUE_256_WORDS; j++) {
            input_f.M.data[j] ^= output->data[j];
        }

        /* Calculate the next value in the chain and put it in native_digest. */
        xmss_F(HASH_ABSTRACTION(hashes) output, &input_f);

        input_prf->M.ADRS.typed.OTS_Hash_Address.hash_address += 1;
    }
}

/**
 * @brief
 * Fill input_prf with the values that don't change between calls to chain.
 *
 * @param[out] input_prf    The input_prf struct to fill. It is assumed to be initialized with INIT_INPUT_PRF.
 * @param[in]  seed         Public seed for the PRF.
 * @param[in]  ots_address  Index of the OTS key pair in the larger XMSS scheme.
 */
inline static void prepare_input_prf_for_chain(Input_PRF *const restrict input_prf,
    const XmssNativeValue256 *const restrict seed, const uint32_t ots_address)
{
    native_256_copy(&input_prf->KEY, seed);
    input_prf->M.ADRS.type = ADRS_type_OTS_Hash_Address;
    input_prf->M.ADRS.typed.OTS_Hash_Address.OTS_address = ots_address;
}

/**
 * @brief
 * Prepare input_prfkeygen for generating the WOTS+ private key.
 *
 * @param[out] input_prfkeygen  The input_prf struct to fill. It is assumed to be initialized with INIT_INPUT_PRF.
 * @param[in]  secret_seed      Secret seed for PRFkeygen.
 * @param[in]  public_seed      Public seed for PRFkeygen.
 * @param[in]  ots_address      Index of the OTS key pair in the larger XMSS scheme.
 */
inline static void prepare_input_prfkeygen(Input_PRFkeygen *const restrict input_prfkeygen,
    const XmssNativeValue256 *const restrict secret_seed,
    const XmssNativeValue256 *const restrict public_seed,
    const uint32_t ots_address)
{
    native_256_copy(&input_prfkeygen->S_XMSS, secret_seed);
    native_256_copy(&input_prfkeygen->SEED, public_seed);
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
 * @param[in]     hashes            The struct with the hash functions to be used.
 * @param[out]    sk_i              Place to store the secret key block.
 * @param[in,out] input_prfkeygen   Input_PRFkeygen containing the seeds and ADRS for generating the secret key.
 *                                  This function sets the chain_address in ADRS to i.
 * @param[in]     i                 Index of the secret key block to generate.
 */
inline static void get_sk_i(HASH_ABSTRACTION(const xmss_hashes *const restrict hashes)
    XmssNativeValue256 *const restrict sk_i,
    Input_PRFkeygen *const restrict input_prfkeygen,
    const uint32_t i)
{
    input_prfkeygen->ADRS.typed.OTS_Hash_Address.chain_address = i;
    xmss_PRFkeygen(HASH_ABSTRACTION(hashes) sk_i, input_prfkeygen);
}

void wotsp_gen_public_key(const struct XmssSigningContext *const restrict context,
    WotspPublicKey *const restrict public_key,
    const XmssNativeValue256 *const restrict secret_seed,
    const XmssNativeValue256 *const restrict public_seed,
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
        get_sk_i(HASH_ABSTRACTION(&context->hash_functions) &sk_i, &input_prfkeygen, i);

        /* Run W - 1 = 15 steps of the chain function on sk[i]. The result is pk[i] in RFC-8391, Algorithm 4. */
        input_prf.M.ADRS.typed.OTS_Hash_Address.chain_address = i;
        chain(HASH_ABSTRACTION(&context->hash_functions) &public_key->hashes[i], &input_prf, &sk_i, 0, W - 1);
    }

    context->zeroize(&input_prfkeygen.S_XMSS, sizeof(input_prfkeygen.S_XMSS));
    context->zeroize(&sk_i, sizeof(sk_i));
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

/**
 * @brief
 * Amount to shift csum in RFC-8391, Algorithms 5 and 6, to get the base-W digits msg[i] for LEN_1 <= i < LEN.
 */
#define CSUM_BITSHIFT(i) (4 * (LEN_2 - 1 - (i - LEN_1)))

void wotsp_sign(const struct XmssSigningContext *const restrict context,
    WotspSignature *const restrict signature,
    const XmssNativeValue256 *const restrict message_digest,
    const XmssNativeValue256 *const restrict secret_seed,
    const XmssNativeValue256 *const restrict public_seed,
    const uint32_t ots_address)
{
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
        get_sk_i(HASH_ABSTRACTION(&context->hash_functions) &sk_i, &input_prfkeygen, i);
        csum -= msg_i;

        /* Run msg[i] steps of the chain function on sk[i] as input. The result is sig[i] in RFC-8391, Algorithm 5. */
        input_prf.M.ADRS.typed.OTS_Hash_Address.chain_address = i;
        chain(HASH_ABSTRACTION(&context->hash_functions) &signature->hashes[i], &input_prf, &sk_i, 0, msg_i);
    }

    /*
     * Process the checksum. This corresponds to the last LEN_2 iterations of the final loop in RFC-8391, Algorithm 5.
     * Note that the bit shift of csum in Algorithm 5 is used only to line it up with the toByte function. The result is
     * the base-W digits of csum in big-endian order, which we calculate in a different way, using the fact that W = 16.
     */
    assert(csum <= 960);
    for (uint32_t i = LEN_1; i < LEN; i++) {
        msg_i = (uint_fast8_t)(csum >> CSUM_BITSHIFT(i)) & 0x0f;
        get_sk_i(HASH_ABSTRACTION(&context->hash_functions) &sk_i, &input_prfkeygen, i);

        input_prf.M.ADRS.typed.OTS_Hash_Address.chain_address = i;
        chain(HASH_ABSTRACTION(&context->hash_functions) &signature->hashes[i], &input_prf, &sk_i, 0, msg_i);
    }

    /* Zeroize the secret seed stored in input_prfkeygen, and the secret key block that is still in memory. */
    context->zeroize(&input_prfkeygen.S_XMSS, sizeof(input_prfkeygen.S_XMSS));
    context->zeroize(&sk_i, sizeof(sk_i));
}

void wotsp_calculate_expected_public_key(HASH_ABSTRACTION(const xmss_hashes *const restrict hashes)
    WotspPublicKey *const restrict expected_public_key,
    const XmssNativeValue256 *const restrict message_digest,
    const WotspSignature *const restrict signature,
    const XmssNativeValue256 *const restrict public_seed,
    const uint32_t ots_address)
{
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
        msg_i = get_msg_i(message_digest, i);
        csum -= msg_i;
        input_prf.M.ADRS.typed.OTS_Hash_Address.chain_address = i;
        chain(HASH_ABSTRACTION(hashes) &expected_public_key->hashes[i], &input_prf, &signature->hashes[i],
            (uint32_t)msg_i, W - 1 - msg_i);
    }

    /*
     * Process the checksum. This corresponds to the last LEN_2 iterations of the final loop in RFC-8391, Algorithm 6.
     * Note that the bit shift of csum in Algorithm 6 is used only to line it up with the toByte function. The result is
     * the base-W digits of csum in big-endian order, which we calculate in a different way, using the fact that W = 16.
     */
    assert(csum <= 960);
    for (uint32_t i = LEN_1; i < LEN; i++) {
        msg_i = (uint_fast8_t)(csum >> CSUM_BITSHIFT(i)) & 0x0f;
        input_prf.M.ADRS.typed.OTS_Hash_Address.chain_address = i;
        chain(HASH_ABSTRACTION(hashes) &expected_public_key->hashes[i], &input_prf, &signature->hashes[i],
            (uint32_t)msg_i, W - 1 - msg_i);
    }
}
