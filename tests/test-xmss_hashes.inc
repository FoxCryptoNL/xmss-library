/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#if XMSS_ENABLE_HASH_ABSTRACTION

extern const xmss_hashes *const hash_functions;

#endif


/* Some 32 unique bytes of test data */
static const XmssValue256 test_blob_32_1 = { {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
} };

/* Some other 32 unique bytes of test data */
static const XmssValue256 test_blob_32_2 = { {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77
} };

/* Even more 32 unique bytes of test data */
static const XmssValue256 test_blob_32_3 = { {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7
} };

/* Some 64 unique bytes of test data */
static const uint8_t test_blob_64[64] = {
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};


/**
 * @brief
 * Outputs the input number as a big-endian byte stream.
 *
 * @details
 * Implements the XMSS toByte(x,32) function, defined by RFC 8391, Section 2.5.
 *
 * @param[out] dst   The 32-byte output byte stream.
 * @param[in] x   The input number.
*/
static void toByte(uint8_t *dst, uint64_t x)
{
    memset(dst, 0, 24);
    dst[24] = (uint8_t)(x >> 56);
    dst[25] = (uint8_t)(x >> 48);
    dst[26] = (uint8_t)(x >> 40);
    dst[27] = (uint8_t)(x >> 32);
    dst[28] = (uint8_t)(x >> 24);
    dst[29] = (uint8_t)(x >> 16);
    dst[30] = (uint8_t)(x >> 8);
    dst[31] = (uint8_t)x;
}


static bool test_F(void)
{
    /* Setup */

#   define test_KEY test_blob_32_1
#   define test_M test_blob_32_2

    Input_F input = INIT_INPUT_F;
    big_endian_to_native_256(&input.KEY, &test_KEY);
    big_endian_to_native_256(&input.M, &test_M);

    /* Test */

    XmssNativeValue256 native_digest;
    xmss_F(HASH_FUNCTIONS &native_digest, &input);
    XmssValue256 digest;
    native_to_big_endian_256(&digest, &native_digest);

    /* Verification: F(KEY, M) == digest(toByte(0) || KEY || M) */

    uint8_t verification_message[96];
    toByte(verification_message, 0);
    memcpy(verification_message + 32, &test_KEY, 32);
    memcpy(verification_message + 64, &test_M, 32);
    XmssValue256 verification_digest;
    reference_digest(&verification_digest, verification_message, sizeof(verification_message));

    return memcmp(&digest, &verification_digest, sizeof(XmssValue256)) == 0;

#   undef test_KEY
#   undef test_M
}


static bool test_H(void)
{
    /* Setup */

#   define test_KEY test_blob_32_1
#   define test_M test_blob_64

    Input_H input = INIT_INPUT_H;
    big_endian_to_native_256(&input.KEY, &test_KEY);
    big_endian_to_native(input.M[0].data, test_M, 16);

    /* Test */

    XmssNativeValue256 native_digest;
    xmss_H(HASH_FUNCTIONS &native_digest, &input);
    XmssValue256 digest;
    native_to_big_endian_256(&digest, &native_digest);

    /* Verification: H(KEY, M) == digest(toByte(1) || KEY || M) */

    uint8_t verification_message[128];
    toByte(verification_message, 1);
    memcpy(verification_message + 32, &test_KEY, 32);
    memcpy(verification_message + 64, test_M, 64);
    XmssValue256 verification_digest;
    reference_digest(&verification_digest, verification_message, sizeof(verification_message));

    return memcmp(&digest, &verification_digest, sizeof(XmssValue256)) == 0;

#   undef test_KEY
#   undef test_M
}


static bool test_H_msg_length(size_t message_length)
{
    /* Setup */

#   define test_r test_blob_32_1
#   define test_Root test_blob_32_2
    const uint32_t test_idx_sig = 0x12345678;
    uint8_t *test_message = malloc(message_length);
    for (size_t i = 0; i < message_length; ++i) {
        /**
         * 137 is prime and slightly bigger than the block size.
         * This ensures that the blocks do not repeat within our test range, neither for SHA-256 (block size 64)
         *      nor for SHAKE256 (block size 136).
         */
        test_message[i] = (uint8_t)(i % 137);
    }

    Input_H_msg input = INIT_INPUT_H_MSG;
    big_endian_to_native_256(&input.r, &test_r);
    big_endian_to_native_256(&input.Root, &test_Root);
    input.idx_sig = test_idx_sig;

    /* Test */

    XmssHMsgCtx ctx;
    XmssNativeValue256 native_digest;
    xmss_H_msg_init(HASH_FUNCTIONS &ctx, &input);
    xmss_H_msg_update(HASH_FUNCTIONS &ctx, test_message, message_length, NULL);
    xmss_H_msg_finalize(HASH_FUNCTIONS &native_digest, &ctx);
    XmssValue256 digest;
    native_to_big_endian_256(&digest, &native_digest);

    /*
     * Verification:
     *      H_msg(KEY, M) == digest(toByte(2) || KEY || M), where KEY = r || getRoot(SK) || toByte(idx_sig,n)
     *
     * Therefore:
     *      H_msg(KEY, M) == digest(toByte(2) || r || Root || toByte(idx_sig,32) || M)
     */

    uint8_t *verification_message = malloc(128 + message_length);
    toByte(verification_message, 2);
    memcpy(verification_message + 32, &test_r, 32);
    memcpy(verification_message + 64, &test_Root, 32);
    toByte(verification_message + 96, test_idx_sig);
    memcpy(verification_message + 128, test_message, message_length);

    XmssValue256 verification_digest;
    reference_digest(&verification_digest, verification_message, 128 + message_length);

    free(test_message);
    free(verification_message);

    return memcmp(&digest, &verification_digest, sizeof(XmssValue256)) == 0;

#   undef test_r
#   undef test_Root
}

static bool test_H_msg(void)
{
    bool success = true;

    /* Test all lengths from 0 up to and including 3 full blocks (we use the bigger block size of SHAKE256). */
    for (size_t message_length = 0; message_length <= 3 * 136; ++message_length) {
        if (!test_H_msg_length(message_length)) {
            fprintf(stderr, "Failed test_H_msg for length %u\n", (unsigned int)message_length);
            success = false;
        }
    }

    return success;
}

static bool test_PRF(void)
{
    /* Setup */

#   define test_KEY test_blob_32_1
#   define test_ADRS test_blob_32_2

    Input_PRF input = INIT_INPUT_PRF;
    big_endian_to_native_256(&input.KEY, &test_KEY);
    big_endian_to_native_256((XmssNativeValue256 *)&input.M.ADRS, &test_ADRS);

    /* Test */

    XmssNativeValue256 native_digest;
    xmss_PRF(HASH_FUNCTIONS &native_digest, &input);
    XmssValue256 digest;
    native_to_big_endian_256(&digest, &native_digest);

    /*
     * Verification: PRF(KEY, M) == digest(toByte(3) || KEY || M), where M = ADRS
     *
     * Therefore: PRF(KEY, M) == digest(toByte(3) || KEY || ADRS)
     */

    uint8_t verification_message[96];
    toByte(verification_message, 3);
    memcpy(verification_message + 32, &test_KEY, 32);
    memcpy(verification_message + 64, &test_ADRS, 32);
    XmssValue256 verification_digest;
    reference_digest(&verification_digest, verification_message, sizeof(verification_message));

    return memcmp(&digest, &verification_digest, sizeof(XmssValue256)) == 0;

#undef test_KEY
#undef test_ADRS
}


#if XMSS_ENABLE_SIGNING


static bool test_PRFkeygen(void)
{
    /* Setup */

#   define test_S_XMSS test_blob_32_1
#   define test_SEED test_blob_32_2
#   define test_ADRS test_blob_32_3

    Input_PRFkeygen input = INIT_INPUT_PRFKEYGEN;
    big_endian_to_native_256(&input.S_XMSS, &test_S_XMSS);
    big_endian_to_native_256(&input.SEED, &test_SEED);
    big_endian_to_native_256((XmssNativeValue256 *)&input.ADRS, &test_ADRS);

    /* Test */

    XmssNativeValue256 native_digest;
    XmssValue256 digest;
    xmss_PRFkeygen(HASH_FUNCTIONS &native_digest, &input);
    native_to_big_endian_256(&digest, &native_digest);

    /*
     * Verification: PRFkeygen(KEY, M) == digest(toByte(4) || M), where M = X_SEED || SEED || ADRS
     *
     * Therefore: PRFkeygen(KEY, M) == digest(toByte(4) || X_SEED || SEED || ADRS)
    */

    uint8_t verification_message[128];
    toByte(verification_message, 4);
    memcpy(verification_message + 32, &test_S_XMSS, 32);
    memcpy(verification_message + 64, &test_SEED, 32);
    memcpy(verification_message + 96, &test_ADRS, 32);
    XmssValue256 verification_digest;
    reference_digest(&verification_digest, verification_message, sizeof(verification_message));

    return memcmp(&digest, &verification_digest, sizeof(XmssValue256)) == 0;

#   undef test_S_XMSS
#   undef test_SEED
#   undef test_ADRS
}


static bool test_PRFindex(void)
{
    /* Setup */

#   define test_S_INDEX test_blob_32_1
#   define test_SEED test_blob_32_2

    Input_PRFindex input = INIT_INPUT_PRFINDEX;
    big_endian_to_native_256(&input.S_INDEX, &test_S_INDEX);
    big_endian_to_native_256(&input.SEED, &test_SEED);
    input.drbg_counter = 42;

    /* Test */

    XmssNativeValue256 native_digest;
    XmssValue256 digest;
    xmss_PRFindex(HASH_FUNCTIONS &native_digest, &input);
    native_to_big_endian_256(&digest, &native_digest);

    /*
     * Verification: PRFindex(KEY, M) == digest(toByte(5) || M), where M = X_INDEX || SEED || toByte(drbg_counter)
     *
     * Therefore: PRFindex(KEY, M) == digest(toByte(5) || X_INDEX || SEED || toByte(drbg_counter))
    */

    uint8_t verification_message[128];
    toByte(verification_message, 5);
    memcpy(verification_message + 32, &test_S_INDEX, 32);
    memcpy(verification_message + 64, &test_SEED, 32);
    toByte(verification_message + 96, 42);
    XmssValue256 verification_digest;
    reference_digest(&verification_digest, verification_message, sizeof(verification_message));

    return memcmp(&digest, &verification_digest, sizeof(XmssValue256)) == 0;

#   undef test_S_INDEX
#   undef test_SEED
}


/* Test all counts from 0 up to and including 3 full blocks (we use the bigger block size of SHAKE256). */
#define MAX_WORD_COUNT (3 * 136 / sizeof(uint32_t))

static bool test_native_digest_count(size_t count)
{
    /* Setup */
    uint32_t words[MAX_WORD_COUNT];

    for (uint32_t i = 0; i < count; ++i) {
        /* some non-trivial data */
        words[i] = (uint32_t)(count * 0x01234567 + i * 0xfedcba98);
    }

    /* Test */

    XmssNativeValue256 native_digest;
    xmss_native_digest(HASH_FUNCTIONS &native_digest, words, count);
    XmssValue256 digest;
    native_to_big_endian_256(&digest, &native_digest);

    /* Verification */

    uint8_t verification_message[MAX_WORD_COUNT * sizeof(uint32_t)];
    native_to_big_endian(verification_message, words, (uint_fast16_t)count);
    XmssValue256 verification_digest;
    reference_digest(&verification_digest, verification_message, count * sizeof(uint32_t));

    return memcmp(&digest, &verification_digest, sizeof(XmssValue256)) == 0;
}


static bool test_native_digest(void)
{
    bool success = true;

    for (size_t word_count = 33; word_count <= MAX_WORD_COUNT; ++word_count) {
        if (!test_native_digest_count(word_count)) {
            fprintf(stderr, "Failed test_native_digest for word count %u\n", (unsigned int)word_count);
            success = false;
        }
    }

    return success;
}


#endif /* XMSS_ENABLE_SIGNING */


int main(void)
{
    bool success = true;

    success = success && test_F();
    success = success && test_H();
    success = success && test_H_msg();
    success = success && test_PRF();
#if XMSS_ENABLE_SIGNING
    success = success && test_PRFkeygen();
    success = success && test_PRFindex();
    success = success && test_native_digest();
#endif

    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
