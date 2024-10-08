/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Max Fillinger
 * SPDX-FileContributor: Pepijn Westen
 */

#include "libxmss.c"

#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>


static void print_output(const XmssNativeValue256 *output, const XmssNativeValue256 *expected_output)
{
    printf("Output:    ");
    for (int i = 0; i < XMSS_VALUE_256_WORDS; i++) {
        printf("0x%08"PRIx32" ", output->data[i]);
    }
    printf("\nExpected:  ");
    for (int i = 0; i < XMSS_VALUE_256_WORDS; i++) {
        printf("0x%08"PRIx32" ", expected_output->data[i]);
    }
    printf("\n");
}

#if XMSS_ENABLE_SHA256
static bool test_rand_hash_with_sha256(void)
{
    /* Inputs and expected output generated with Frans' C# implementation: github.com/dorssel/dotnet-xmss. */
    const XmssNativeValue256 left = { {
        0xc764df20, 0x7d235dcd, 0x9211ac68, 0xea0c082f, 0xc1ee07fb, 0x2d9ec82f, 0xed6e5809, 0xa78a416d,
    } };
    const XmssNativeValue256 right = { {
        0x04b17f7c, 0x57b0ed1e, 0x7efb3af5, 0x88875f6e, 0xf2af7ab4, 0xe7c2122c, 0x2bef95d3, 0xe8a83552,

    } };
    const XmssNativeValue256 seed = { {
        0xde6be3f5, 0xe4ee1898, 0x50d2af27, 0x082e2c6e, 0xda69afbb, 0x0f37f5ae, 0x1df118aa, 0x34264a14,

    } };
    const uint32_t adrs[8] = {
        0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    };
    const XmssNativeValue256 expected_output = { {
        0xde0df4cf, 0x8e31dc35, 0xb417a034, 0x0f8c4006, 0xe8313632, 0x07c2813c, 0xb7694203, 0xe4452590,
    } };

    XmssNativeValue256 output;
    Input_PRF rand_hash_state = INIT_INPUT_PRF;
    memcpy(&rand_hash_state.M.ADRS, adrs, sizeof(ADRS));
    rand_hash_state.KEY = seed;

    DEFINE_HASH_FUNCTIONS;
    INITIALIZE_HASH_FUNCTIONS(XMSS_PARAM_SHA2_10_256);
    rand_hash(HASH_FUNCTIONS &output, &rand_hash_state, &left, &right);

    const bool success = memcmp(&output, &expected_output, sizeof(XmssNativeValue256)) == 0;
    printf("rand hash function test %s for SHA256!\n", success ? "succeeded" : "failed");
    if (!success) {
        print_output(&output, &expected_output);
    }

    return success;
}
#endif /* XMSS_ENABLE_SHA256 */

#if XMSS_ENABLE_SHAKE256_256
static bool test_rand_hash_with_shake256_256(void)
{
 /* Inputs and expected output generated with Frans' C# implementation: github.com/dorssel/dotnet-xmss. */
    const XmssNativeValue256 left = {{
        0x36324bce, 0x64bd2c50, 0x7d65b603, 0x33cfff4d, 0xc125f091, 0x6aa048cf, 0xc144ff62, 0xd4300bdc,
    }};
    const XmssNativeValue256 right = {{
        0x4458ebae, 0x1f758a43, 0x2ee15c0d, 0x99e52608, 0xcfc9061b, 0xb556b5f3, 0x39793ef9, 0xaea328e7,
    }};
    const XmssNativeValue256 seed = { {
        0xb68d1f6c, 0x09e495cd, 0x4c180507, 0x3d959957, 0xde0727be, 0x80162d50, 0x443a48fe, 0xef7ac433,
    } };
    const uint32_t adrs[8] = {
        0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    };
    const XmssNativeValue256 expected_output = { {
        0xa40c15cd, 0x826e9f08, 0xf67687a4, 0xef241bd8, 0x6d99de0d, 0x36589b0e, 0xa2aa61a8, 0xc8ade07c,
    } };

    XmssNativeValue256 output;
    Input_PRF rand_hash_state = INIT_INPUT_PRF;
    memcpy(&rand_hash_state.M.ADRS, adrs, sizeof(ADRS));
    rand_hash_state.KEY = seed;

    DEFINE_HASH_FUNCTIONS;
    INITIALIZE_HASH_FUNCTIONS(XMSS_PARAM_SHAKE256_10_256);
    rand_hash(HASH_FUNCTIONS &output, &rand_hash_state, &left, &right);

    const bool success = memcmp(&output, &expected_output, sizeof(XmssNativeValue256)) == 0;
    printf("rand hash function test %s for SHAKE256_256!\n", success ? "succeeded" : "failed");
    if (!success) {
        print_output(&output, &expected_output);
    }

    return success;
}
#endif /* XMSS_ENABLE_SHAKE256_256 */

int main(void)
{
    bool success = true;
#if XMSS_ENABLE_SHA256
    success &= test_rand_hash_with_sha256();
#endif
#if XMSS_ENABLE_SHAKE256_256
    success &= test_rand_hash_with_shake256_256();
#endif
    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
