/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Max Fillinger
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "wotsp.c"

#include "xmss_hashes.h"
#if XMSS_ENABLE_SHA256
#include "sha256_xmss_hashes.h"
#endif
#if XMSS_ENABLE_SHAKE256_256
#include "shake256_256_xmss_hashes.h"
#endif

static void print_output(const XmssNativeValue256 *output, const XmssNativeValue256 *expected_output)
{
    printf("Output:    ");
    for (int i = 0; i < XMSS_VALUE_256_WORDS; i++) {
        printf("0x%08x ", output->data[i]);
    }
    printf("\nExpected:  ");
    for (int i = 0; i < XMSS_VALUE_256_WORDS; i++) {
        printf("0x%08x ", expected_output->data[i]);
    }
    printf("\n");
}

#if XMSS_ENABLE_SHA256
static bool test_chain_with_sha256(void)
{
    const XmssNativeValue256 input = { { 0x01000000 } };
    const XmssNativeValue256 prf_seed = { { 0x02000000 } };
    XmssNativeValue256 output;
    Input_PRF input_prf = INIT_INPUT_PRF;

    prepare_input_prf_for_chain(&input_prf, &prf_seed, 0);
    chain(HASH_ABSTRACTION(&sha256_xmss_hashes) &output, &input_prf, &input, 2, 3);

    /* Expected output calculated with Frans' C# implementation: github.com/dorssel/dotnet-xmss. */
    const XmssNativeValue256 expected_output = { {
        0x1d54ffa3, 0xa8302db1, 0xf077b8d8, 0x4fcfdefb, 0x83678eb2, 0x54c159ab, 0x276a03c2, 0x195a8aae
    } };

    const bool success = memcmp(&output, &expected_output, sizeof(XmssNativeValue256)) == 0;
    printf("Chain function test %s for SHA256!\n", success ? "succeeded" : "failed");
    if (!success) {
        print_output(&output, &expected_output);
    }

    return success;
}
#endif /* XMSS_ENABLE_SHA256 */

#if XMSS_ENABLE_SHAKE256_256
static bool test_chain_with_shake256_256(void)
{
    const XmssNativeValue256 input = { { 0x01000000 } };
    const XmssNativeValue256 prf_seed = { { 0x02000000 } };
    XmssNativeValue256 output;
    Input_PRF input_prf = INIT_INPUT_PRF;

    prepare_input_prf_for_chain(&input_prf, &prf_seed, 0);
    chain(HASH_ABSTRACTION(&shake256_256_xmss_hashes) &output, &input_prf, &input, 2, 3);

    /* Expected output calculated with Frans' C# implementation: github.com/dorssel/dotnet-xmss. */
    const XmssNativeValue256 expected_output = { {
        0xbfa7a39a, 0xc051e963, 0x3478b449, 0xcd538e82, 0xa533aa52, 0xddef9852, 0xd42a227, 0x2e5d338f
    } };

    const bool success = memcmp(&output, &expected_output, sizeof(XmssNativeValue256)) == 0;
    printf("Chain function test %s for SHAKE256_256!\n", success ? "succeeded" : "failed");
    if (!success) {
        print_output(&output, &expected_output);
    }

    return success;
}
#endif /* XMSS_ENABLE_SHAKE256_256 */

int main()
{
    bool success = true;
#if XMSS_ENABLE_SHA256
    success &= test_chain_with_sha256();
#endif
#if XMSS_ENABLE_SHAKE256_256
    success &= test_chain_with_shake256_256();
#endif
    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
