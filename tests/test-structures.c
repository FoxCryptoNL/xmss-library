/*
 * SPDX-FileCopyrightText: 2022 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#include "signing_private.h"

int main(void) {
    uint8_t buf[XMSS_KEY_GENERATION_CONTEXT_SIZE(16)];
    XmssKeyGenerationContext *ctx = (void*)&buf;
    size_t element_distance = \
        (size_t)(((uint8_t *)(&ctx->partition_states[1])) - ((uint8_t *)(&ctx->partition_states[0])));
    size_t element_size = 4;
    if (element_distance != element_size)
    {
        printf("Partition state array has padding between elements: %zu != %zu", element_distance, element_size);
        return 1;
    }

    return 0;
}
