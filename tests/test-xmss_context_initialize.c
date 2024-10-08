/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Pepijn Westen
 */

#include "libxmss.c"

#include <stdlib.h>
#include <stdbool.h>


static bool free_called = false;
static bool realloc_called = false;

static void custom_free(void *mem)
{
    (void) mem;
    free_called = true;
}

static void *custom_realloc(void *mem, const size_t size)
{
    (void)mem;
    (void)size;
    realloc_called = true;
	return mem;
}

static unsigned char test_context[XMSS_SIGNING_CONTEXT_SIZE];
static XmssSigningContext *context_ptr = (XmssSigningContext *)&test_context;

#define test(arg_struct, expectation)                                         \
    success = success && (expectation == xmss_context_initialize(             \
        arg_struct.context,                                                   \
        arg_struct.parameter_set,                                             \
        arg_struct.custom_realloc, args.custom_free, args.zeroize))

struct argument_convenience_struct {
    XmssSigningContext **context;
    XmssParameterSetOID parameter_set;
    XmssReallocFunction custom_realloc;
    XmssFreeFunction custom_free;
    XmssZeroizeFunction zeroize;
};

int main(void)
{
    bool success = true;

    struct argument_convenience_struct args = {0};
    static XmssSigningContext *context_ptr_dynamic = NULL;

#if !XMSS_ENABLE_SHAKE256_256
    const uint32_t any_supported_param_set = XMSS_PARAM_SHA2_10_256;
#else
    const uint32_t any_supported_param_set = XMSS_PARAM_SHAKE256_10_256;
#endif

    // known-good arguments
    args.context = &context_ptr_dynamic;
    args.parameter_set = any_supported_param_set;
    args.custom_realloc = realloc;
    args.custom_free = free;

    // test with NULL context
    args.context = NULL;
    test(args, XMSS_ERR_NULL_POINTER);
    args.context = &context_ptr_dynamic;

    // test with NULL realloc
    args.custom_realloc = NULL;
    test(args, XMSS_ERR_NULL_POINTER);
    args.custom_realloc = realloc;

    // test with NULL free
    args.custom_free = NULL;
    test(args, XMSS_ERR_NULL_POINTER);
    args.custom_free = free;

    // test with bad parameter set OID
    args.parameter_set =  XMSS_PARAM_SHAKE256_20_256 + 10;
    test(args, XMSS_ERR_INVALID_ARGUMENT);
    args.parameter_set = any_supported_param_set;
    context_ptr_dynamic = NULL;

    // test success with stdlib realloc
    test(args, XMSS_OKAY);
    success = success && (context_ptr_dynamic != NULL);
    success = success && ((XmssSigningContext*) context_ptr_dynamic)->initialized == XMSS_INITIALIZATION_INITIALIZED;
    success = success && ((XmssSigningContext*) context_ptr_dynamic)->parameter_set == (uint32_t)args.parameter_set;
    if (success) free(context_ptr_dynamic);
    context_ptr_dynamic = NULL;

    args.parameter_set = XMSS_PARAM_SHAKE256_20_256;
#if XMSS_ENABLE_SHAKE256_256
    test(args, XMSS_OKAY);
    success = success && (context_ptr_dynamic != NULL);
    success = success && ((XmssSigningContext*) context_ptr_dynamic)->initialized == XMSS_INITIALIZATION_INITIALIZED;
    success = success && ((XmssSigningContext*) context_ptr_dynamic)->parameter_set == (uint32_t)args.parameter_set;
#if XMSS_ENABLE_HASH_ABSTRACTION
    success = success && ((XmssSigningContext*) context_ptr_dynamic)->hash_functions == &shake256_256_xmss_hashes;
#endif
    if (success) free(context_ptr_dynamic);
    context_ptr_dynamic = NULL;
#endif

#if XMSS_ENABLE_SHA256
    args.parameter_set = XMSS_PARAM_SHA2_16_256;
    test(args, XMSS_OKAY);
    success = success && (context_ptr_dynamic != NULL);
    success = success && ((XmssSigningContext*) context_ptr_dynamic)->initialized == XMSS_INITIALIZATION_INITIALIZED;
    success = success && ((XmssSigningContext*) context_ptr_dynamic)->parameter_set == (uint32_t)args.parameter_set;
#if XMSS_ENABLE_HASH_ABSTRACTION
    success = success && ((XmssSigningContext*) context_ptr_dynamic)->hash_functions == &sha256_xmss_hashes;
#endif
    if (success) free(context_ptr_dynamic);
    context_ptr_dynamic = NULL;
#endif

     args.parameter_set = any_supported_param_set;
     args.custom_realloc = &custom_realloc;
     args.custom_free = &custom_free;
     // test realloc fails
     test(args, XMSS_ERR_ALLOC_ERROR);
     success = success && realloc_called;
     success = success && !free_called;
     realloc_called = false;

     // test realloc succeeds
     args.context = &context_ptr;
     test(args, XMSS_OKAY);
     success = success && ((XmssSigningContext*) context_ptr)->parameter_set == (uint32_t)args.parameter_set;
     success = success && realloc_called;
     success = success && !free_called;
     success = success && ((XmssSigningContext*) context_ptr)->zeroize == xmss_zeroize;
     realloc_called = false;
     return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
