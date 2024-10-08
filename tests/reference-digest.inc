/*
 * SPDX-FileCopyrightText: 2024 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/*

We need to test various xmss hash functions (F, H, H_msg, etc.), for which we need a reference digest function.
We also need to test the underlying primitives (e.g., xmss_sha256_process_block) against the NIST KATs,
    for which we (again) need a reference digest function.
Here we construct such a reference digest function from the underlying primitives, such that it can be used
for both. Note that this is very similar (if not identical) to the generic XMSS digest function of the library,
except that the latter is not defined when compiling with XMSS_ENABLE_SIGNING=OFF. The version here is always
available.

*/

#include "types.h"

#if defined(REFERENCE_DIGEST_SHA256) && !defined(REFERENCE_DIGEST_SHAKE256_256)
#   if XMSS_ENABLE_SHA256_GENERIC
#       include "override_sha256_generic.h"
#   else
#       include "sha256_internal_xmss_hashes.h"
#   endif
#elif defined(REFERENCE_DIGEST_SHAKE256_256) && !defined(REFERENCE_DIGEST_SHA256)
#   if XMSS_ENABLE_SHAKE256_256_GENERIC
#       include "override_shake256_256_generic.h"
#   else
#       include "override_shake256_256_internal.h"
#   endif
#else
#   error Either REFERENCE_DIGEST_SHA256 or REFERENCE_DIGEST_SHAKE256_256 must be defined.
#endif


static inline void reference_digest(XmssValue256 *const digest, const uint8_t *const message,
    const size_t message_length)
{
#if defined(REFERENCE_DIGEST_SHA256)
#   if XMSS_ENABLE_SHA256_GENERIC

    // Produce a generic digest from the generic primitives.
    void *context = xmss_sha256_init();
    xmss_sha256_update(context, message, message_length);
    xmss_sha256_finalize(context, digest);

#   else

    // Produce a generic digest from the internal primitives.
    XmssNativeValue256 native_digest;
    native_digest = sha256_H0;
    sha256_process_message_final(&native_digest, message, message_length, 0);
    native_to_big_endian_256(digest, &native_digest);

#   endif
#elif defined(REFERENCE_DIGEST_SHAKE256_256)
#   if XMSS_ENABLE_SHAKE256_256_GENERIC

    // Produce a generic digest from the generic primitives.
    void *context = xmss_shake256_256_init();
    xmss_shake256_256_update(context, message, message_length);
    xmss_shake256_256_finalize(context, digest);

#   else

    // Produce a generic digest from the internal primitives.
    uint64_t A[200] = { 0 };
    shake256_256_process_message_final(A, 0, message, message_length);
    XmssNativeValue256 native_digest;
    // Note that xmss_sponge_squeeze() also is unavailable for XMSS_ENABLE_SIGNING=OFF
    xmss_sponge_squeeze_native(&native_digest, A);
    native_to_big_endian_256(digest, &native_digest);

#   endif
#else
#   error Either REFERENCE_DIGEST_SHA256 or REFERENCE_DIGEST_SHAKE256_256 must be defined.
#endif
}
