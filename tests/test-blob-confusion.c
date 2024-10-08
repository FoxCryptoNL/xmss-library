/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Thomas Schaap
 */

/* Importing the incorrect part of a key as the stateful private key part might lead to fatal index reuse. We check the
   blobs before importing them, but the blobs do not have markers that identify their type. The only thing we have is
   the size and the integrity digest. As long as the size of the stateful blob has a different size than the other ones,
   a problematic import needs *three* issues: (1) the user of the library already passed the wrong blob to load as
   stateful private key (this may be human error of the actual end user, so it's not unlikely) but with the correct
   length for a stateful private key blob (a programming error: the actual length of the blob should always be passed),
   (2) the rest of the incorrectly passed struct lines up *and* contains index counters that are valid and lower than
   they should have been *and* happens to contain the correct digest of the corresponding stateless private key part and
   (3) the integrity digest happens to correctly validate the shortened blob. (1) requires a bad programming mistake,
   (2) is not unlikely (the public key blob has the same digest on the same offset), (3) means you happened upon a
   collision with a secure hashing algorithm by truncating its original message.

   From the above it follows that as long as we have the size and the integrity digest in the blob, we're fine. As long
   as the sizes are different, that is, so we'll test for that.
*/

#include <stdio.h>
#include <stdlib.h>

#include "signing_private.h"

int main(void) {
    /* Prevent compilers from complaining about comparing constants. */
    const volatile size_t sizeof_XmssPrivateKeyStateless = sizeof(XmssPrivateKeyStateless);
    if (sizeof(XmssPrivateKeyStateful) == sizeof_XmssPrivateKeyStateless) {
        puts("ERROR: The stateless private key blob has the same size as the stateful private key blob.");
        puts("FAILED");
        return EXIT_FAILURE;
    }
    if (sizeof(XmssPublicKeyInternal) == sizeof_XmssPrivateKeyStateless) {
        puts("ERROR: The public key blob has the same size as the stateful private key blob.");
        puts("FAILED");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
