<!--
    SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
    SPDX-License-Identifier: MIT
-->

# Test vectors (Known Answer Tests)

## SHA-256

These test vectors are provided by the NIST
[Cryptographic Algorithm Validation Program (CAVP)](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program).

The selected test vectors are from
[CAVP Testing: Secure Hashing](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing), restricted to
those from "SHA Test Vectors for Hashing Byte-Oriented Messages" for SHA-256.

The test vectors are described in
[The Secure Hash Algorithm Validation System (SHAVS)](http://csrc.nist.gov/groups/STM/cavp/documents/shs/SHAVS.pdf),
NIST, Updated: May 21, 2014.

## SHAKE256/256

These test vectors are provided by the NIST
[Cryptographic Algorithm Validation Program (CAVP)](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program).

The selected test vectors are from
[CAVP Testing: Secure Hashing](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing),
restricted to those from "SHA-3 XOF Test Vectors for Byte-Oriented Output" for SHAKE256 with an output length of 256 bits.

The test vectors are described in
[The Secure Hash Algorithm 3 Validation System (SHA3VS)](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf),
NIST, April 7, 2016.

## WOTS+ / XMSS

These test vectors are the output of the ```vectors``` program of
the [XMSS reference code](https://github.com/XMSS/xmss-reference).

The test vectors are described by the generating source code. Note that the
OIDs identifying the WOTS+ test vectors are XMSS_OIDs, not WOTS_OIDs.
