<!--
    SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
    SPDX-License-Identifier: MIT
-->

# XMSS

eXtended Merkle Signature Scheme is a post-quantum safe signature algorithm
([RFC](https://datatracker.ietf.org/doc/html/rfc8391)).

![XMSS C Library License](https://img.shields.io/github/license/FoxCryptoNL/xmss-library?style=plastic)
[![XMSS C Library Release](https://img.shields.io/github/v/release/FoxCryptoNL/xmss-library?style=plastic)](https://github.com/FoxCryptoNL/xmss-library/releases)

## XMSS C Library Source Code

This repository contains the source code of the XMSS C Library. For more information about the complete project, please
visit [https://github.com/FoxCryptoNL/xmss](https://github.com/FoxCryptoNL/xmss).

This repository will only be updated when a new release of the XMSS C Library is published. The documentation may be
updated more frequently. This includes the API documentation that is generated from the source code. While this means
that the source code and the published API documentation may slightly differ, this will allow more frequent updates for
minor edits without the need to update this repository.

## Issues and Security Issues

Security issues regarding the implementation of the XMSS C Library should be reported via the
[security tab](https://github.com/FoxCryptoNL/xmss-library/security) to allow for responsible disclosure.

Other issues regarding the implementation of the algorithm can be reported in this repository's
[issue tracker](https://github.com/FoxCryptoNL/xmss-library/issues).

Please report any issues regarding the documentation, including the API documentation in the source code, on the
[documentation issue tracker](https://github.com/FoxCryptoNL/xmss-documentation/issues).

## Discussions

Discussions about the implementation of the XMSS C Library can be held in the
[library discussions](https://github.com/FoxCryptoNL/xmss-library/discussions).

## Building the XMSS C Library

Building the library requires a recent version of [CMake](https://cmake.org/) and a C compiler.
[GCC](https://gcc.gnu.org/), [clang](https://clang.llvm.org/) and
[Microsoft Visual Studio](https://visualstudio.microsoft.com/) have been confirmed to work, but any C99 compliant
compiler should work.

To build the library, use CMake to create a build directory using a copy of this repository as source directory. After
that you should be able to build the library right away.

A quick-start for a Linux-based system:

```bash
git clone https://github.com/FoxCryptoNL/xmss-library.git
cd xmss-library
mkdir build
cd build
cmake ..
make -j
make test
```
