# SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
# SPDX-License-Identifier: MIT

# Compiler configuration for the XMSS library. This is located in a separate cmake file to allow the 'public' repository
# to include these at a very early stage.

if (NOT CMAKE_BUILD_TYPE)
    # This is initialized by project() based on the environment and/or command line options.
    # For some toolkits, the default is an empty string, in which case we default to a release build.
   set(CMAKE_BUILD_TYPE "Release")
endif()

# This changes the compiler mode: C99, as strict as possible.
# Requirement XMSS-LIB-ENV-0010
option(XMSS_C99_COMPATIBLE "Add compiler options to enforce compiling against strict C99." ON)
if(XMSS_C99_COMPATIBLE)
    set(CMAKE_C_STANDARD 99)
else()
    set(CMAKE_C_STANDARD 11)
endif()
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT MSVC)
    # NOTE: These are compiler specific! These are for gcc/clang.

    # Requirement XMSS-LIB-ENV-0030
    add_compile_options(-Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes)

    # Be extra strict (all pedantic diagnostics are errors), not a requirement.
    add_compile_options(-pedantic-errors)
    # Be extra strict (all conversions that could be out-of-range must be explicit casts), not a requirement.
    add_compile_options(-Wconversion)
else()
    # NOTE: Microsoft Visual C++ (MSVC) does not support C99.
    # Support for MSVC is not a requirement.
    if(XMSS_C99_COMPATIBLE)
        message(WARNING "MSVC does not support C99. Build with XMSS_C99_COMPATIBLE=OFF to suppress this warning.")
        set(XMSS_C99_COMPATIBLE OFF)
endif()
    # Disable warnings about deprecation of C99 functions for which C11 provides an alternative.
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    # MSVC's recommended warning level for new projects.
    # NOTE: /Wall would even "warn" informational messages, so it cannot be used in combination with /WX.
    add_compile_options(/W4 /WX)
    # MSVC thinks that incomplete array types as last member of a struct are non-standard (but they really are C99).
    add_compile_options(/wd4200)
endif()
