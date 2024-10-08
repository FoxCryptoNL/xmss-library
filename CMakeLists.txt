# SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
# SPDX-License-Identifier: MIT

# CMake 3.22.1 is the version installed with Ubuntu 22.04.1.
cmake_minimum_required(VERSION 3.22.1 FATAL_ERROR)

project(xmss-library VERSION 2.0.0 LANGUAGES C)

# All compiler options are in a separate file
include("cmake/compiler_options.cmake")

#
# User-configurable options
#

# Hash optimization

set(HASH_OPTIONS "Default" "Disabled" "OverrideInternal" "OverrideGeneric")

set(XMSS_SHA256 Default CACHE STRING "Optimization configuration for SHA-256.")
set_property(CACHE XMSS_SHA256 PROPERTY STRINGS ${HASH_OPTIONS})
if(NOT XMSS_SHA256 IN_LIST HASH_OPTIONS)
    message(FATAL_ERROR "XMSS_SHA256 must be one of ${HASH_OPTIONS}")
endif()

set(XMSS_SHAKE256_256 Default CACHE STRING "Optimization configuration for SHAKE256/256.")
set_property(CACHE XMSS_SHAKE256_256 PROPERTY STRINGS ${HASH_OPTIONS})
if(NOT XMSS_SHAKE256_256 IN_LIST HASH_OPTIONS)
    message(FATAL_ERROR "XMSS_SHAKE256_256 must be one of ${HASH_OPTIONS}")
endif()

set(XMSS_HASH_OVERRIDE_SOURCES "" CACHE STRING "Source files for hash override(s).")
set(XMSS_HASH_OVERRIDE_LINK_LIBRARIES "" CACHE STRING "Libraries for hash override(s).")

if(XMSS_SHA256 MATCHES "Override" OR XMSS_SHAKE256_256 MATCHES "Override")
    if(NOT XMSS_HASH_OVERRIDE_SOURCES AND NOT XMSS_HASH_OVERRIDE_LINK_LIBRARIES)
        message(FATAL_ERROR "Hash overrides require either XMSS_HASH_OVERRIDE_SOURCES, XMSS_HASH_OVERRIDE_LINK_LIBRARIES, or both.")
    endif()
else()
    if(XMSS_HASH_OVERRIDE_SOURCES)
        message(WARNING "XMSS_HASH_OVERRIDE_SOURCES ignored.")
        set(XMSS_HASH_OVERRIDE_SOURCES "")
    endif()
    if(XMSS_HASH_OVERRIDE_LINK_LIBRARIES)
        message(WARNING "XMSS_HASH_OVERRIDE_LINK_LIBRARIES ignored.")
        set(XMSS_HASH_OVERRIDE_LINK_LIBRARIES "")
    endif()
endif()

# When set to OFF (default), static libraries are built.
# When set to ON, shared libraries are built.
option(BUILD_SHARED_LIBS "Build shared libraries instead of static ones." OFF)

# When set to ON (default), both the full library (including signing) and a verification-only library are built.
# When set to OFF, just the verification-only library is built.
option(XMSS_ENABLE_SIGNING "Enable signing support in the library." ON)

# The C tests are part of the early validation of the compiler/platform combination with the XMSS library and must not
# be disabled for normal testing or production builds.
# The full test suite contains several tests that require hash overrides that will completely fail these tests, though.
option(XMSS_BUILD_TESTS
       "Build C tests for XMSS. These must only be disabled for specific test builds that purposely break the tests."
       ON)
mark_as_advanced(XMSS_BUILD_TESTS)

#
# Calculated settings for xmss_config.h and config.h based on user-configurable options
#

if(XMSS_SHA256 STREQUAL "Disabled")
    set(XMSS_ENABLE_SHA256 OFF)
else()
    set(XMSS_ENABLE_SHA256 ON)
endif()

if(XMSS_SHA256 STREQUAL "Default")
    set(XMSS_ENABLE_SHA256_DEFAULT ON)
else()
    set(XMSS_ENABLE_SHA256_DEFAULT OFF)
endif()

if(XMSS_SHAKE256_256 STREQUAL "Disabled")
    set(XMSS_ENABLE_SHAKE256_256 OFF)
else()
    set(XMSS_ENABLE_SHAKE256_256 ON)
endif()

if(XMSS_SHAKE256_256 STREQUAL "Default")
    set(XMSS_ENABLE_SHAKE256_256_DEFAULT ON)
else()
    set(XMSS_ENABLE_SHAKE256_256_DEFAULT OFF)
endif()

if(NOT XMSS_ENABLE_SHA256 AND NOT XMSS_ENABLE_SHAKE256_256)
    message(FATAL_ERROR "XMSS_SHA256 and XMSS_SHAKE256_256 cannot be both Disabled.")
endif()

if(XMSS_ENABLE_SHA256 AND XMSS_ENABLE_SHAKE256_256)
    set(XMSS_ENABLE_HASH_ABSTRACTION ON)
else()
    set(XMSS_ENABLE_HASH_ABSTRACTION OFF)
endif()

if(XMSS_SHA256 STREQUAL "OverrideGeneric")
    set(XMSS_ENABLE_SHA256_GENERIC ON)
else()
    set(XMSS_ENABLE_SHA256_GENERIC OFF)
endif()

if(XMSS_SHAKE256_256 STREQUAL "OverrideGeneric")
    set(XMSS_ENABLE_SHAKE256_256_GENERIC ON)
else()
    set(XMSS_ENABLE_SHAKE256_256_GENERIC OFF)
endif()

#
# Detectable compiler options
#

# All our try_compile() checks use the exact same compile options as the library itself.
get_directory_property(ACCUMULATED_COMPILE_OPTIONS COMPILE_OPTIONS)
get_directory_property(ACCUMULATED_LINK_OPTIONS LINK_OPTIONS)

# Test if we can compile with various optimization pragmas. This does not necessarily mean that they *work*, but it
# means that the compiler won't error on encountering them.
try_compile(XMSS_CAN_USE_PRAGMA_OPTIMIZE ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/check_pragma_optimize.c
    COMPILE_DEFINITIONS "${ACCUMULATED_COMPILE_OPTIONS}"
    LINK_OPTIONS "${ACCUMULATED_LINK_OPTIONS}"
)
try_compile(XMSS_CAN_USE_PRAGMA_GCC_OPTIMIZE ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/check_pragma_gcc_optimize.c
    COMPILE_DEFINITIONS "${ACCUMULATED_COMPILE_OPTIONS}"
    LINK_OPTIONS "${ACCUMULATED_LINK_OPTIONS}"
)
try_compile(XMSS_CAN_USE_PRAGMA_CLANG_OPTIMIZE ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/check_pragma_clang_optimize.c
    COMPILE_DEFINITIONS "${ACCUMULATED_COMPILE_OPTIONS}"
    LINK_OPTIONS "${ACCUMULATED_LINK_OPTIONS}"
)

# _Static_assert is C11, but it may still be available for certain compilers.
try_compile(XMSS_CAN_USE_STATIC_ASSERT ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/check_static_assert.c
    COMPILE_DEFINITIONS "${ACCUMULATED_COMPILE_OPTIONS}"
    LINK_OPTIONS "${ACCUMULATED_LINK_OPTIONS}"
)
# Modern gcc and clang support _Static_assert even in pedantic C99 mode if prefixed by __extension__.
try_compile(XMSS_CAN_USE_EXTENSION_STATIC_ASSERT ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/check_extension_static_assert.c
    COMPILE_DEFINITIONS "${ACCUMULATED_COMPILE_OPTIONS}"
    LINK_OPTIONS "${ACCUMULATED_LINK_OPTIONS}"
)

#
# Final configuration, based on user options and detected options
#

configure_file(include/xmss_config.in.h include/xmss_config.h NO_SOURCE_PERMISSIONS)
configure_file(src/config.in.h src/config.h NO_SOURCE_PERMISSIONS)

add_library(config INTERFACE)
target_include_directories(config
    INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/include
    INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/src
)

enable_testing()
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

add_subdirectory(include)
add_subdirectory(src)
if(XMSS_BUILD_TESTS)
    add_subdirectory(tests)
endif()
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/docs)
    add_subdirectory(docs)
endif()
