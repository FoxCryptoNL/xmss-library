# SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
# SPDX-License-Identifier: MIT

set(CMAKE_FOLDER tests)

# All our try_compile() checks use the exact same compile options as the library itself.
get_directory_property(ACCUMULATED_COMPILE_OPTIONS COMPILE_OPTIONS)
get_directory_property(ACCUMULATED_LINK_OPTIONS LINK_OPTIONS)

include_directories(
    ../include
    ../src
    ${CMAKE_CURRENT_BINARY_DIR}/../include
    ${CMAKE_CURRENT_BINARY_DIR}/../src
)
link_libraries(${XMSS_HASH_OVERRIDE_LINK_LIBRARIES})

# Make the build type show up in the test report.
add_library(test-build_type STATIC
    test-build_type.c
    test-build_type.h
)
add_executable(test-debug test-debug.c)
target_link_libraries(test-debug PRIVATE test-build_type)
add_executable(test-release test-release.c)
target_link_libraries(test-release PRIVATE test-build_type)
get_property(GENERATOR_IS_MULTI_CONFIG GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(${GENERATOR_IS_MULTI_CONFIG})
    # Multi-configuration build system (e.g., Microsoft Visual Studio).
    # Use a generator expression (does not work for NAME).
    add_test(NAME "Build type" COMMAND $<IF:$<CONFIG:Debug>,test-debug,test-release>)
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Definitely a debug build; test-debug must succeed (and test-release would fail).
    add_test(NAME "Debug build" COMMAND test-debug)
else()
    # Any other build type: Release, MinSizeRel, etc.
    # In any case: some release build; test-release must succeed (and test-debug would fail).
    add_test(NAME "Release build" COMMAND test-release)
endif()


# Compile-time test that STATIC_ASSERT(1) succeeds; must succeed whether static assert are available or not.
try_compile(XMSS_TEST_STATIC_ASSERT_PASS ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/test_static_assert.c
    COMPILE_DEFINITIONS
        "${ACCUMULATED_COMPILE_OPTIONS}"
        -I${PROJECT_BINARY_DIR}/include
        -I${PROJECT_SOURCE_DIR}/include
        -DASSERT_VALUE=1
    LINK_OPTIONS
        "${ACCUMULATED_LINK_OPTIONS}"
)
if(NOT XMSS_TEST_STATIC_ASSERT_PASS)
    message(FATAL_ERROR "STATIC_ASSERT(1) did not compile, but it should have.")
endif()
if(XMSS_CAN_USE_STATIC_ASSERT OR XMSS_CAN_USE_EXTENSION_STATIC_ASSERT)
    # Compile-time test that STATIC_ASSERT(0) fails; requires that static asserts are available.
    try_compile(XMSS_TEST_STATIC_ASSERT_DID_NOT_FAIL ${CMAKE_CURRENT_BINARY_DIR}
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/test_static_assert.c
        COMPILE_DEFINITIONS
            "${ACCUMULATED_COMPILE_OPTIONS}"
            -I${PROJECT_BINARY_DIR}/include
            -I${PROJECT_SOURCE_DIR}/include
            -DASSERT_VALUE=0
        LINK_OPTIONS
            "${ACCUMULATED_LINK_OPTIONS}"
    )
    if(XMSS_TEST_STATIC_ASSERT_DID_NOT_FAIL)
        message(FATAL_ERROR "STATIC_ASSERT(0) did not fail, but it should have.")
    endif()
    # Make the test report show that static asserts where enabled at compile time.
    add_executable(test-static_assert test-static_assert.c)
    target_include_directories(test-static_assert
        PRIVATE ${PROJECT_SOURCE_DIR}/include
        PRIVATE ${PROJECT_BINARY_DIR}/include
    )
    add_test(NAME "Static asserts enabled" COMMAND test-static_assert)
endif()

add_executable(test-endianness test-endianness.c)
add_test(NAME "Endianness conversions" COMMAND test-endianness)

add_library(nist-test-vectors OBJECT
    nist-test-vectors.c
    nist-test-vectors.h
)

if(XMSS_ENABLE_SHA256)

    # Test the generic sha256_digest() hash function.
    add_executable(sha256-kat sha256-kat.c ${XMSS_HASH_OVERRIDE_SOURCES})
    target_link_libraries(sha256-kat nist-test-vectors)
    add_test(NAME "SHA-256 Known Answer Tests (KATs)"
        COMMAND sha256-kat
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/external-test-vectors/shabytetestvectors
    )

    # Test the XMSS-specialized (F, H, Hmsg, PRF, and PRFkeygen) SHA-256 hash functions.
    add_executable(test-sha256_xmss_hashes test-sha256_xmss_hashes.c ${XMSS_HASH_OVERRIDE_SOURCES})
    add_test(NAME "SHA-256 XMSS Hash Functions" COMMAND test-sha256_xmss_hashes)

endif()

if(XMSS_ENABLE_SHAKE256_256)

    # Test the generic shake256_256_digest() hash function.
    add_executable(shake256_256-kat shake256_256-kat.c ${XMSS_HASH_OVERRIDE_SOURCES})
    target_link_libraries(shake256_256-kat nist-test-vectors)
    add_test(NAME "SHAKE256/256 Known Answer Tests (KATs)"
        COMMAND shake256_256-kat
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/external-test-vectors/shakebytetestvectors
    )

    # Test the XMSS-specialized (F, H, Hmsg, PRF, and PRFkeygen) SHAKE256/256 hash functions.
    add_executable(test-shake256_256_xmss_hashes test-shake256_256_xmss_hashes.c ${XMSS_HASH_OVERRIDE_SOURCES})
    add_test(NAME "SHAKE256/256 XMSS Hash Functions" COMMAND test-shake256_256_xmss_hashes)

endif()

add_executable(test-chain test-chain.c ${XMSS_HASH_OVERRIDE_SOURCES})
add_test(NAME "Chain function" COMMAND test-chain)

add_executable(test-rand_hash test-rand_hash.c ${XMSS_HASH_OVERRIDE_SOURCES})
add_test(NAME "rand_hash function" COMMAND test-rand_hash)

add_executable(test-ltree test-ltree.c ${XMSS_HASH_OVERRIDE_SOURCES})
add_test(NAME "ltree function" COMMAND test-ltree)

if(XMSS_ENABLE_SIGNING)

    add_executable(test-structures test-structures.c)
    add_test(NAME "Structure layout" COMMAND test-structures)

    add_executable(test-blob-confusion test-blob-confusion.c)
    add_test(NAME "Test key blob sizes" COMMAND test-blob-confusion)

    add_executable(test-xmss_zeroize test-xmss_zeroize.c)
    add_test(NAME "Secure zeroize" COMMAND test-xmss_zeroize)

    add_executable(test-wotsp test-wotsp.c ${XMSS_HASH_OVERRIDE_SOURCES})
    add_test(NAME "Test WOTS+" COMMAND test-wotsp)

    add_executable(test-xmss_tree_hash test-xmss_tree_hash.c ${XMSS_HASH_OVERRIDE_SOURCES})
    add_test(NAME "xmss_tree_hash" COMMAND test-xmss_tree_hash)

    add_executable(test-xmss_context_initialize test-xmss_context_initialize.c ${XMSS_HASH_OVERRIDE_SOURCES})
    add_test(NAME "xmss_context_initialize" COMMAND test-xmss_context_initialize)

    add_executable(test-xmss_generate_private_key test-xmss_generate_private_key.c ${XMSS_HASH_OVERRIDE_SOURCES})
    target_link_libraries(test-xmss_generate_private_key xmss)
    add_test(NAME "xmss_generate_private_key"
        COMMAND test-xmss_generate_private_key
        WORKING_DIRECTORY $<TARGET_FILE_DIR:xmss>
    )

    add_executable(test-xmss_sign_verify test-xmss_sign_verify.c ${XMSS_HASH_OVERRIDE_SOURCES})
    target_link_libraries(test-xmss_sign_verify xmss)
    add_test(NAME "xmss_sign_verify"
        COMMAND test-xmss_sign_verify
        WORKING_DIRECTORY $<TARGET_FILE_DIR:xmss>
    )

    add_executable(test-xmss_generate_public_key test-xmss_generate_public_key.c  ${XMSS_HASH_OVERRIDE_SOURCES})
    target_link_libraries(test-xmss_generate_public_key xmss)
    add_test(NAME "xmss_generate_public_key"
        COMMAND test-xmss_generate_public_key
        WORKING_DIRECTORY $<TARGET_FILE_DIR:xmss>
    )

endif()

add_executable(test-version test-version.c)
target_link_libraries(test-version xmss)
add_test(NAME "Library version"
    COMMAND test-version
    WORKING_DIRECTORY $<TARGET_FILE_DIR:xmss>
)

add_executable(test-completeness test-completeness.c)
target_link_libraries(test-completeness xmss)
add_test(NAME "Library completeness"
    COMMAND test-completeness
    WORKING_DIRECTORY $<TARGET_FILE_DIR:xmss>
)
