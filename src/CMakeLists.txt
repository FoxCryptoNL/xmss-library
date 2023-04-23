# SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
# SPDX-License-Identifier: MIT

if (XMSS_ENABLE_SHA256)

    if(XMSS_SHA256 STREQUAL "OverrideGeneric")
        set(SHA256_SOURCES
            endianness.h
            generic_xmss_hashes.h
            sha256_generic_xmss_hashes.h
            sha256_xmss_hashes.c
            sha256_xmss_hashes.h
            xmss_hashes_base.h
            ${XMSS_SHA256_OVERRIDE_SOURCES}
        )
    else()
        set(SHA256_SOURCES
            endianness.h
            sha256_internal_xmss_hashes.c
            sha256_internal_xmss_hashes.h
            sha256_xmss_hashes.c
            sha256_xmss_hashes.h
            xmss_hashes_base.h
        )
        if(XMSS_SHA256 STREQUAL "Default")
            list(APPEND SHA256_SOURCES sha256_internal_default.c)
        else()
            # "OverrideInternal"
            list(APPEND SHA256_SOURCES ${XMSS_SHA256_OVERRIDE_SOURCES})
        endif()
    endif()

    add_library(sha256 STATIC ${SHA256_SOURCES})
    target_include_directories(sha256
        INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}
        PUBLIC ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(sha256
        PUBLIC xmss_headers
    )

endif()

if (XMSS_ENABLE_SHAKE256_256)

    if(XMSS_SHAKE256_256 STREQUAL "OverrideGeneric")
        set(SHAKE256_256_SOURCES
            endianness.h
            generic_xmss_hashes.h
            shake256_256_generic_xmss_hashes.h
            shake256_256_xmss_hashes.c
            shake256_256_xmss_hashes.h
            xmss_hashes_base.h
            ${XMSS_SHAKE256_256_OVERRIDE_SOURCES}
        )
    else()
        set(SHAKE256_256_SOURCES
            shake256_256_internal_xmss_hashes.c
            shake256_256_internal_xmss_hashes.h
            shake256_256_xmss_hashes.c
            shake256_256_xmss_hashes.h
            xmss_hashes_base.h
        )
        if(XMSS_SHAKE256_256 STREQUAL "Default")
            list(APPEND SHAKE256_256_SOURCES shake256_256_internal_default.c)
        else()
            # "OverrideInternal"
            list(APPEND SHAKE256_256_SOURCES ${XMSS_SHAKE256_256_OVERRIDE_SOURCES})
        endif()
    endif()

    add_library(shake256_256 STATIC ${SHAKE256_256_SOURCES})
    target_include_directories(shake256_256
        INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}
        PUBLIC ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(shake256_256
        PUBLIC xmss_headers
    )

endif()

add_library(xmss_hashes STATIC
    xmss_hashes.c
    xmss_hashes.h
)
target_include_directories(xmss_hashes
    INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC ${CMAKE_CURRENT_BINARY_DIR}
)
if (XMSS_ENABLE_SHA256)
    target_link_libraries(xmss_hashes PUBLIC sha256)
endif()
if (XMSS_ENABLE_SHAKE256_256)
    target_link_libraries(xmss_hashes PUBLIC shake256_256)
endif()

if(XMSS_HASH_OVERRIDE_SOURCES)
    # Compile needed voor override(s).
    add_library(hash_overrides STATIC ${XMSS_HASH_OVERRIDE_SOURCES})
    target_include_directories(hash_overrides
        INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}
        PUBLIC ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(hash_overrides
        PUBLIC xmss_headers
    )
    if(XMSS_HASH_OVERRIDE_LINK_LIBRARIES)
        # Link needed as well.
        target_link_libraries(hash_overrides PUBLIC ${XMSS_HASH_OVERRIDE_LINK_LIBRARIES})
    endif()
    target_link_libraries(xmss_hashes PUBLIC hash_overrides)
elseif(XMSS_HASH_OVERRIDE_LINK_LIBRARIES)
    # Link-only override(s)
    target_link_libraries(xmss_hashes PUBLIC ${XMSS_HASH_OVERRIDE_LINK_LIBRARIES})
endif()

add_library(utils STATIC
    utils.c
    utils.h
)
target_include_directories(utils
    INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC ${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(utils
    PUBLIC xmss_headers
)
add_library(xmss_signing STATIC
    signing.c
    xmss_tree.c
    index_permutation.c
    private.h
)
target_link_libraries(xmss_signing
    PUBLIC xmss_headers
    PRIVATE utils
    PRIVATE xmss_hashes
    PRIVATE wotsp
)
add_library(xmss_verification STATIC
    verification.c
    private.h
)
target_link_libraries(xmss_verification
    PUBLIC xmss_headers
    PRIVATE xmss_hashes
    PRIVATE wotsp
)
add_library(wotsp STATIC
    wotsp.c
    wotsp.h
)
target_include_directories(wotsp
    INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC ${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(wotsp
    PUBLIC xmss_headers
)
