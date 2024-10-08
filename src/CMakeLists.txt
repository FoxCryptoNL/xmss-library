# SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
# SPDX-License-Identifier: MIT

if(XMSS_ENABLE_SHA256)
    if(XMSS_ENABLE_SHA256_DEFAULT)
        list(APPEND SOURCES sha256_internal_default.c)
    endif()
    if(NOT XMSS_ENABLE_SHA256_GENERIC)
        list(APPEND SOURCES
            sha256_internal_H0.c
            sha256_internal_xmss_hashes.c
        )
    endif()
endif()
if(XMSS_ENABLE_SHAKE256_256)
    if(XMSS_ENABLE_SHAKE256_256_DEFAULT)
        list(APPEND SOURCES shake256_256_internal_default.c)
    endif()
    if(NOT XMSS_ENABLE_SHAKE256_256_GENERIC)
        list(APPEND SOURCES shake256_256_internal_xmss_hashes.c)
    endif()
endif()
if(XMSS_ENABLE_HASH_ABSTRACTION)
    list(APPEND SOURCES
        sha256_xmss_hashes.c
        shake256_256_xmss_hashes.c
    )
endif()
list(APPEND SOURCES
    errors.c
    rand_hash.c
    xmss_hashes.c
    xmss_ltree.c
    wotsp.c
    wotsp_verification.c
    utils.c
    verification.c
    version.c
)
if(XMSS_ENABLE_SIGNING)
    list(APPEND SOURCES
        zeroize.c
        wotsp_signing.c
        xmss_tree.c
        index_permutation.c
        signing.c
    )
endif()

# This target verifies that the source files *could* be compiled individually.
add_library(sources_sanity OBJECT ${SOURCES})
target_link_libraries(sources_sanity
    PRIVATE xmss_headers
    PRIVATE config
)

if(BUILD_SHARED_LIBS)
    # These are used when building a Windows DLL; they are no-ops for other platforms.
    configure_file(version.in.rc version.rc NO_SOURCE_PERMISSIONS)
    list(APPEND ADDITIONAL_SOURCES ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
    if(XMSS_ENABLE_SIGNING)
        list(APPEND ADDITIONAL_SOURCES libxmss.def)
    else()
        list(APPEND ADDITIONAL_SOURCES libxmss_no_signing.def)
    endif()
endif()

# Our actual library target amalgamates all sources into one; see comment in libxmss.c for rationale.
add_library(xmss
    libxmss.c
    ${XMSS_HASH_OVERRIDE_SOURCES}
    ${ADDITIONAL_SOURCES}
)
set_target_properties(xmss PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})
if(BUILD_SHARED_LIBS AND MSVC)
    # According to CMake documentation (https://cmake.org/cmake/help/latest/prop_tgt/VERSION.html), this should be set
    #   automatically. But it is not (cmake version 3.30.2), so we set it explicitly.
    target_link_options(xmss PRIVATE "/VERSION:${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}")
    # Prevent the default inclusion of a manifest resource, which is intended for .NET assembly DLLs only.
    target_link_options(xmss PRIVATE "/MANIFEST:NO")
endif()
target_link_libraries(xmss
    PUBLIC xmss_headers
    PRIVATE config
    PUBLIC ${XMSS_HASH_OVERRIDE_LINK_LIBRARIES}
)
install(TARGETS xmss)
