# SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
# SPDX-License-Identifier: MIT

set(XMSS_HEADER_FILES
    compat.h
    errors.h
    generic_digest.h
    opaque_structures.h
    override_sha256_generic.h
    override_sha256_internal.h
    override_shake256_256_generic.h
    override_shake256_256_internal.h
    signing.h
    structures.h
    types.h
    verification.h
    version.h
    ${CMAKE_CURRENT_BINARY_DIR}/xmss_config.h
)

# Ensure that all header files are included.
# Note that while it's discouraged to use GLOB to gather source files, it's fine to use it as a late check like this.
file(GLOB DETECTED_HEADER_FILES LIST_DIRECTORIES false RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.h)
# Exclude template files
list(FILTER DETECTED_HEADER_FILES EXCLUDE REGEX ".*\.in\.h")
# Exclude generated xmss_config.h, in case building in-tree
list(REMOVE_ITEM DETECTED_HEADER_FILES xmss_config.h)
foreach(HEADER ${DETECTED_HEADER_FILES})
    list(FIND XMSS_HEADER_FILES "${HEADER}" HEADER_INDEX)
    if(HEADER_INDEX EQUAL -1)
        message(FATAL_ERROR "Header ${HEADER} was not added to CMakeLists.txt.")
    endif()
endforeach()

# Add a minimal test to verify that each of the public headers is standalone
foreach(HEADER ${XMSS_HEADER_FILES})
    cmake_path(GET HEADER FILENAME HEADER_FILENAME)
    file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/_verify_${HEADER_FILENAME}.c" CONTENT "#include \"${HEADER_FILENAME}\"
int main(void) { return 0; }
")
    add_executable("_verify_${HEADER_FILENAME}" "_verify_${HEADER_FILENAME}.c")
    target_include_directories("_verify_${HEADER_FILENAME}"
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
        PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
    )
    set_property(TARGET _verify_${HEADER_FILENAME} PROPERTY FOLDER tests/verify_headers)
    # Note that building the executable is the real test. They're added as tests, anyway, to ensure that they're built
    # as part of the test cycle.
    add_test(NAME "Verify ${HEADER_FILENAME} is standalone" COMMAND "_verify_${HEADER_FILENAME}")
endforeach()

add_library(xmss_headers INTERFACE ${XMSS_HEADER_FILES})
target_include_directories(xmss_headers
    INTERFACE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
)

install(FILES ${XMSS_HEADER_FILES} DESTINATION include/xmss)
