#
# Copyright (C) 2015-2018 Virgil Security Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#

cmake_minimum_required (VERSION 3.10 FATAL_ERROR)

project (${WRAPPED_LIB_NAME}_nodejs)

# Enable C++11
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

set (LANG_VERSION "4.8.7" CACHE STRING "Node.js version")


# ---------------------------------------------------------------------------
#   Utility functions
# ---------------------------------------------------------------------------

# Check SHA256 <checksum> of the given <file>.
function (nodejs_file_checksum_sha256 file checksum)
    file (SHA256 "${file}" checksum_test)

    if (NOT checksum_test STREQUAL checksum)
        message(FATAL_ERROR
            "Mismatched checksum for file: ${file}\n"
            "       [actual]   ${checksum_test}\n"
            "       [expected] ${checksum}"
        )
    endif ()
endfunction ()

# Download file from the given <url> and stores it in a <file>.
# SHA256 <hash> is checked.
function (nodejs_cache_file url file hash)
    if (NOT EXISTS "${file}")
        message (STATUS "Download file: ${file}")

        file (DOWNLOAD "${url}" "${file}"
            SHOW_PROGRESS
            EXPECTED_HASH SHA256=${hash}
            STATUS download_status
        )

        list (GET download_status 0 download_status_code)
        list (GET download_status 1 download_status_message)

        if (NOT download_status_code EQUAL "0")
            message (FATAL_ERROR
                "Fail to upload file. ${download_status_message}.\n"
                "   [file]  ${file}\n"
                "   [url ]  ${url}\n"
                "   [hash]  ${hash}\n"
            )
        endif ()
    else ()
        message (STATUS "File is already in the cache: ${file}")
    endif ()
endfunction ()

# Define V8 engine version from the NodeJS <header> file.
function (nodejs_define_v8_version file major minor hex)

    file (STRINGS "${file}"
        v8_major_line REGEX "^#define[\t ]+V8_MAJOR_VERSION[\t ]+[0-9]+"
    )

    file (STRINGS "${file}"
        v8_minor_line REGEX "^#define[\t ]+V8_MINOR_VERSION[\t ]+[0-9]+"
    )

    string (REGEX REPLACE "^#define[\t ]+V8_MAJOR_VERSION[\t ]+([0-9]+)" "\\1"
        v8_major "${v8_major_line}"
    )

    string (REGEX REPLACE "^#define[\t ]+V8_MINOR_VERSION[\t ]+([0-9]+)" "\\1"
        v8_minor "${v8_minor_line}"
    )

    # Construct HEX representation of the version.
    set (v8_hex "0x")

    string (LENGTH "${v8_major}" str_len)
    if (str_len EQUAL 1)
        set (v8_hex "${v8_hex}0${v8_major}")
    else ()
        set (v8_hex "${v8_hex}${v8_major}")
    endif ()

    string (LENGTH "${v8_minor}" str_len)
    if (str_len EQUAL 1)
        set (v8_hex "${v8_hex}0${v8_minor}")
    else ()
        set (v8_hex "${v8_hex}${v8_minor}")
    endif ()

    set (v8_hex "${v8_hex}00")

    set (${major} ${v8_major} PARENT_SCOPE)
    set (${minor} ${v8_minor} PARENT_SCOPE)
    set (${hex} ${v8_hex} PARENT_SCOPE)
endfunction ()

# ---------------------------------------------------------------------------
#   Load checksum for given version
# ---------------------------------------------------------------------------
file (READ "${CMAKE_CURRENT_LIST_DIR}/checksum.txt" CHECKSUM_FILE)

string (REGEX REPLACE "[.]" "\\\\." LANG_VERSION_REGEX "${LANG_VERSION}")

string (REGEX MATCH
    "v${LANG_VERSION_REGEX}[ ]+[0-9a-zA-Z]+[ ]+node-v${LANG_VERSION_REGEX}-headers.tar.gz"
    NODEJS_HEADRES_CHECKSUM_STRING
    ${CHECKSUM_FILE}
)

string (REGEX MATCH
    "v${LANG_VERSION_REGEX}[ ]+[0-9a-zA-Z]+[ ]+win-x86/node.lib"
    NODEJS_WIN_X86_LIB_CHECKSUM_STRING
    ${CHECKSUM_FILE}
)

string (REGEX MATCH
    "v${LANG_VERSION_REGEX}[ ]+[0-9a-zA-Z]+[ ]+win-x64/node.lib"
    NODEJS_WIN_X64_LIB_CHECKSUM_STRING
    ${CHECKSUM_FILE}
)

if (NOT NODEJS_HEADRES_CHECKSUM_STRING)
    message (FATAL_ERROR
        "Requested NodeJS version ${LANG_VERSION} is not found in a 'checksum.txt' file.\n"
        "   Possible reasons:\n"
        "       - requested version is new and 'checksum.txt' is outdated;\n"
        "       - requested version is stale and not supported any more;\n"
        "       - requested version does not exists.\n"
        "   To update 'checksum.txt' use CMake target 'nodejs_update'."
    )
endif ()

string (REGEX REPLACE "[ ]+" ";" NODEJS_HEADRES_CHECKSUM_LIST ${NODEJS_HEADRES_CHECKSUM_STRING})
string (REGEX REPLACE "[ ]+" ";" NODEJS_WIN_X86_LIB_CHECKSUM_LIST ${NODEJS_WIN_X86_LIB_CHECKSUM_STRING})
string (REGEX REPLACE "[ ]+" ";" NODEJS_WIN_X64_LIB_CHECKSUM_LIST ${NODEJS_WIN_X64_LIB_CHECKSUM_STRING})

list (GET NODEJS_HEADRES_CHECKSUM_LIST 1  NODEJS_HEADRES_CHECKSUM)
list (GET NODEJS_WIN_X86_LIB_CHECKSUM_LIST 1  NODEJS_WIN_X86_LIB_CHECKSUM)
list (GET NODEJS_WIN_X64_LIB_CHECKSUM_LIST 1  NODEJS_WIN_X64_LIB_CHECKSUM)

# ---------------------------------------------------------------------------
#   Download nodejs of the requested version to the cache
# ---------------------------------------------------------------------------
set (NODEJS_HEADERS_TGZ "${VIRGIL_DEPENDS_CACHE_DIR}/nodejs/v${LANG_VERSION}/headers.tgz")
set (NODEJS_WIN_X86_LIB "${VIRGIL_DEPENDS_CACHE_DIR}/nodejs/v${LANG_VERSION}/win-x86/node.lib")
set (NODEJS_WIN_X64_LIB "${VIRGIL_DEPENDS_CACHE_DIR}/nodejs/v${LANG_VERSION}/win-x64/node.lib")

nodejs_cache_file (
    "https://nodejs.org/download/release/v${LANG_VERSION}/node-v${LANG_VERSION}-headers.tar.gz"
    "${NODEJS_HEADERS_TGZ}"
    "${NODEJS_HEADRES_CHECKSUM}"
)

nodejs_cache_file (
    "https://nodejs.org/download/release/v${LANG_VERSION}/win-x86/node.lib"
    "${NODEJS_WIN_X86_LIB}"
    "${NODEJS_WIN_X86_LIB_CHECKSUM}"
)

nodejs_cache_file (
    "https://nodejs.org/download/release/v${LANG_VERSION}/win-x64/node.lib"
    "${NODEJS_WIN_X64_LIB}"
    "${NODEJS_WIN_X64_LIB_CHECKSUM}"
)

# ---------------------------------------------------------------------------
#   Check downloaded / cached files checksum
# ---------------------------------------------------------------------------
nodejs_file_checksum_sha256 ("${NODEJS_HEADERS_TGZ}" "${NODEJS_HEADRES_CHECKSUM}")
nodejs_file_checksum_sha256 ("${NODEJS_WIN_X86_LIB}" "${NODEJS_WIN_X86_LIB_CHECKSUM}")
nodejs_file_checksum_sha256 ("${NODEJS_WIN_X64_LIB}" "${NODEJS_WIN_X64_LIB_CHECKSUM}")

# ---------------------------------------------------------------------------
#   Unpack and copy nodejs of the requested version to the build directory
# ---------------------------------------------------------------------------
set (NODEJS_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/node-v${LANG_VERSION}")

execute_process(
    COMMAND ${CMAKE_COMMAND} -E tar xzf "${NODEJS_HEADERS_TGZ}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)

execute_process(
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${NODEJS_WIN_X86_LIB}"
        "${NODEJS_TARGET_DIR}/lib/win-x86/node.lib"
)

execute_process(
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${NODEJS_WIN_X64_LIB}"
        "${NODEJS_TARGET_DIR}/lib/win-x64/node.lib"
)

# ---------------------------------------------------------------------------
#   Create NodeJS IMPORTED target for the requested version
# ---------------------------------------------------------------------------
add_library (node INTERFACE)
target_include_directories (node SYSTEM INTERFACE
    $<BUILD_INTERFACE:${NODEJS_TARGET_DIR}/include/node>
)
if (WIN32)
    if (POINTER_SIZE EQUAL 8)
        target_link_libraries (node INTERFACE "${NODEJS_TARGET_DIR}/lib/win-x64/node.lib")
    else ()
        target_link_libraries (node INTERFACE "${NODEJS_TARGET_DIR}/lib/win-x86/node.lib")
    endif ()
endif (WIN32)

nodejs_define_v8_version ("${NODEJS_TARGET_DIR}/include/node/v8-version.h"
    V8_VERSION_MAJOR
    V8_VERSION_MINOR
    V8_VERSION_HEX
)

message (STATUS "V8 version: ${V8_VERSION_MAJOR}.${V8_VERSION_MINOR}")
message (STATUS "V8 version hex: ${V8_VERSION_HEX}")

# ---------------------------------------------------------------------------
#   Create helper target 'nodejs_update'
# ---------------------------------------------------------------------------
add_custom_target(nodejs_update
    COMMAND python load_checksum.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMENT "Updating file 'wrappers/nodejs/checksum.txt' ..."
)

# ---------------------------------------------------------------------------
#   Configure wrapper environment
# ---------------------------------------------------------------------------
set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set (WRAPPER_NAME ${PROJECT_NAME})

find_host_package (SWIG REQUIRED)
include (${SWIG_USE_FILE})

set (CMAKE_SWIG_FLAGS "")
set (SWIG_WRAP_COPY_CONSTRUCTOR YES)
set (SWIG_MODULE_NAME ${WRAPPER_NAME})

set (WRAPPER_INTERFACE_FILE "${CMAKE_CURRENT_BINARY_DIR}/wrapper.i")
configure_file (
    "${wrappers_SOURCE_DIR}/swig/wrapper.i.in"
    "${WRAPPER_INTERFACE_FILE}"
)

# ---------------------------------------------------------------------------
#   Configure wrapper build
# ---------------------------------------------------------------------------
set_property (SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY CPLUSPLUS ON)

set_property (
    SOURCE "${WRAPPER_INTERFACE_FILE}"
    PROPERTY SWIG_FLAGS "-ignoremissing" "-node" "-DV8_VERSION=${V8_VERSION_HEX}"
)

swig_add_library (${WRAPPER_NAME}
    LANGUAGE javascript
    SOURCES "${WRAPPER_INTERFACE_FILE}"
)
set (WRAPPER_TARGET "${SWIG_MODULE_${WRAPPER_NAME}_REAL_NAME}")


set_target_properties (${WRAPPER_TARGET} PROPERTIES PREFIX "")
set_target_properties (${WRAPPER_TARGET} PROPERTIES SUFFIX ".node")

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set_property (TARGET ${WRAPPER_TARGET}
        APPEND_STRING PROPERTY LINK_FLAGS " -undefined dynamic_lookup"
    )
endif ()

target_compile_definitions (${WRAPPER_TARGET} PUBLIC "BUILDING_NODE_EXTENSION")
target_link_libraries (${WRAPPER_TARGET} node)
swig_link_libraries (${WRAPPER_TARGET} ${WRAPPED_LIB_NAME})

# ---------------------------------------------------------------------------
#   Configure wrapper install
# ---------------------------------------------------------------------------
install (TARGETS ${WRAPPER_TARGET}
        RUNTIME DESTINATION "${INSTALL_BIN_DIR_NAME}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR_NAME}")
