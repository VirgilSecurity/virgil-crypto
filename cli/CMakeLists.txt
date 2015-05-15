#
# Copyright (C) 2014 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
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

cmake_minimum_required (VERSION 2.8 FATAL_ERROR)

find_package (CURL REQUIRED)
include_directories (CURL_INCLUDE_DIRS)

# Define variables
set (VIRGIL_LIB_NAME virgil)

# Add include directory of wrapped module
if (CMAKE_MAJOR_VERSION LESS 3)
    include_directories (${VIRGIL_INCLUDE_DIR})
    include_directories (${MBEDTLS_INCLUDE_DIR})
    include_directories (${JSONCPP_INCLUDE_DIR})
endif (CMAKE_MAJOR_VERSION LESS 3)

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/ext)
include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include)

# Define sources list
aux_source_directory ("src/common" SRC_LIST)
aux_source_directory ("src/pki" SRC_LIST)
aux_source_directory ("src/commands" SRC_LIST)
foreach (src_file ${SRC_LIST})
    configure_file (
        "${CMAKE_CURRENT_SOURCE_DIR}/${src_file}"
        "${CMAKE_CURRENT_BINARY_DIR}/${src_file}"
        @ONLY
    )
endforeach ()
aux_source_directory(${CMAKE_CURRENT_BINARY_DIR}/src/common SRC_COMMON)
aux_source_directory(${CMAKE_CURRENT_BINARY_DIR}/src/pki SRC_PKI)
aux_source_directory(${CMAKE_CURRENT_BINARY_DIR}/src/commands SRC_COMMANDS)

add_library (virgil_cli_common ${SRC_COMMON})
target_link_libraries (virgil_cli_common virgil)

add_library (virgil_cli_pki ${SRC_PKI})
target_link_libraries (virgil_cli_pki virgil ${CURL_LIBRARIES})

set (COMMON_CLI_NAME virgil)

if (${CPP_SPLIT_CLI})
    add_definitions (-DSPLIT_CLI)
    foreach (SRC ${SRC_COMMANDS})
        get_filename_component (TARGET_NAME ${SRC} NAME_WE)
        if (NOT ${TARGET_NAME} STREQUAL ${COMMON_CLI_NAME})
            add_executable (${TARGET_NAME} ${SRC})
            target_link_libraries (${TARGET_NAME} virgil virgil_cli_common virgil_cli_pki)
            install (TARGETS ${TARGET_NAME} DESTINATION ${INSTALL_BIN_DIR_NAME})
        endif ()
    endforeach (SRC)
else ()
    add_executable (virgil_cli ${SRC_COMMANDS})
    target_link_libraries (virgil_cli virgil virgil_cli_common virgil_cli_pki)
    set_target_properties (virgil_cli PROPERTIES OUTPUT_NAME ${COMMON_CLI_NAME})
    install (TARGETS virgil_cli DESTINATION ${INSTALL_BIN_DIR_NAME})
endif (${CPP_SPLIT_CLI})

if (UNIX)
    install (DIRECTORY "doc/man/" DESTINATION ${INSTALL_MAN_DIR_NAME})
endif (UNIX)

if (UNIX AND ENABLE_TESTING)
    add_test (
        NAME "test_cli.sh"
        COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/utils/test_cli.sh" "${CMAKE_CURRENT_BINARY_DIR}"
    )
endif (UNIX AND ENABLE_TESTING)
