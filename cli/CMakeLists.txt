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

# Define variables
set (VIRGIL_LIB_NAME virgil)

# Add include directory of wrapped module
if (CMAKE_MAJOR_VERSION LESS 3)
    include_directories (${${VIRGIL_LIB_NAME}_SOURCE_DIR}/include)
endif (CMAKE_MAJOR_VERSION LESS 3)
include_directories (${CMAKE_CURRENT_SOURCE_DIR}/ext)
include_directories (${CMAKE_CURRENT_SOURCE_DIR}/src)

# Define sources list
aux_source_directory ("src" SRC_LIST)
foreach (src_file ${SRC_LIST})
    configure_file (
        "${CMAKE_CURRENT_SOURCE_DIR}/${src_file}"
        "${CMAKE_CURRENT_BINARY_DIR}/${src_file}"
        @ONLY
    )
endforeach ()
set (SRC_LIST "")
aux_source_directory(${CMAKE_CURRENT_BINARY_DIR}/src SRC_LIST)

if (${CPP_SPLIT_CLI})
    add_definitions (-DSPLIT_CLI)
    add_library (cli_utils "${CMAKE_CURRENT_BINARY_DIR}/src/utils.cxx")
    target_link_libraries (cli_utils virgil)
    foreach (SRC ${SRC_LIST})
        get_filename_component (TARGET_NAME ${SRC} NAME_WE)
        if (NOT (${TARGET_NAME} STREQUAL "utils" OR ${TARGET_NAME} STREQUAL "virgil"))
            add_executable (${TARGET_NAME} ${SRC})
            target_link_libraries (${TARGET_NAME} cli_utils)
            target_link_libraries (${TARGET_NAME} virgil)
            install (TARGETS ${TARGET_NAME} DESTINATION ${INSTALL_BIN_DIR_NAME})
        endif ()
    endforeach (SRC)
else ()
    add_executable (virgil_cli ${SRC_LIST})
    target_link_libraries (virgil_cli virgil)
    set_target_properties (virgil_cli PROPERTIES OUTPUT_NAME virgil)
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
