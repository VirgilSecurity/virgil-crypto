#
# Copyright (C) 2015 Virgil Security Inc.
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

cmake_minimum_required (VERSION 3.2 FATAL_ERROR)

project (virgil_crypto)

# Include and build external libraries
include (ExternalProject)
include (${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/mbedtls_ext.cmake)
include (${CMAKE_CURRENT_SOURCE_DIR}/rapidjson/rapidjson.cmake)

set (VIRGIL_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
include_directories (${VIRGIL_INCLUDE_DIR})
include_directories (${MBEDTLS_INCLUDE_DIR})
include_directories (${RAPIDJSON_INCLUDE_DIRS})

# Define sources list
aux_source_directory ("src" src)
if (LIB_FILE_IO)
    aux_source_directory ("src/stream" stream_src)
    list (APPEND src ${stream_src})
endif()

foreach (src_file ${src})
    configure_file (
        "${CMAKE_CURRENT_SOURCE_DIR}/${src_file}"
        "${CMAKE_CURRENT_BINARY_DIR}/${src_file}"
        @ONLY
    )
endforeach ()
set (src "")
aux_source_directory(${CMAKE_CURRENT_BINARY_DIR}/src src)
aux_source_directory(${CMAKE_CURRENT_BINARY_DIR}/src/stream src)

# Build
add_library (${PROJECT_NAME} STATIC ${src})
set_property (TARGET ${PROJECT_NAME} PROPERTY OUTPUT_NAME ${PROJECT_NAME})
set_property (TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)
set_property (TARGET ${PROJECT_NAME} PROPERTY INTERFACE_POSITION_INDEPENDENT_CODE ON)
set_property (TARGET ${PROJECT_NAME} PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${VIRGIL_INCLUDE_DIR})

target_link_libraries (${PROJECT_NAME} ${MBEDTLS_LIBRARIES})
add_dependencies (${PROJECT_NAME} mbedtls)

add_custom_command (TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND}
    ARGS -E copy_if_different
            $<TARGET_FILE:${PROJECT_NAME}>
            ${EXTERNAL_LIBS_DIR}/$<TARGET_FILE_NAME:${PROJECT_NAME}>
)

# Export includes
set (VIRGIL_INCLUDE_DIR ${VIRGIL_INCLUDE_DIR} PARENT_SCOPE)

# Install
if (INSTALL_CORE_LIBS)
    install (TARGETS ${PROJECT_NAME} DESTINATION "${INSTALL_LIB_DIR_NAME}")
    if (INSTALL_EXT_LIBS)
        install (FILES ${MBEDTLS_LIBRARIES} DESTINATION "${INSTALL_LIB_DIR_NAME}")
    endif (INSTALL_EXT_LIBS)
    add_subdirectory (include)
endif ()

if (INSTALL_EXT_HEADERS)
    install (DIRECTORY ${MBEDTLS_INCLUDE_DIR}/ DESTINATION "${INSTALL_INC_DIR_NAME}")
    install (DIRECTORY ${RAPIDJSON_INCLUDE_DIRS}/ DESTINATION "${INSTALL_INC_DIR_NAME}")
endif ()

# add a target to generate API documentation with Doxygen
find_host_program (DOT_PROGRAM NAMES dot)
if (DOT_PROGRAM)
    set (DOT_FOUND "YES")
else ()
    set (DOT_FOUND "NO")
endif (DOT_PROGRAM)

find_host_package (Doxygen)
if (DOXYGEN_FOUND)
    if (DOXYGEN_EXCLUDE_PRIVATE)
        set (DOXYGEN_EXCLUDE
            "${CMAKE_CURRENT_SOURCE_DIR}/include/virgil/crypto/foundation/priv/*"
            "${CMAKE_CURRENT_SOURCE_DIR}/include/virgil/crypto/foundation/asn1/priv/*"
        )
        string (REPLACE ";" " " DOXYGEN_EXCLUDE "${DOXYGEN_EXCLUDE}")
        set (DOXYGEN_EXTRACT_PRIVATE "NO")
    else ()
        set (DOXYGEN_EXTRACT_PRIVATE "YES")
    endif (DOXYGEN_EXCLUDE_PRIVATE)
    configure_file (${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target (doc
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/docs
        COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
endif (DOXYGEN_FOUND)
