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

project (virgil)

# Include and build external libraries
include (ExternalProject)
include (${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/mbedtls_ext.cmake)
include (${CMAKE_CURRENT_SOURCE_DIR}/jsoncpp/jsoncpp_ext.cmake)

set (LIB_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include")
include_directories (${LIB_INCLUDE_DIRS})
if (CMAKE_MAJOR_VERSION LESS 3)
    include_directories (${MBEDTLS_INCLUDE_DIR})
    include_directories (${JSONCPP_INCLUDE_DIR})
endif (CMAKE_MAJOR_VERSION LESS 3)


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
set_property (TARGET ${PROJECT_NAME} PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${LIB_INCLUDE_DIRS})

target_link_libraries (${PROJECT_NAME} mbedtls jsoncpp)
add_custom_command (TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND}
    ARGS -E copy_if_different
            $<TARGET_FILE:${PROJECT_NAME}>
            ${EXTERNAL_LIBS_DIR}/$<TARGET_FILE_NAME:${PROJECT_NAME}>
)

# Install
if (INSTALL_CORE_LIB)
    install (TARGETS ${PROJECT_NAME}
            ARCHIVE DESTINATION "${INSTALL_LIB_DIR_NAME}")
    install (FILES ${MBEDTLS_LIBRARY}
            DESTINATION "${INSTALL_LIB_DIR_NAME}")
    install (FILES ${JSONCPP_LIBRARY}
            DESTINATION "${INSTALL_LIB_DIR_NAME}")

    add_subdirectory (include)
endif ()
