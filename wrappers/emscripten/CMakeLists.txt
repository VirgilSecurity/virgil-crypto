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

project (${WRAPPED_LIB_NAME}_emscripten)

# Configure
set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set (WRAPPER_TARGET ${PROJECT_NAME}_${VIRGIL_VERSION})
set (EMIT_MEM_FILE OFF)

set (EMSCRIPTEN $ENV{EMSCRIPTEN})
if (NOT EMSCRIPTEN)
    message (FATAL_ERROR "Enviroment variable: EMSCRIPTEN not found."
        " See http://kripken.github.io/emscripten-site/docs/getting_started/downloads.html")
endif ()

set (WRAPPER_SRC wrapper.cxx)
configure_file (
    ${CMAKE_CURRENT_SOURCE_DIR}/${WRAPPER_SRC}
    ${CMAKE_CURRENT_BINARY_DIR}/${WRAPPER_SRC}
    @ONLY
)
configure_file (
    ${CMAKE_CURRENT_SOURCE_DIR}/example.html
    ${CMAKE_CURRENT_BINARY_DIR}/example.html
    @ONLY
)

# Build
add_executable (${WRAPPER_TARGET} ${WRAPPER_SRC})
target_link_libraries (${WRAPPER_TARGET} ${WRAPPED_LIB_NAME})
set_property (TARGET ${WRAPPER_TARGET} APPEND_STRING PROPERTY COMPILE_FLAGS " -std=c++11")
set_property (TARGET ${WRAPPER_TARGET} APPEND_STRING PROPERTY LINK_FLAGS " --bind")
if (NOT EMIT_MEM_FILE)
    set_property (TARGET ${WRAPPER_TARGET} APPEND_STRING PROPERTY LINK_FLAGS " --memory-init-file 0")
endif ()
em_link_post_js (${WRAPPER_TARGET} ${CMAKE_CURRENT_SOURCE_DIR}/helpers.js)

# Install
install (TARGETS ${WRAPPER_TARGET} DESTINATION "${INSTALL_LIB_DIR_NAME}")

if (CMAKE_BUILD_TYPE)
    string (TOUPPER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE_UPPER)
    set (CMAKE_CXX_FLAGS_ALL "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
endif ()
string (REGEX MATCH "-O2|-O3" OPTIMIZED_BUILD "${CMAKE_CXX_FLAGS_ALL}")
if (OPTIMIZED_BUILD AND EMIT_MEM_FILE)
    install (FILES $<TARGET_FILE:${WRAPPER_TARGET}>.mem DESTINATION "${INSTALL_LIB_DIR_NAME}")
endif ()

install (FILES ${CMAKE_CURRENT_BINARY_DIR}/example.html DESTINATION
        "${INSTALL_DOC_DIR_NAME}/${PROJECT_NAME}/${VIRGIL_VERSION}/example")
