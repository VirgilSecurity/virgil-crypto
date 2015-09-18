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

project (${WRAPPED_LIB_NAME}_js)

# Enable C++11
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

set (NODEJS_VERSION "4.1.0" CACHE STRING "Default target Node.js version.")

if (NODEJS_VERSION)
    set (NODEJS_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/node-v${NODEJS_VERSION}")
else ()
    message (FATAL_ERROR "node.js version is unknown, please define it in varibale NODEJS_VERSION.")
endif ()

if (EXISTS "${NODEJS_TARGET_DIR}/")
    # Make target for Node
    add_library (node INTERFACE)
    target_include_directories (node INTERFACE
        $<BUILD_INTERFACE:${NODEJS_TARGET_DIR}/include>
    )
    if (WIN32)
        if (POINTER_SIZE EQUAL 8)
            target_link_libraries (node INTERFACE "${NODEJS_TARGET_DIR}/lib/win/x64/node.lib")
        else ()
            target_link_libraries (node INTERFACE "${NODEJS_TARGET_DIR}/lib/win/x86/node.lib")
        endif ()
    endif (WIN32)

    # Parse V8 version
    file (STRINGS
        "${NODEJS_TARGET_DIR}/include/v8-version.h"
        v8_major_version_str REGEX "^#define[\t ]+V8_MAJOR_VERSION[\t ]+[0-9]+"
    )
    file (STRINGS
        "${NODEJS_TARGET_DIR}/include/v8-version.h"
        v8_minor_version_str REGEX "^#define[\t ]+V8_MINOR_VERSION[\t ]+[0-9]+"
    )
    string (REGEX REPLACE
        "^#define[\t ]+V8_MAJOR_VERSION[\t ]+([0-9]+)" "\\1"
        V8_MAJOR_VERSION_STRING "${v8_major_version_str}"
    )
    string (REGEX REPLACE
        "^#define[\t ]+V8_MINOR_VERSION[\t ]+([0-9]+)" "\\1"
        V8_MINOR_VERSION_STRING "${v8_minor_version_str}"
    )
    unset (v8_major_version_str)
    unset (v8_minor_version_str)
    message (STATUS "V8 version: ${V8_MAJOR_VERSION_STRING}.${V8_MINOR_VERSION_STRING}")

    string (LENGTH "${V8_MAJOR_VERSION_STRING}" str_len)
    if (str_len EQUAL 1)
        set (V8_MAJOR_VERSION_STRING "0${V8_MAJOR_VERSION_STRING}")
    endif ()
    string (LENGTH "${V8_MINOR_VERSION_STRING}" str_len)
    if (str_len EQUAL 1)
        set (V8_MINOR_VERSION_STRING "0${V8_MINOR_VERSION_STRING}")
    endif ()
    set (V8_VERSION_HEX "0x${V8_MAJOR_VERSION_STRING}${V8_MINOR_VERSION_STRING}00")
    message (STATUS "V8 version hex: ${V8_VERSION_HEX}")
else ()
    message (FATAL_ERROR
        "NODEJS_VERSION contains invalid value - related folder is not found."
    )
endif ()

set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set (JS_MODULE_NAME ${PROJECT_NAME})
set (SWIG_MODULE_NAME ${JS_MODULE_NAME})

find_package (SWIG REQUIRED)
include (${SWIG_USE_FILE})

set (CMAKE_SWIG_FLAGS "")

set (SWIG_WRAP_COPY_CONSTRUCTOR YES)
set (WRAPPER_INTERFACE_FILE "${CMAKE_CURRENT_BINARY_DIR}/wrapper.i")
configure_file (
    "${wrappers_SOURCE_DIR}/swig/wrapper.i.in"
    "${WRAPPER_INTERFACE_FILE}"
)

set_property (SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY CPLUSPLUS ON)
set_property (
    SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY SWIG_FLAGS "-ignoremissing" "-node" "-DV8_VERSION=${V8_VERSION_HEX}"
)

swig_add_module (${JS_MODULE_NAME} javascript "${WRAPPER_INTERFACE_FILE}")
set_target_properties (${SWIG_MODULE_${JS_MODULE_NAME}_REAL_NAME} PROPERTIES PREFIX "")
set_target_properties (${SWIG_MODULE_${JS_MODULE_NAME}_REAL_NAME} PROPERTIES SUFFIX ".node")
target_compile_definitions (${SWIG_MODULE_${JS_MODULE_NAME}_REAL_NAME} PUBLIC "BUILDING_NODE_EXTENSION")

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set_property (TARGET ${JS_MODULE_NAME} APPEND_STRING PROPERTY LINK_FLAGS "-undefined dynamic_lookup")
endif ()
target_link_libraries (${SWIG_MODULE_${JS_MODULE_NAME}_REAL_NAME} node)
swig_link_libraries (${JS_MODULE_NAME} ${WRAPPED_LIB_NAME})

set (PLATFORM_VERSION ${NODEJS_VERSION} PARENT_SCOPE)

install (TARGETS ${JS_MODULE_NAME}
        RUNTIME DESTINATION "${INSTALL_BIN_DIR_NAME}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR_NAME}")
