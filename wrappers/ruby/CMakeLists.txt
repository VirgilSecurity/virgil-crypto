#
# Copyright (C) 2015-2016 Virgil Security Inc.
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

project (${WRAPPED_LIB_NAME}_ruby)

set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set (RUBY_MODULE_NAME ${PROJECT_NAME})
set (SWIG_MODULE_NAME ${RUBY_MODULE_NAME})

# Find Ruby package
if (LANG_VERSION)
    find_host_package (Ruby "${LANG_VERSION}" EXACT REQUIRED)
else ()
    find_host_package (Ruby REQUIRED)
endif (LANG_VERSION)

# Find Ruby headers in given path - not system
find_host_path (RUBY_INCLUDE_DIR_LOCAL
    NAMES ruby.h
    HINTS
    ${RUBY_HDR_DIR}
    ${RUBY_ARCH_DIR}
    NO_DEFAULT_PATH
)

find_host_path (RUBY_CONFIG_INCLUDE_DIR_LOCAL
    NAMES ruby/config.h  config.h
    HINTS
    ${RUBY_HDR_DIR}/${RUBY_ARCH}
    ${RUBY_ARCH_DIR}
    ${RUBY_ARCHHDR_DIR}
    NO_DEFAULT_PATH
)

# Replace system ruby include dirs with found within RbConfig
set (RUBY_INCLUDE_DIRS
    "${RUBY_INCLUDE_DIR_LOCAL}" "${RUBY_CONFIG_INCLUDE_DIR_LOCAL}"
    CACHE STRING "Ruby include directories" FORCE
)
include_directories (SYSTEM ${RUBY_INCLUDE_DIRS})

if (RUBY_VERSION)
    string (REPLACE "." ";" RUBY_VERSION_LIST ${RUBY_VERSION})
    list (GET RUBY_VERSION_LIST 0 RUBY_VERSION_MAJOR)
    list (GET RUBY_VERSION_LIST 1 RUBY_VERSION_MINOR)
    set (LANG_VERSION "${RUBY_VERSION_MAJOR}.${RUBY_VERSION_MINOR}" CACHE STRING "RUBY version" FORCE)
endif (RUBY_VERSION)

find_host_package (SWIG REQUIRED)
include (${SWIG_USE_FILE})

set (CMAKE_SWIG_FLAGS "")

set (SWIG_WRAP_COPY_CONSTRUCTOR YES)
set (WRAPPER_INTERFACE_FILE "${CMAKE_CURRENT_BINARY_DIR}/wrapper.i")
configure_file (
    "${wrappers_SOURCE_DIR}/swig/wrapper.i.in"
    "${WRAPPER_INTERFACE_FILE}"
)

set_property (SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY CPLUSPLUS ON)
set_property (SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY SWIG_FLAGS "-ignoremissing;-autorename")

swig_add_module (${RUBY_MODULE_NAME} ruby "${WRAPPER_INTERFACE_FILE}")
set (SWIG_TARGET ${SWIG_MODULE_${RUBY_MODULE_NAME}_REAL_NAME})

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set_property (TARGET ${SWIG_TARGET} APPEND_STRING PROPERTY LINK_FLAGS "-undefined dynamic_lookup")
else()
    set_target_properties(${SWIG_TARGET} PROPERTIES VERSION ${VIRGIL_VERSION} SOVERSION ${VIRGIL_SOVERSION})
endif ()
swig_link_libraries (${RUBY_MODULE_NAME} ${WRAPPED_LIB_NAME} ${RUBY_LIBRARY})

install (TARGETS ${SWIG_TARGET}
        RUNTIME DESTINATION "${INSTALL_BIN_DIR_NAME}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR_NAME}")
