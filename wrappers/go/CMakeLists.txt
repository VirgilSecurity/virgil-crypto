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

project (${WRAPPED_LIB_NAME}_go)

set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set (GO_MODULE_NAME ${PROJECT_NAME})
set (SWIG_MODULE_NAME ${GO_MODULE_NAME})

find_host_package (SWIG REQUIRED)
include (${SWIG_USE_FILE})

set (CMAKE_SWIG_FLAGS "")

set (SWIG_WRAP_COPY_CONSTRUCTOR YES)
set (WRAPPER_INTERFACE_FILE "${CMAKE_CURRENT_BINARY_DIR}/wrapper.i")
configure_file (
    "${wrappers_SOURCE_DIR}/swig/wrapper.i.in"
    "${WRAPPER_INTERFACE_FILE}"
)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set (SWIG_TARGET_LINUX 1)
endif ()

configure_file (
    "${wrappers_SOURCE_DIR}/swig/go/common.i.in"
    "${CMAKE_CURRENT_BINARY_DIR}/go/common.i"
    @ONLY
)

if (CMAKE_SIZEOF_VOID_P)
    math(EXPR GO_INT_SIZE "8 * ${CMAKE_SIZEOF_VOID_P}")
else ()
    math(EXPR GO_INT_SIZE 32)
endif ()

message (STATUS "Size of Golang integer: ${GO_INT_SIZE}")

set_property (SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY CPLUSPLUS ON)
set_property (SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY SWIG_FLAGS "-ignoremissing;-cgo;-intgosize;${GO_INT_SIZE}")

swig_add_library (${GO_MODULE_NAME}
        TYPE STATIC
        LANGUAGE go
        SOURCES "${WRAPPER_INTERFACE_FILE}")

swig_link_libraries (${GO_MODULE_NAME} ${WRAPPED_LIB_NAME})
set (GO_SWIG_TARGET_NAME ${SWIG_MODULE_${GO_MODULE_NAME}_REAL_NAME})

install (PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/${GO_MODULE_NAME}.go" DESTINATION ".")

install (TARGETS ${GO_SWIG_TARGET_NAME}
        RUNTIME DESTINATION "${INSTALL_BIN_DIR_NAME}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR_NAME}"
        ARCHIVE DESTINATION "${INSTALL_LIB_DIR_NAME}"
)
