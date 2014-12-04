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

project (${WRAPPED_LIB_NAME}_php)

set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set (PHP_INSTALL_DIR php)
set (PHP_MODULE_NAME ${PROJECT_NAME})
set (SWIG_MODULE_NAME ${PHP_MODULE_NAME})

find_package (PHPLibs REQUIRED)
include_directories (${PHP_INCLUDE_DIRS})

find_package (SWIG REQUIRED)
include (${SWIG_USE_FILE})

set (CMAKE_SWIG_FLAGS "")

set (SWIG_WRAP_LOW_LEVEL_API YES)
set (SWIG_WRAP_COPY_CONSTRUCTOR YES)
set (WRAPPER_INTERFACE_FILE "${CMAKE_CURRENT_BINARY_DIR}/wrapper.i")
configure_file (
    "${wrappers_SOURCE_DIR}/swig/wrapper.i.in"
    "${WRAPPER_INTERFACE_FILE}"
)

set_property (SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY CPLUSPLUS ON)
set_property (
    SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY SWIG_FLAGS "-includeall" "-ignoremissing"
)

swig_add_module (${PHP_MODULE_NAME} php5 "${WRAPPER_INTERFACE_FILE}")
set_target_properties(${SWIG_MODULE_${PHP_MODULE_NAME}_REAL_NAME} PROPERTIES PREFIX "")

# Conform to http://www.php-cpp.com/documentation/install
if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set_property (TARGET ${PHP_MODULE_NAME} APPEND_STRING PROPERTY LINK_FLAGS "-undefined dynamic_lookup")
endif ()
swig_link_libraries (${PHP_MODULE_NAME} ${WRAPPED_LIB_NAME})

install (TARGETS ${PHP_MODULE_NAME}
        RUNTIME DESTINATION "${PHP_INSTALL_DIR}/${INSTALL_BIN_DIR_NAME}"
        LIBRARY DESTINATION "${PHP_INSTALL_DIR}/${INSTALL_LIB_DIR_NAME}")

install (PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/${SWIG_MODULE_${PHP_MODULE_NAME}_REAL_NAME}.php"
        DESTINATION ${PHP_INSTALL_DIR}/${INSTALL_API_DIR_NAME})

# Unit tests
set (PHP_MODULE_FILE_NAME "${SWIG_MODULE_${PHP_MODULE_NAME}_REAL_NAME}.php")
add_subdirectory (tests)
