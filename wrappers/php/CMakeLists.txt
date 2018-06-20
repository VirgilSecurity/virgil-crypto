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

project (${WRAPPED_LIB_NAME}_php)

set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

#
#   Find PHP module
#
if(LANG_VERSION)
    find_host_package (PHP ${LANG_VERSION} EXACT REQUIRED)
else()
    find_host_package (PHP REQUIRED)
endif()

include_directories (SYSTEM ${PHP_INCLUDE_DIRS})

#
#   Find SWIG module
#
find_host_package (SWIG REQUIRED)
include (${SWIG_USE_FILE})

#
#   Configure build options
#
set (PHP_MODULE_NAME ${PROJECT_NAME})
set (SWIG_MODULE_NAME ${PHP_MODULE_NAME})
set (CMAKE_SWIG_FLAGS "")

set (SWIG_WRAP_COPY_CONSTRUCTOR YES)
set (WRAPPER_INTERFACE_FILE "${CMAKE_CURRENT_BINARY_DIR}/wrapper.i")
configure_file (
    "${wrappers_SOURCE_DIR}/swig/wrapper.i.in"
    "${WRAPPER_INTERFACE_FILE}"
)

set_property (SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY CPLUSPLUS ON)
set_property (
    SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY SWIG_FLAGS "-ignoremissing"
)

swig_add_library (${PHP_MODULE_NAME}
    LANGUAGE php${PHP_VERSION_MAJOR}
    SOURCES "${WRAPPER_INTERFACE_FILE}"
)
set (PHP_SWIG_TARGET_NAME ${SWIG_MODULE_${PHP_MODULE_NAME}_REAL_NAME})

# Conform to http://www.php-cpp.com/documentation/install
if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set_property (TARGET ${PHP_SWIG_TARGET_NAME} APPEND_STRING PROPERTY LINK_FLAGS "-undefined dynamic_lookup")
else()
    set_target_properties(${PHP_SWIG_TARGET_NAME} PROPERTIES VERSION ${VIRGIL_VERSION} SOVERSION ${VIRGIL_SOVERSION})
endif ()
swig_link_libraries (${PHP_MODULE_NAME} ${WRAPPED_LIB_NAME} "${PHP_LIBRARIES}")

set_target_properties(${PHP_SWIG_TARGET_NAME} PROPERTIES PREFIX "")

set_property(TARGET ${PHP_SWIG_TARGET_NAME}
        APPEND PROPERTY COMPILE_DEFINITIONS "${PHP_DEFINES}" ZEND_DEBUG=0)

set (PHP_WRAPPER_VERSION_STRING "\\\"${VIRGIL_VERSION}\\\"")
add_custom_command (TARGET ${PHP_SWIG_TARGET_NAME} PRE_BUILD
    COMMAND ${CMAKE_COMMAND}
    ARGS
        -DSRC:PATH="${swig_generated_file_fullname}"
        -DREGULAR_EXPRESSION:STRING="NO_VERSION_YET"
        -DREPLACE_EXPRESSION:STRING="${PHP_WRAPPER_VERSION_STRING}"
        -P ${CMAKE_SOURCE_DIR}/cmake/file_regex_replace.cmake
    COMMENT "Add version to the SWIG generated wrapper."
)

install (TARGETS ${PHP_SWIG_TARGET_NAME}
        RUNTIME DESTINATION "${INSTALL_BIN_DIR_NAME}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR_NAME}")

install (PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/${PHP_SWIG_TARGET_NAME}.php"
        DESTINATION ${INSTALL_API_DIR_NAME})

# Unit tests
if (ENABLE_TESTING)
    set (PHP_MODULE_FILE_NAME "${PHP_SWIG_TARGET_NAME}.php")
    add_subdirectory (tests)
endif (ENABLE_TESTING)
