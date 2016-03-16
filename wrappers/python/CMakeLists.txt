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

cmake_minimum_required (VERSION 3.4 FATAL_ERROR)

project (${WRAPPED_LIB_NAME}_python)

set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set (PYTHON_MODULE_NAME ${PROJECT_NAME})
set (SWIG_MODULE_NAME ${PYTHON_MODULE_NAME})

if (LANG_VERSION)
    find_host_package (PythonInterp "${LANG_VERSION}" EXACT)
    find_host_package (PythonLibs "${LANG_VERSION}" EXACT REQUIRED)
else ()
    find_host_package (PythonInterp)
    find_host_package (PythonLibs REQUIRED)
endif (LANG_VERSION)

include_directories (${PYTHON_INCLUDE_DIRS})

if (PYTHONLIBS_VERSION_STRING)
    string (REPLACE "." ";" PYTHON_VERSION_LIST ${PYTHONLIBS_VERSION_STRING})
    list (GET PYTHON_VERSION_LIST 0 PYTHON_VERSION_MAJOR)
    list (GET PYTHON_VERSION_LIST 1 PYTHON_VERSION_MINOR)
    set (LANG_VERSION "${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR}" CACHE STRING "PYTHON version" FORCE)
endif (PYTHONLIBS_VERSION_STRING)

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
set_property (SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY SWIG_FLAGS "-ignoremissing")

swig_add_module (${PYTHON_MODULE_NAME} python "${WRAPPER_INTERFACE_FILE}")
set (SWIG_TARGET ${SWIG_MODULE_${PYTHON_MODULE_NAME}_REAL_NAME})

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set_property (TARGET ${SWIG_TARGET} APPEND_STRING PROPERTY LINK_FLAGS "-undefined dynamic_lookup")
else()
    set_target_properties(${SWIG_TARGET} PROPERTIES VERSION ${VIRGIL_VERSION} SOVERSION ${VIRGIL_SOVERSION})
endif ()
swig_link_libraries (${PYTHON_MODULE_NAME} ${WRAPPED_LIB_NAME})

install (TARGETS ${SWIG_TARGET}
        RUNTIME DESTINATION "${INSTALL_BIN_DIR_NAME}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR_NAME}")

install (PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/${PYTHON_MODULE_NAME}.py"
        DESTINATION ${INSTALL_API_DIR_NAME})
