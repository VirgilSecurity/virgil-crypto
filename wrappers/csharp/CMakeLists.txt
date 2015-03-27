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

project (${WRAPPED_LIB_NAME}_csharp)

# Configure cmake modules location
set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

# Configure C#
set (CSHARP_INSTALL_DIR csharp)
set (CSHARP_ASSEMBLY_NAME ${WRAPPED_LIB_NAME}.assembly)
set (CSHARP_MODULE_NAME ${PROJECT_NAME})
set (SWIG_MODULE_NAME ${CSHARP_MODULE_NAME})

# Find C#
find_package( CSharp REQUIRED )
include( ${CSHARP_USE_FILE} )

set (CSHARP_VIRGILCRYPTO_ASSEMBLY_VERSION "1.0.*")

# Make sure the nested directory structure exists
set (CSHARP_SOURCE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/src CACHE INTERNAL "")
set (CSHARP_BINARY_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin CACHE INTERNAL "")
set (CSHARP_SWIG_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/swig_gen CACHE INTERNAL "")
file (MAKE_DIRECTORY ${CSHARP_SOURCE_DIRECTORY})
file (MAKE_DIRECTORY ${CSHARP_BINARY_DIRECTORY})
file (MAKE_DIRECTORY ${CSHARP_SWIG_OUTPUT_DIRECTORY})

# Configure SWIG
find_package (SWIG REQUIRED)
include (${SWIG_USE_FILE})

set (CMAKE_SWIG_OUTDIR ${CSHARP_SWIG_OUTPUT_DIRECTORY})
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
    SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY SWIG_FLAGS "-ignoremissing"
)

swig_add_module (${CSHARP_MODULE_NAME} csharp ${WRAPPER_INTERFACE_FILE})
swig_link_libraries (${CSHARP_MODULE_NAME} ${WRAPPED_LIB_NAME})
add_custom_command (TARGET ${CSHARP_MODULE_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND}
        ARGS
            -DSRC_DIR:PATH=${CSHARP_SWIG_OUTPUT_DIRECTORY}
            -DDST_DIR:PATH=${CSHARP_SOURCE_DIRECTORY}
            -DGLOBBING_EXPRESSION:STRING="*.cs"
            -P ${CMAKE_SOURCE_DIR}/cmake/copy_all_files.cmake
        COMMENT "Copy generated source files from ${CSHARP_SWIG_OUTPUT_DIRECTORY} to ${CSHARP_SOURCE_DIRECTORY}."
    )


# Configure assembly
set (VIRGILCRYPTO_SWIG_TARGET_NAME ${SWIG_MODULE_${CSHARP_MODULE_NAME}_REAL_NAME})
set_target_properties (${VIRGILCRYPTO_SWIG_TARGET_NAME}
        PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CSHARP_BINARY_DIRECTORY})

# Configure AssemblyInfo.cs
configure_file (
    ${CMAKE_CURRENT_SOURCE_DIR}/AssemblyInfo.cs.in
    ${CSHARP_SOURCE_DIRECTORY}/AssemblyInfo.cs
    @ONLY
)

# Add assembly dependencies
csharp_add_library (${CSHARP_ASSEMBLY_NAME} "${CSHARP_SOURCE_DIRECTORY}/*.cs")
add_dependencies (${CSHARP_ASSEMBLY_NAME} ${VIRGILCRYPTO_SWIG_TARGET_NAME})

# Install
set (INSTALL_ARCH_DIR_NAME "")
if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin" AND CMAKE_OSX_ARCHITECTURES)
    if (CMAKE_OSX_ARCHITECTURES STREQUAL "i386")
        set (INSTALL_ARCH_DIR_NAME ${INSTALL_X86_DIR_NAME})
    elseif (CMAKE_OSX_ARCHITECTURES STREQUAL "x86_64")
        set (INSTALL_ARCH_DIR_NAME ${INSTALL_X64_DIR_NAME})
    endif ()
else ()
    if (COMPILER_ARCH_32)
        set (INSTALL_ARCH_DIR_NAME ${INSTALL_X86_DIR_NAME})
    elseif (COMPILER_ARCH_64)
        set (INSTALL_ARCH_DIR_NAME ${INSTALL_X64_DIR_NAME})
    endif ()
endif ()

install (TARGETS ${CSHARP_MODULE_NAME}
        RUNTIME DESTINATION "${CSHARP_INSTALL_DIR}/${INSTALL_BIN_DIR_NAME}/${INSTALL_ARCH_DIR_NAME}"
        LIBRARY DESTINATION "${CSHARP_INSTALL_DIR}/${INSTALL_LIB_DIR_NAME}/${INSTALL_ARCH_DIR_NAME}")

install (FILES "${CSHARP_BINARY_DIRECTORY}/${CSHARP_ASSEMBLY_NAME}.dll"
        DESTINATION "${CSHARP_INSTALL_DIR}/${INSTALL_LIB_DIR_NAME}")

