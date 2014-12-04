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

project (${WRAPPED_LIB_NAME}_as3)

# Define module name
set (AS3_INSTALL_DIR as3)
set (AS3_MODULE_NAME ${PROJECT_NAME})
set (SWIG_MODULE_NAME ${AS3_MODULE_NAME})
set (SWIG_MODULE_NAMESPACE com.virgilsecurity.wrapper)

# Find required programs and libraries
find_package (Java REQUIRED)

if (NOT FLASCC)
    message (FATAL_ERROR "Path to Flash C++ (CrossBridge) SDK is not defined. Please specify FLASCC variable.")
endif ()

find_program (AS3_COMPILER name asc2.jar PATHS "${FLASCC}/usr/lib")
find_file (BUILTIN_ABC_LIB name builtin.abc PATHS "${FLASCC}/usr/lib")

# Configure inlcudes
set (INCLUDES "-I${${WRAPPED_LIB_NAME}_SOURCE_DIR}/include" "-I${CMAKE_CURRENT_SOURCE_DIR}/include")

# Build wrapper
set (WRAPPER_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/wrapper.cxx)
set (WRAPPER_OBJ ${CMAKE_CURRENT_BINARY_DIR}/wrapper.o)
add_custom_command (OUTPUT ${WRAPPER_OBJ}
    COMMAND ${CMAKE_CXX_COMPILER}
    ARGS -c ${CMAKE_CXX_FLAGS} ${INCLUDES}
    -o ${WRAPPER_OBJ} ${WRAPPER_SRC}
    DEPENDS ${WRAPPER_SRC}
)

# Build wrapper ABC
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/wrapper.as
    ${CMAKE_CURRENT_BINARY_DIR}/wrapper.as
    COPYONLY
)
set (WRAPPER_AS3 ${CMAKE_CURRENT_BINARY_DIR}/wrapper.as)
set (WRAPPER_ABC_LIB ${CMAKE_CURRENT_BINARY_DIR}/wrapper.abc)
add_custom_command (OUTPUT ${WRAPPER_ABC_LIB}
    COMMAND ${Java_JAVA_EXECUTABLE}
    ARGS -jar ${AS3_COMPILER} -merge -md -import ${BUILTIN_ABC_LIB} ${WRAPPER_AS3}
    DEPENDS ${BUILTIN_ABC_LIB}
    DEPENDS ${WRAPPER_AS3}
)

# Generate wrapper export methods list
set (COMMON_EXPORT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/src/public-api.txt)
set (WRAPPER_EXPORT_FILE ${CMAKE_CURRENT_BINARY_DIR}/wrapper_export.txt)
add_custom_command (OUTPUT ${WRAPPER_EXPORT_FILE}
    COMMAND cat ${COMMON_EXPORT_FILE} > ${WRAPPER_EXPORT_FILE}
    COMMAND nm  ${WRAPPER_OBJ} |
            grep ' T ' | awk '{print $$3}' | sed 's/__/_/' >> ${WRAPPER_EXPORT_FILE}
    COMMAND nm  $<TARGET_LINKER_FILE:${WRAPPED_LIB_NAME}> |
            grep ' T ' | awk '{print $$3}' | sed 's/__/_/' >> ${WRAPPER_EXPORT_FILE}
    COMMAND nm  ${CMAKE_BINARY_DIR}/libs/libpolarssl.a |
            grep ' T ' | awk '{print $$3}' | sed 's/__/_/' >> ${WRAPPER_EXPORT_FILE}
    COMMAND nm  ${CMAKE_BINARY_DIR}/libs/libjsoncpp.a |
            grep ' T ' | awk '{print $$3}' | sed 's/__/_/' >> ${WRAPPER_EXPORT_FILE}
    DEPENDS ${COMMON_EXPORT_FILE}
    DEPENDS ${WRAPPER_OBJ}
)

# Link wrapper with target library
set (WRAPPER_SWC ${CMAKE_CURRENT_BINARY_DIR}/${SWIG_MODULE_NAME}.swc)
add_custom_target (${SWIG_MODULE_NAME} ALL
    COMMAND ${CMAKE_CXX_COMPILER}
            -emit-swc=${SWIG_MODULE_NAMESPACE} -O3 -flto-api=${WRAPPER_EXPORT_FILE} -o ${WRAPPER_SWC}
            ${WRAPPER_OBJ} ${WRAPPER_ABC_LIB}
            $<TARGET_LINKER_FILE:${WRAPPED_LIB_NAME}> ${CMAKE_BINARY_DIR}/libs/libpolarssl.a
            ${CMAKE_BINARY_DIR}/libs/libjsoncpp.a -lAS3++
    DEPENDS ${WRAPPER_OBJ}
    DEPENDS ${WRAPPER_ABC_LIB}
    DEPENDS ${WRAPPER_EXPORT_FILE}
)
get_directory_property(SWIG_EXTRA_CLEAN_FILES ADDITIONAL_MAKE_CLEAN_FILES)
set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${WRAPPER_SWC}")

install (FILES ${WRAPPER_SWC}
        DESTINATION ${AS3_INSTALL_DIR}/${INSTALL_LIB_DIR_NAME})

# Unit tests
set (AS3_MODULE_FILE_NAME ${WRAPPER_SWC})
add_subdirectory (tests)

