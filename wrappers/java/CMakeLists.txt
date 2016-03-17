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

project (${WRAPPED_LIB_NAME}_java)

# Macros
macro (subdirlist result curdir)
  file (GLOB children ${curdir}/*)
  set (dirlist "")
  foreach (child ${children})
    if (IS_DIRECTORY ${child})
        list (APPEND dirlist ${child})
    endif ()
  endforeach ()
  set (${result} ${dirlist})
  unset (dirlist)
endmacro ()

# Configure Java
set (JAVA_MODULE_NAME ${PROJECT_NAME})
set (JAVA_JAR_NAME ${JAVA_MODULE_NAME})
set (JAVA_JAR_TARGET_NAME ${JAVA_MODULE_NAME}_jar)
set (SWIG_MODULE_NAME ${JAVA_MODULE_NAME})

# Find Java
find_host_package (Java REQUIRED)
include (UseJava)

# Find Java JNI
if (ANDROID)
    find_path (JAVA_INCLUDE_PATH jni.h)
    set (JNI_INCLUDE_DIRS ${JAVA_INCLUDE_PATH})
else (ANDROID)
    find_host_package (JNI REQUIRED)
endif (ANDROID)
include_directories (${JNI_INCLUDE_DIRS})

# Make sure the nested directory structure exists
set (JAVA_BINARY_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin CACHE INTERNAL "")
set (JAVA_SWIG_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/src CACHE INTERNAL "")
file (MAKE_DIRECTORY ${JAVA_BINARY_DIRECTORY})
file (MAKE_DIRECTORY ${JAVA_SWIG_OUTPUT_DIRECTORY})

# Configure SWIG
find_host_package (SWIG REQUIRED)
include (${SWIG_USE_FILE})

set (CMAKE_SWIG_OUTDIR ${JAVA_SWIG_OUTPUT_DIRECTORY})
set (CMAKE_SWIG_FLAGS "")

set (SWIG_WRAP_COPY_CONSTRUCTOR YES)
set (SWIG_WRAP_NAMESPACE NO)
set (WRAPPER_INTERFACE_FILE "${CMAKE_CURRENT_BINARY_DIR}/wrapper.i")
configure_file (
    "${wrappers_SOURCE_DIR}/swig/wrapper.i.in"
    "${WRAPPER_INTERFACE_FILE}"
)

set_property (SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY CPLUSPLUS ON)
set_property (
    SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY SWIG_FLAGS "-ignoremissing;-package;com.virgilsecurity.crypto"
)

swig_add_module (${JAVA_MODULE_NAME} java ${WRAPPER_INTERFACE_FILE})
swig_link_libraries (${JAVA_MODULE_NAME} ${WRAPPED_LIB_NAME})

set (JAVA_SWIG_TARGET_NAME ${SWIG_MODULE_${JAVA_MODULE_NAME}_REAL_NAME})

# Configure assembly
set_target_properties (${JAVA_SWIG_TARGET_NAME}
        PROPERTIES OUTPUT_NAME ${JAVA_MODULE_NAME})
set_target_properties (${JAVA_SWIG_TARGET_NAME}
        PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${JAVA_BINARY_DIRECTORY})
set_target_properties (${JAVA_SWIG_TARGET_NAME}
        PROPERTIES POSITION_INDEPENDENT_CODE ON)

if (UNIX AND NOT (${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))
    set_target_properties (${JAVA_SWIG_TARGET_NAME}
            PROPERTIES NO_SONAME OFF VERSION ${VIRGIL_VERSION} SOVERSION ${VIRGIL_SOVERSION})
endif ()

# Copy additional source files
file (GLOB_RECURSE JAVA_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.java")
foreach (JAVA_FILE ${JAVA_SRC})
    string (REPLACE "${CMAKE_CURRENT_SOURCE_DIR}/src/" "" JAVA_FILE_NAME ${JAVA_FILE})
    configure_file (
        ${CMAKE_CURRENT_SOURCE_DIR}/src/${JAVA_FILE_NAME}
        ${JAVA_SWIG_OUTPUT_DIRECTORY}/${JAVA_FILE_NAME}
        @ONLY
    )
endforeach (JAVA_FILE)

# Add assembly dependencies
add_jar (${JAVA_JAR_TARGET_NAME}
    "${CMAKE_CURRENT_BINARY_DIR}/src/VirgilStreamDataSink.java"
    OUTPUT_NAME ${JAVA_JAR_NAME}
)
add_dependencies (${JAVA_JAR_TARGET_NAME} ${JAVA_SWIG_TARGET_NAME})

# Payload 'java_sources' file with generated classes
get_property (JAVA_CLASS_DIR TARGET ${JAVA_JAR_TARGET_NAME} PROPERTY CLASS_DIR)
if (NOT JAVA_CLASS_DIR)
    get_property (JAVA_CLASS_DIR TARGET ${JAVA_JAR_TARGET_NAME} PROPERTY CLASSDIR)
endif ()
set (JAVA_SOURCE_LIST_FILE ${JAVA_CLASS_DIR}/java_sources)

add_custom_command (TARGET ${JAVA_SWIG_TARGET_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND}
        ARGS
            -DSRC_DIR:PATH=${JAVA_SWIG_OUTPUT_DIRECTORY}
            -DDST_FILE:PATH=${JAVA_SOURCE_LIST_FILE}
            -DGLOBBING_EXPRESSION:STRING="*.java"
            -P ${CMAKE_SOURCE_DIR}/cmake/aux_source_directory_to_file.cmake
        COMMENT "Create java source list file: ${JAVA_SOURCE_LIST_FILE}."
    )

# Install
set (PLATFORM_VERSION "${Java_VERSION_MAJOR}.${Java_VERSION_MINOR}" PARENT_SCOPE)

if (ANDROID)
    install (TARGETS ${JAVA_SWIG_TARGET_NAME}
            DESTINATION "${INSTALL_LIB_DIR_NAME}/${ANDROID_INSTALL_JNI_DIR_NAME}")
else ()
    install (TARGETS ${JAVA_SWIG_TARGET_NAME}
            DESTINATION "${INSTALL_LIB_DIR_NAME}")
endif (ANDROID)

install_jar (${JAVA_JAR_TARGET_NAME} "${INSTALL_LIB_DIR_NAME}")
