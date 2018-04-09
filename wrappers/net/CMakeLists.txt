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

project (${WRAPPED_LIB_NAME}_net)

# Capitalize first character in the wrapped library name
include (uppercase_first_char)
uppercase_first_char (${WRAPPED_LIB_NAME} WRAPPED_LIB_NAME_CAP)

# Configure cmake modules location
set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

# Configure C#
set (CSHARP_ASSEMBLY_NAME Virgil.Crypto)
set (CSHARP_MODULE_NAME ${PROJECT_NAME})
set (SWIG_MODULE_NAME ${CSHARP_MODULE_NAME})

# Find C#
find_host_package( CSharp REQUIRED )
include (${CSHARP_USE_FILE})

# Make sure the nested directory structure exists
set (CSHARP_SOURCE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/src CACHE INTERNAL "")
set (CSHARP_BINARY_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin CACHE INTERNAL "")
set (CSHARP_SWIG_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/swig_gen CACHE INTERNAL "")
file (MAKE_DIRECTORY ${CSHARP_SOURCE_DIRECTORY})
file (MAKE_DIRECTORY ${CSHARP_BINARY_DIRECTORY})
file (MAKE_DIRECTORY ${CSHARP_SWIG_OUTPUT_DIRECTORY})

# Configure SWIG
find_host_package (SWIG REQUIRED)
include (${SWIG_USE_FILE})

set (CMAKE_SWIG_OUTDIR ${CSHARP_SWIG_OUTPUT_DIRECTORY})
set (CMAKE_SWIG_FLAGS "")

set (SWIG_WRAP_COPY_CONSTRUCTOR YES)
set (SWIG_WRAP_NAMESPACE YES)
set (WRAPPER_INTERFACE_FILE "${CMAKE_CURRENT_BINARY_DIR}/wrapper.i")
configure_file (
    "${wrappers_SOURCE_DIR}/swig/wrapper.i.in"
    "${WRAPPER_INTERFACE_FILE}"
)
configure_file (
    "${wrappers_SOURCE_DIR}/swig/csharp/csharphead.swg.in"
    "${CMAKE_CURRENT_BINARY_DIR}/csharphead.swg"
)

set_property (SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY CPLUSPLUS ON)
set_property (
    SOURCE "${WRAPPER_INTERFACE_FILE}" PROPERTY SWIG_FLAGS "-ignoremissing"
)

if (CMAKE_CROSSCOMPILING AND (APPLE OR ANDROID))
    set (WRAPPER_TYPE STATIC)
else ()
    set (WRAPPER_TYPE SHARED)
endif ()

swig_add_library (${CSHARP_MODULE_NAME}
    TYPE ${WRAPPER_TYPE}
    LANGUAGE csharp
    SOURCES ${WRAPPER_INTERFACE_FILE}
)
set (CSHARP_SWIG_TARGET_NAME ${SWIG_MODULE_${CSHARP_MODULE_NAME}_REAL_NAME})

# todo remove patching for mono when the issue https://github.com/swig/swig/issues/1165 is closed.
if (WRAPPER_TYPE STREQUAL "STATIC")

 set (delegate_expression "\"public delegate \"")
    set (set_pending_expression "\"static void SetPending\"")
    set (set_pending_argument_expression "\"static void SetPendingArgument\"")
    set (create_string_expression "\"static string CreateString\"")
    set (get_array_size_expression "\"static int GetManaged_byte_ArraySize\"")
    set (create_managed_array_expression "\"static System.IntPtr CreateManaged_byte_Array\"")
    set (copy_to_unmanaged_expression "\"static void CopyToUnmanaged_byte_Array\"")
    set (get_array_size_expression "\"static int GetManaged_byte_ArraySize\"")
    set (get_array_size_expression "\"static int GetManaged_byte_ArraySize\"")
    set (mono_callback "[global::ObjCRuntime.MonoPInvokeCallback\(typeof\(")
    set (new_line "\\n")

    add_custom_command (TARGET ${CSHARP_SWIG_TARGET_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND}
        ARGS
            -DSRC:PATH="${CSHARP_SWIG_OUTPUT_DIRECTORY}/${CSHARP_MODULE_NAME}PINVOKE.cs"
            -DDLL_IMPORT_REGEXP:STRING="DllImport\\\(\\\"${CSHARP_MODULE_NAME}\\\""
            -DDLL_IMPORT_REPLACE_EXPR:STRING="DllImport\(\\\"__Internal\\\""
            -DDELEGATE_REGEXP:STRING="${delegate_expression}"
            -DDELEGATE_REPLACE_EXPR:STRING="[global::ObjCRuntime.MonoNativeFunctionWrapper]${new_line}${delegate_expression}"
            -DSET_PENDING_REGEXP:STRING="${set_pending_expression}"
            -DSET_PENDING_REPLACE_EXPR:STRING="${mono_callback}ExceptionDelegate\)\)]${new_line}${set_pending_expression}"
            -DSET_PENDING_ARGUMENT_REGEXP:STRING="ExceptionDelegate\\\)\\\)].?${set_pending_argument_expression}"
            -DSET_PENDING_ARGUMENT_REPLACE_EXPR:STRING="ExceptionArgumentDelegate\)\)]${new_line}${set_pending_argument_expression}"
            -DCREATE_STRING_REGEXP:STRING="${create_string_expression}"
            -DCREATE_STRING_REPLACE_EXPR:STRING="${mono_callback}SWIGStringDelegate\)\)]${new_line}${create_string_expression}"
            -DCREATE_MANAGED_ARRAY_REGEXP:STRING="${create_managed_array_expression}"
            -DCREATE_MANAGED_ARRAY_REPLACE_EXPR:STRING="${mono_callback}CreateManaged_byte_ArrayDelegate\)\)]${new_line}${create_managed_array_expression}"
            -DGET_ARRAY_SIZE_REGEXP:STRING="${get_array_size_expression}"
            -DGET_ARRAY_SIZE_REPLACE_EXPR:STRING="${mono_callback}GetManaged_byte_ArraySizeDelegate\)\)]${new_line}${get_array_size_expression}"
            -DCOPY_TO_UNMANAGED_REGEXP:STRING="${copy_to_unmanaged_expression}"
            -DCOPY_TO_UNMANAGED_REPLACE_EXPR:STRING="${mono_callback}CopyToUnmanaged_byte_ArrayDelegate\)\)]${new_line}${copy_to_unmanaged_expression}"
            -P ${CMAKE_SOURCE_DIR}/cmake/file_regex_replace_mono.cmake
        COMMENT "Patch generated source files for mono."
    )
endif ()

swig_link_libraries (${CSHARP_SWIG_TARGET_NAME} ${WRAPPED_LIB_NAME})

add_custom_command (TARGET ${CSHARP_SWIG_TARGET_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND}
    ARGS
        -DSRC_DIR:PATH=${CSHARP_SWIG_OUTPUT_DIRECTORY}
        -DDST_DIR:PATH=${CSHARP_SOURCE_DIRECTORY}
        -DGLOBBING_EXPRESSION:STRING="*.cs"
        -P ${CMAKE_SOURCE_DIR}/cmake/copy_all_files.cmake
    COMMENT "Copy generated source files from ${CSHARP_SWIG_OUTPUT_DIRECTORY} to ${CSHARP_SOURCE_DIRECTORY}."
)

add_custom_command (TARGET ${CSHARP_SWIG_TARGET_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND}
    ARGS
        -DSRC_DIR:PATH=${CSHARP_SOURCE_DIRECTORY}
        -DGLOBBING_EXPRESSION:STRING="*.cs"
        -P ${CMAKE_SOURCE_DIR}/cmake/uppercase_namespaces.cmake
    COMMENT "Uppercase C# namespaces for ${CSHARP_SOURCE_DIRECTORY}/*.cs"
)

if (UNIX AND NOT APPLE)
    if (CMAKE_SYSTEM_NAME MATCHES "Android")
        string(REPLACE "<CMAKE_SHARED_LIBRARY_SONAME_CXX_FLAG><TARGET_SONAME>" ""
                CMAKE_CXX_CREATE_SHARED_MODULE "${CMAKE_CXX_CREATE_SHARED_MODULE}")
    else ()
        set_target_properties (${CSHARP_SWIG_TARGET_NAME}
                PROPERTIES NO_SONAME OFF VERSION ${VIRGIL_VERSION} SOVERSION ${VIRGIL_SOVERSION})
    endif ()
endif ()

# Configure assembly
set_target_properties (${CSHARP_SWIG_TARGET_NAME}
        PROPERTIES OUTPUT_NAME ${CSHARP_MODULE_NAME})
set_target_properties (${CSHARP_SWIG_TARGET_NAME}
        PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CSHARP_BINARY_DIRECTORY})
set_target_properties (${CSHARP_SWIG_TARGET_NAME}
        PROPERTIES POSITION_INDEPENDENT_CODE ON)

file (GLOB_RECURSE ASSEMBLY_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cs")
foreach (CS_FILE ${ASSEMBLY_SRC})
    string (REPLACE "${CMAKE_CURRENT_SOURCE_DIR}/src/" "" CS_FILE_NAME ${CS_FILE})
    configure_file (
        ${CMAKE_CURRENT_SOURCE_DIR}/src/${CS_FILE_NAME}
        ${CSHARP_SOURCE_DIRECTORY}/${CS_FILE_NAME}
        @ONLY
    )
endforeach (CS_FILE)

# Add assembly dependencies
csharp_add_library (${CSHARP_ASSEMBLY_NAME} "${CSHARP_SOURCE_DIRECTORY}/*.cs")
add_dependencies (${CSHARP_ASSEMBLY_NAME} ${CSHARP_SWIG_TARGET_NAME})

# Install
set (INSTALL_ARCH_DIR_NAME "")
if (WIN32 AND NOT CYGWIN)
    if (POINTER_SIZE EQUAL 4)
        set (INSTALL_ARCH_DIR_NAME x86)
    elseif (POINTER_SIZE EQUAL 8)
        set (INSTALL_ARCH_DIR_NAME x64)
    endif ()
endif ()

if (ANDROID)
    install (TARGETS ${CSHARP_SWIG_TARGET_NAME}
            DESTINATION "${INSTALL_LIB_DIR_NAME}/${ANDROID_INSTALL_JNI_DIR_NAME}")
else ()
    install (TARGETS ${CSHARP_SWIG_TARGET_NAME}
            DESTINATION "${INSTALL_LIB_DIR_NAME}/${INSTALL_ARCH_DIR_NAME}")
endif (ANDROID)

install (FILES "${CSHARP_BINARY_DIRECTORY}/${CSHARP_ASSEMBLY_NAME}.dll"
        DESTINATION "${INSTALL_LIB_DIR_NAME}")

if (WIN32)
    set (LANG "net" CACHE STRING "For Windows platform this value is forced" FORCE)
else ()
    set (LANG "mono" CACHE STRING "For *nix platforms this value is forced" FORCE)
endif ()
