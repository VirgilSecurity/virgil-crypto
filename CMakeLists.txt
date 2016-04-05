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

#
# Configurable variables:
#     - LANG                - name of target language (optional).
#     - LANG_VERSION        - minimum supported lang version (optional).
#     - PLATFORM            - name of target platform (optional).
#     - PLATFORM_VERSION    - minimum supported version of the target platform (optional).
#     - PLATFORM_ARCH       - target platform processor architecture (optional).
#
#     - LIB_LOW_LEVEL_API   - boolean value that defines whether to include low-level API or not.
#     - LIB_FILE_IO         - boolean value that defines whether to include module depends on file IO or not.
#                             or separate utilities.
#     - INSTALL_CORE_LIBS   - boolean value that defines whether install core library and it's dependencies or not,
#                             if this value is NO or undefined - only wrapped library will be installed.
#     - INSTALL_EXT_HEADERS - boolean value that defines whether install third-party library headers or not.
#     - ENABLE_TESTING      - boolean value that defines whether include unit testing or not.
#     - ENABLE_BENCHMARK    - boolean value that defines whether include benchmark or not.
#
#     - INSTALL_INC_DIR_NAME  - name of the directory where include will be installed.
#     - INSTALL_LIB_DIR_NAME  - name of the directory where libraries will be installed.
#     - INSTALL_BIN_DIR_NAME  - name of the directory where binaries will be installed.
#     - INSTALL_MAN_DIR_NAME  - name of the directory where man pages will be installed.
#     - INSTALL_DOC_DIR_NAME  - name of the directory where documentation will be installed.
#     - INSTALL_API_DIR_NAME  - name of the directory where API source files will be installed.
#
#     - DOXYGEN_EXCLUDE_PRIVATE - boolean value that defines whether to exclude private API
#                                 from Doxygen documentation or not
#
# Define variables:
#     - VIRGIL_VERSION           - library full version.
#     - VIRGIL_VERSION_MAJOR     - library major version number.
#     - VIRGIL_VERSION_MINOR     - library minor version number.
#     - VIRGIL_VERSION_PATCH     - library patch number.
#     - VIRGIL_SOVERSION         - library ABI version.
#     - VIRGIL_VERSION_FEATURE   - library version feature, i.e. rc1, or coolfeature, etc.
#     - VIRGIL_VERSION_FULL_NAME - library version full name, i.e. 1.3.4-rc1
#
#     - POINTER_SIZE         - compiler pointer size.
#
#     - CMAKE_ARGS           - list of CMake parameters in form -DVAR:TYPE=VAL
#
# Define platform specific variables (that are defined only if build for this platform):
#     - ANDROID_INSTALL_JNI_DIR_NAME - name of the directory where JNI libraries will be installed
#                                      for Android platform
#

cmake_minimum_required (VERSION 3.2 FATAL_ERROR)

# Set project name
project (VirgilSecurity)

# Set library version
set (VIRGIL_VERSION_MAJOR 1)
set (VIRGIL_VERSION_MINOR 4)
set (VIRGIL_VERSION_PATCH 0)
set (VIRGIL_VERSION_FEATURE rc1)
set (VIRGIL_VERSION ${VIRGIL_VERSION_MAJOR}.${VIRGIL_VERSION_MINOR}.${VIRGIL_VERSION_PATCH})
set (VIRGIL_SOVERSION 1)

if (VIRGIL_VERSION_FEATURE)
    set (VIRGIL_VERSION_FULL_NAME ${VIRGIL_VERSION}-${VIRGIL_VERSION_FEATURE})
else (VIRGIL_VERSION_FEATURE)
    set (VIRGIL_VERSION_FULL_NAME ${VIRGIL_VERSION})
endif (VIRGIL_VERSION_FEATURE)

message (STATUS "Virgil version: " ${VIRGIL_VERSION})
message (STATUS "Virgil soversion: " ${VIRGIL_SOVERSION})

# Configure path to custom modules
set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

# Add find_host_* utilities
include (find_host_utils)

# Define possible cmake_args
include (cmake_args)
set (CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
)
append_cmake_arg (CMAKE_ARGS NAME CMAKE_TOOLCHAIN_FILE TYPE PATH)
append_cmake_arg (CMAKE_ARGS NAME CMAKE_BUILD_TYPE TYPE STRING)
append_cmake_arg (CMAKE_ARGS NAME PLATFORM TYPE STRING)
append_cmake_arg (CMAKE_ARGS NAME PLATFORM_VERSION TYPE STRING)
if (NOT CMAKE_TOOLCHAIN_FILE)
    append_cmake_arg (CMAKE_ARGS NAME CMAKE_C_COMPILER TYPE STRING)
    append_cmake_arg (CMAKE_ARGS NAME CMAKE_C_FLAGS TYPE STRING)
    append_cmake_arg (CMAKE_ARGS NAME CMAKE_C_FLAGS_RELEASE TYPE STRING)
    append_cmake_arg (CMAKE_ARGS NAME CMAKE_C_FLAGS_DEBUG TYPE STRING)

    append_cmake_arg (CMAKE_ARGS NAME CMAKE_CXX_COMPILER TYPE STRING)
    append_cmake_arg (CMAKE_ARGS NAME CMAKE_CXX_FLAGS TYPE STRING)
    append_cmake_arg (CMAKE_ARGS NAME CMAKE_CXX_FLAGS_RELEASE TYPE STRING)
    append_cmake_arg (CMAKE_ARGS NAME CMAKE_CXX_FLAGS_DEBUG TYPE STRING)
endif ()
if (ANDROID)
    append_cmake_arg (CMAKE_ARGS NAME ANDROID_NDK TYPE PATH)
    append_cmake_arg (CMAKE_ARGS NAME ANDROID_ABI TYPE STRING)
    append_cmake_arg (CMAKE_ARGS NAME ANDROID_NATIVE_API_LEVEL TYPE STRING)
    append_cmake_arg (CMAKE_ARGS NAME ANDROID_TOOLCHAIN_NAME TYPE STRING)
    append_cmake_arg (CMAKE_ARGS NAME ANDROID_FORCE_ARM_BUILD TYPE BOOL)
    append_cmake_arg (CMAKE_ARGS NAME ANDROID_NO_UNDEFINED TYPE BOOL)
    append_cmake_arg (CMAKE_ARGS NAME ANDROID_SO_UNDEFINED TYPE BOOL)
    append_cmake_arg (CMAKE_ARGS NAME ANDROID_STL TYPE STRING)
    append_cmake_arg (CMAKE_ARGS NAME ANDROID_STL_FORCE_FEATURES TYPE BOOL)
endif (ANDROID)

if (CMAKE_TOOLCHAIN_FILE AND APPLE)
    append_cmake_arg (CMAKE_ARGS NAME SIMULATOR TYPE BOOL)
    append_cmake_arg (CMAKE_ARGS NAME CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT TYPE PATH)
    append_cmake_arg (CMAKE_ARGS NAME CMAKE_APPLE_SDK_ROOT TYPE PATH)
endif ()

# Define enviroment parameters
if (NOT DEFINED POINTER_SIZE)
    include (check_pointer_size)
    check_pointer_size (POINTER_SIZE)
    if (POINTER_SIZE)
        message (STATUS "Compiler pointer size: " ${POINTER_SIZE} " bytes")
    else ()
        message (STATUS "Compiler pointer size: UNDEFINED")
    endif ()
endif ()

# Configure language parameters
set (LANG "cpp" CACHE STRING "Target language")
set_property (CACHE LANG PROPERTY STRINGS
    "cpp"
    "csharp"
    "as3"
    "asmjs"
    "nodejs"
    "php"
    "java"
    "python"
    "ruby"
)
set (LIB_LOW_LEVEL_API OFF CACHE BOOL "Defines whether to include low-level API or not")
set (LIB_FILE_IO OFF CACHE BOOL "Defines whether to include module depends on file IO or not")
set (ENABLE_TESTING ON CACHE BOOL "Defines whether include unit testing or not.")
set (ENABLE_BENCHMARK OFF CACHE BOOL "Defines whether include benchmark or not.")

# Propogate some parameters as C/C++ defines
if (LIB_FILE_IO)
    add_definitions(-DLIB_FILE_IO)
endif (LIB_FILE_IO)

# Configure
find_host_package (Git)

# Configure path variables
set (INSTALL_INC_DIR_NAME include CACHE STRING "Installation directory name for includes")
set (INSTALL_LIB_DIR_NAME lib CACHE STRING "Installation directory name for libraries")
set (INSTALL_BIN_DIR_NAME bin CACHE STRING "Installation directory name for executables")
set (INSTALL_MAN_DIR_NAME "share/man" CACHE STRING "Installation directory name for man pages")
set (INSTALL_DOC_DIR_NAME "share/doc" CACHE STRING "Installation directory name for doc pages")
set (INSTALL_API_DIR_NAME api CACHE STRING "Installation directory name for interface files")

# Configure platform specific path variables
if (ANDROID)
    set (ANDROID_INSTALL_JNI_DIR_NAME "lib/${ANDROID_NDK_ABI_NAME}")
endif (ANDROID)

# Configure internal path variables
set (EXTERNAL_LIBS_DIR "${CMAKE_CURRENT_BINARY_DIR}/libs" CACHE INTERNAL
        "Path to the folder where all libs MUST be located after build")

# Configure submodules installation
set (INSTALL_CORE_LIBS_TMP OFF)
if (LANG STREQUAL "cpp")
    set (INSTALL_CORE_LIBS_TMP ON)
endif ()
set (INSTALL_CORE_LIBS ${INSTALL_CORE_LIBS_TMP} CACHE BOOL
        "Defines whether install core library and it's dependencies or not")
set (INSTALL_EXT_HEADERS OFF CACHE BOOL
        "Defines whether install third-party library headers or not")

# Configure Doxygen behaviour
set (DOXYGEN_EXCLUDE_PRIVATE ON CACHE BOOL "Exclude private API from Doxygen documentation")

# Configure testing
if (ENABLE_TESTING)
    enable_testing ()
    message (STATUS "Unit tests status: ENABLED")
else (ENABLE_TESTING)
    message (STATUS "Unit tests status: DISABLED")
endif (ENABLE_TESTING)

# Configure submodules
add_subdirectory (lib)
add_subdirectory (wrappers)

# Configure platform after submodules configuration
string (TOLOWER ${CMAKE_SYSTEM_NAME} PLATFORM_LOWER)
set (LANG_VERSION "" CACHE STRING "Target language minimum supported version")
set (PLATFORM "${PLATFORM_LOWER}" CACHE STRING "Target platform")
set (PLATFORM_VERSION_LOCAL "")
if (CMAKE_SYSTEM_VERSION)
    string (REPLACE "." ";" SYSTEM_VERSION_LIST ${CMAKE_SYSTEM_VERSION})
    list (LENGTH SYSTEM_VERSION_LIST SYSTEM_VERSION_LIST_LENGTH)
    if (${SYSTEM_VERSION_LIST_LENGTH} GREATER 0)
        list (GET SYSTEM_VERSION_LIST 0 SYSTEM_VERSION_MAJOR)
        set (PLATFORM_VERSION_LOCAL "${SYSTEM_VERSION_MAJOR}")
    endif (${SYSTEM_VERSION_LIST_LENGTH} GREATER 0)
    if (${SYSTEM_VERSION_LIST_LENGTH} GREATER 1)
        list (GET SYSTEM_VERSION_LIST 1 SYSTEM_VERSION_MINOR)
        set (PLATFORM_VERSION_LOCAL "${PLATFORM_VERSION_LOCAL}.${SYSTEM_VERSION_MINOR}")
    endif (${SYSTEM_VERSION_LIST_LENGTH} GREATER 1)
endif (CMAKE_SYSTEM_VERSION)
set (PLATFORM_VERSION "${PLATFORM_VERSION_LOCAL}" CACHE STRING "Target platform version")
set (PLATFORM_EMBEDDED NO CACHE BOOL "Mark target platform as embedded")
mark_as_advanced (PLATFORM_EMBEDDED PLATFORM_VERSION)
unset (PLATFORM_VERSION_LOCAL)

# Enable C++ tests and profiling only for native platforms
if (LANG STREQUAL "cpp" AND NOT PLATFORM_EMBEDDED)
    if (ENABLE_TESTING)
        add_subdirectory (tests)
    endif (ENABLE_TESTING)
    if (ENABLE_BENCHMARK)
        add_subdirectory (benchmark)
    endif (ENABLE_BENCHMARK)
endif (LANG STREQUAL "cpp" AND NOT PLATFORM_EMBEDDED)


# Define full platform name
set (LIB_NAME_FULL "virgil-crypto-${VIRGIL_VERSION_FULL_NAME}-${LANG}")

if (LANG AND LANG_VERSION)
    set (LIB_NAME_FULL "${LIB_NAME_FULL}-${LANG_VERSION}")
endif (LANG AND LANG_VERSION)

if (PLATFORM)
    set (LIB_NAME_FULL "${LIB_NAME_FULL}-${PLATFORM}")
endif (PLATFORM)

if (PLATFORM AND PLATFORM_VERSION)
    set (LIB_NAME_FULL "${LIB_NAME_FULL}-${PLATFORM_VERSION}")
endif (PLATFORM AND PLATFORM_VERSION)

file (WRITE "${CMAKE_CURRENT_BINARY_DIR}/lib_name.txt" "${LIB_NAME_FULL}")

if (PLATFORM_ARCH)
    set (LIB_NAME_FULL "${LIB_NAME_FULL}-${PLATFORM_ARCH}")
endif (PLATFORM_ARCH)

message (STATUS "Library full name: ${LIB_NAME_FULL}")

file (WRITE "${CMAKE_CURRENT_BINARY_DIR}/lib_name_full.txt" "${LIB_NAME_FULL}")

# Configure CPack
set (CPACK_GENERATOR STGZ TGZ ZIP)
set (CPACK_PACKAGE_DESCRIPTION_SUMMARY "Virgil Security Crypto library")
set (CPACK_PACKAGE_VENDOR "Virgil Security")
set (CPACK_PACKAGE_VERSION_MAJOR ${VIRGIL_VERSION_MAJOR})
set (CPACK_PACKAGE_VERSION_MINOR ${VIRGIL_VERSION_MINOR})
set (CPACK_PACKAGE_VERSION_PATCH ${VIRGIL_VERSION_PATCH})
set (CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
string (TOLOWER ${CMAKE_SYSTEM_NAME} CPACK_SYSTEM_NAME)
set (CPACK_PACKAGE_FILE_NAME "${LIB_NAME_FULL}")

include (CPack)
