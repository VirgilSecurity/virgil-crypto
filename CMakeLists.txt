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
#     - PLATFORM_NAME     - name of target platform and/or language.
#     - LOW_LEVEL_API     - boolean value that defines whether to include low-level API or not.
#     - LIB_FILE_IO       - boolean value that defines whether to include module depends on file IO or not.
#     - CPP_BUILD_CLI     - boolean value that defines whether build C++ CLI or not.
#     - CPP_SPLIT_CLI     - boolean value that defines whether split C++ CLI to separate utilities or not.
#                           or separate utilities.
#     - INSTALL_CORE_LIB  - boolean value that defines whether install core library and it's dependencies or not,
#                           if this value is NO or undefined - only wrapped library will be installed.
#     - ENABLE_TESTING    - boolean value that defines whether include unit testing or not.
#
#     - INSTALL_INC_DIR_NAME  - name of the directory where include will be installed.
#     - INSTALL_LIB_DIR_NAME  - name of the directory where libraries will be installed.
#     - INSTALL_BIN_DIR_NAME  - name of the directory where binaries will be installed.
#     - INSTALL_MAN_DIR_NAME  - name of the directory where man pages will be installed.
#     - INSTALL_DOC_DIR_NAME  - name of the directory where documentation will be installed.
#     - INSTALL_API_DIR_NAME  - name of the directory where API source files will be installed.
#
# Define variables:
#     - PLATFORM_NAME_LOWER   - lowercase(PLATFORM_NAME).
#     - POINTER_SIZE          - compiler pointer size.
#
#     - VIRGIL_VERSION       - library full version.
#     - VIRGIL_VERSION_MAJOR - library major version number.
#     - VIRGIL_VERSION_MINOR - library minor version number.
#     - VIRGIL_VERSION_PATCH - library patch number.
#     - VIRGIL_SOVERSION     - library ABI version.
#
#     - CPP_CLI_VERSION       - C++ CLI full version.
#     - CPP_CLI_VERSION_MAJOR - C++ CLI major version number.
#     - CPP_CLI_VERSION_MINOR - C++ CLI minor version number.
#     - CPP_CLI_VERSION_PATCH - C++ CLI patch number.
#

cmake_minimum_required (VERSION 2.8 FATAL_ERROR)

# Set project name
project (VirgilSecurity)

# Configure path to custom modules
set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

# Define enviroment parameters
include (check_pointer_size)
check_pointer_size (POINTER_SIZE)
if (POINTER_SIZE)
    message (STATUS "Compiler pointer size: " ${POINTER_SIZE} " bytes")
else ()
    message (STATUS "Compiler pointer size: UNDEFINED")
endif ()

# Set library version
set (VIRGIL_VERSION_MAJOR 0)
set (VIRGIL_VERSION_MINOR 8)
set (VIRGIL_VERSION_PATCH 0)
set (VIRGIL_VERSION ${VIRGIL_VERSION_MAJOR}.${VIRGIL_VERSION_MINOR}.${VIRGIL_VERSION_PATCH})
set (VIRGIL_SOVERSION 1)
message (STATUS "Virgil version: " ${VIRGIL_VERSION})
message (STATUS "Virgil soversion: " ${VIRGIL_SOVERSION})

# Configure platform
if (CMAKE_CROSSCOMPILING AND NOT PLATFORM_NAME)
    set (PLATFORM_NAME ${CMAKE_SYSTEM_NAME} CACHE STRING "Target platform / language")
else ()
    set (PLATFORM_NAME "CPP" CACHE STRING "Target platform / language")
    set_property (CACHE PLATFORM_NAME PROPERTY STRINGS "CPP" "CSHARP" "AS3" "JS" "PHP")
endif ()
string (TOLOWER "${PLATFORM_NAME}" PLATFORM_NAME_LOWER)
message (STATUS "Selected platform and/or language is: " ${PLATFORM_NAME})

set (LOW_LEVEL_API OFF CACHE BOOL "Defines whether to include low-level API or not")
set (LIB_FILE_IO OFF CACHE BOOL "Defines whether to include module depends on file IO or not")
set (CPP_BUILD_CLI OFF CACHE BOOL "Defines whether build C++ CLI or not")
set (CPP_SPLIT_CLI OFF CACHE BOOL "Defines whether split C++ CLI to separate utilities or not")
set (ENABLE_TESTING ON CACHE BOOL "Defines whether include unit testing or not.")

# Platform dependent configuration
if (NOT CMAKE_CROSSCOMPILING AND ${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    if (NOT CMAKE_OSX_ARCHITECTURES)
        set (CMAKE_OSX_ARCHITECTURES "x86_64;i386" CACHE STRING "" FORCE)
    endif ()
    message (STATUS "OS X architectures: ${CMAKE_OSX_ARCHITECTURES}")
endif ()

# Configure path variables
set (INSTALL_INC_DIR_NAME include CACHE STRING "Installation directory name for includes")
set (INSTALL_LIB_DIR_NAME lib CACHE STRING "Installation directory name for libraries")
set (INSTALL_BIN_DIR_NAME bin CACHE STRING "Installation directory name for executables")
set (INSTALL_MAN_DIR_NAME "share/man" CACHE STRING "Installation directory name for man pages")
set (INSTALL_DOC_DIR_NAME "share/doc" CACHE STRING "Installation directory name for doc pages")
set (INSTALL_API_DIR_NAME api CACHE STRING "Installation directory name for interface files")

# Configure internal path variables
set (EXTERNAL_LIBS_DIR "${CMAKE_CURRENT_BINARY_DIR}/libs" CACHE INTERNAL
        "Path to the folder where all libs MUST be located after build")

# Configure submodules installation
set (INSTALL_CORE_LIB_TMP OFF)
if ((PLATFORM_NAME_LOWER STREQUAL "cpp") OR
        (PLATFORM_NAME_LOWER STREQUAL "pnacl") OR
        (PLATFORM_NAME_LOWER STREQUAL "ios"))
    set (INSTALL_CORE_LIB_TMP ON)
endif ()
set (INSTALL_CORE_LIB ${INSTALL_CORE_LIB_TMP} CACHE BOOL
        "defines whether install core library and it's dependencies or not")

# Configure testing
if (ENABLE_TESTING)
    enable_testing ()
    message (STATUS "Unit tests status: ENABLED")
else (ENABLE_TESTING)
    message (STATUS "Unit tests status: DISABLED")
endif (ENABLE_TESTING)

# Build submodules
add_subdirectory (lib)
if (PLATFORM_NAME_LOWER STREQUAL "cpp")
    if (ENABLE_TESTING)
        add_subdirectory (tests)
    endif (ENABLE_TESTING)
    if (CPP_BUILD_CLI)
        if (NOT LIB_FILE_IO)
            message (FATAL_ERROR "C++ CLI prerequisite failed: LIB_FILE_IO is OFF")
        endif (NOT LIB_FILE_IO)
        message (STATUS "C++ CLI status: ENABLED")
        # Set C++ CLI version
        set (CPP_CLI_VERSION_MAJOR 0)
        set (CPP_CLI_VERSION_MINOR 1)
        set (CPP_CLI_VERSION_PATCH 0)
        set (CPP_CLI_VERSION ${CPP_CLI_VERSION_MAJOR}.${CPP_CLI_VERSION_MINOR}.${CPP_CLI_VERSION_PATCH})
        message (STATUS "C++ CLI version: " ${CPP_CLI_VERSION})
        add_subdirectory (cli)
    else (CPP_BUILD_CLI)
        message (STATUS "C++ CLI status: DISABLED")
    endif(CPP_BUILD_CLI)
endif ()
add_subdirectory (wrappers)
