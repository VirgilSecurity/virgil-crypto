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

# An extrenal project for PolarSSL library build
#
# Define variables:
#     - MBEDTLS_LIBRARY_NAME - library file name
#     - MBEDTLS_INCLUDE_DIR  - full path to the library includes
#     - MBEDTLS_LIBRARY      - full path to the library
#

include(CheckCCompilerFlag)

set (MBEDTLS_PROJECT_NAME mbedtls_project)

if (NOT CMAKE_CROSSCOMPILING)
    # Configure compiler settings
    check_c_compiler_flag (-fPIC COMPILER_SUPPORT_PIC)
    if (COMPILER_SUPPORT_PIC)
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
    endif()
endif (NOT CMAKE_CROSSCOMPILING)

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin" AND CMAKE_OSX_ARCHITECTURES)
    foreach (arch ${CMAKE_OSX_ARCHITECTURES})
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -arch ${arch}")
    endforeach (arch)
endif ()

# Confugure additional CMake parameters
append_cmake_arg (CMAKE_ARGS NAME ENABLE_PROGRAMS TYPE BOOL VALUE OFF)
append_cmake_arg (CMAKE_ARGS NAME ENABLE_TESTING TYPE BOOL VALUE OFF)
if (NOT CMAKE_TOOLCHAIN_FILE)
    append_cmake_arg (CMAKE_ARGS NAME CMAKE_C_COMPILER TYPE STRING)
    append_cmake_arg (CMAKE_ARGS NAME CMAKE_C_FLAGS TYPE STRING)
    append_cmake_arg (CMAKE_ARGS NAME CMAKE_C_FLAGS_RELEASE TYPE STRING)
    append_cmake_arg (CMAKE_ARGS NAME CMAKE_C_FLAGS_DEBUG TYPE STRING)
endif ()

# Add external project build steps
set (MBEDTLS_CONFIGURE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/configure")
set (MBEDTLS_CONFIG_DEFINES "${MBEDTLS_CONFIGURE_DIR}/settings/defines.yml")
set (MBEDTLS_CONFIG_PLATFORM_DEFINES_LANG "${MBEDTLS_CONFIGURE_DIR}/settings/defines_${LANG}.yml")
set (MBEDTLS_CONFIG_PLATFORM_DEFINES_PLATFROM "${MBEDTLS_CONFIGURE_DIR}/settings/defines_${PLATFORM}.yml")

set (CONFIGURE_COMMAND_ARGS
    --input-dir=<SOURCE_DIR>
    --config-defines=${MBEDTLS_CONFIG_DEFINES}
)

if (EXISTS ${MBEDTLS_CONFIG_PLATFORM_DEFINES_LANG})
    list (APPEND CONFIGURE_COMMAND_ARGS
        --config-platform-defines=${MBEDTLS_CONFIG_PLATFORM_DEFINES_LANG}
    )
endif ()

if (EXISTS ${MBEDTLS_CONFIG_PLATFORM_DEFINES_PLATFROM})
    list (APPEND CONFIGURE_COMMAND_ARGS
        --config-platform-defines=${MBEDTLS_CONFIG_PLATFORM_DEFINES_PLATFROM}
    )
endif ()

ExternalProject_Add (${MBEDTLS_PROJECT_NAME}
    GIT_REPOSITORY "https://github.com/VirgilSecurity/mbedtls.git"
    GIT_TAG "f4112c60cbd6203f9b7cafec45faa761f82fe3be"
    PREFIX "${CMAKE_CURRENT_BINARY_DIR}/mbedtls"
    CMAKE_ARGS ${CMAKE_ARGS}
    UPDATE_COMMAND python "${MBEDTLS_CONFIGURE_DIR}/configure.py" ${CONFIGURE_COMMAND_ARGS}
)

# Payload targets and output variables
ExternalProject_Get_Property (${MBEDTLS_PROJECT_NAME} INSTALL_DIR)

set (MBEDTLS_LIBRARY_NAME ${CMAKE_STATIC_LIBRARY_PREFIX}mbedtls${CMAKE_STATIC_LIBRARY_SUFFIX})
set (MBEDTLS_INCLUDE_DIR "${INSTALL_DIR}/include")
set (MBEDTLS_LIBRARY "${INSTALL_DIR}/lib/${MBEDTLS_LIBRARY_NAME}")

# Workaround of http://public.kitware.com/Bug/view.php?id=14495
file (MAKE_DIRECTORY ${MBEDTLS_INCLUDE_DIR})

add_custom_target (copy_mbedtls_lib
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${MBEDTLS_LIBRARY}"
            "${EXTERNAL_LIBS_DIR}/${MBEDTLS_LIBRARY_NAME}"
    DEPENDS ${MBEDTLS_PROJECT_NAME}
)

add_library (mbedtls STATIC IMPORTED)
set_property (TARGET mbedtls PROPERTY IMPORTED_LOCATION ${MBEDTLS_LIBRARY})
set_property (TARGET mbedtls PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MBEDTLS_INCLUDE_DIR})
add_dependencies (mbedtls ${MBEDTLS_PROJECT_NAME} copy_mbedtls_lib)

set (MBEDTLS_LIBRARY_NAME ${MBEDTLS_LIBRARY_NAME} PARENT_SCOPE)
set (MBEDTLS_INCLUDE_DIR ${MBEDTLS_INCLUDE_DIR} PARENT_SCOPE)
set (MBEDTLS_LIBRARY ${MBEDTLS_LIBRARY} PARENT_SCOPE)
