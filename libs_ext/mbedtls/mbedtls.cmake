#
# Copyright (C) 2015-2016 Virgil Security Inc.
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

cmake_minimum_required (VERSION @CMAKE_VERSION@ FATAL_ERROR)

project ("@VIRGIL_DEPENDS_PACKAGE_NAME@-depends")

include (ExternalProject)

set (BUILD_SHARED_LIBS @BUILD_SHARED_LIBS@)

if (BUILD_SHARED_LIBS)
    set (USE_STATIC_MBEDTLS_LIBRARY OFF)
    set (USE_SHARED_MBEDTLS_LIBRARY ON)
else (BUILD_SHARED_LIBS)
    set (USE_STATIC_MBEDTLS_LIBRARY ON)
    set (USE_SHARED_MBEDTLS_LIBRARY OFF)
endif (BUILD_SHARED_LIBS)

# Configure additional CMake parameters
file (APPEND "@VIRGIL_DEPENDS_ARGS_FILE@"
    "set (ENABLE_PROGRAMS OFF CACHE INTERNAL \"\")\n"
    "set (ENABLE_TESTING OFF CACHE INTERNAL \"\")\n"
    "set (USE_STATIC_MBEDTLS_LIBRARY ${USE_STATIC_MBEDTLS_LIBRARY} CACHE INTERNAL \"\")\n"
    "set (USE_SHARED_MBEDTLS_LIBRARY ${USE_SHARED_MBEDTLS_LIBRARY} CACHE INTERNAL \"\")\n"
)

# Configure custom MbedTLS 'config.h' file
set (MBEDTLS_CONFIGS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/configs")
configure_file (
    ${MBEDTLS_CONFIGS_DIR}/config.h
    ${CMAKE_CURRENT_BINARY_DIR}/configs/config.h
    COPYONLY
)

# Configure platform dependent MbedTLS 'config*.h' files
if (EXISTS "${MBEDTLS_CONFIGS_DIR}/config_${LANG}.h")
    configure_file (
        ${MBEDTLS_CONFIGS_DIR}/config_${LANG}.h
        ${CMAKE_CURRENT_BINARY_DIR}/configs/config_platform.h
        COPYONLY
    )
elseif (EXISTS "${MBEDTLS_CONFIGS_DIR}/config_${PLATFORM}.h")
    configure_file (
        ${MBEDTLS_CONFIGS_DIR}/config_${PLATFORM}.h
        ${CMAKE_CURRENT_BINARY_DIR}/configs/config_platform.h
        COPYONLY
    )
else ()
    configure_file (
        ${MBEDTLS_CONFIGS_DIR}/config_desktop.h
        ${CMAKE_CURRENT_BINARY_DIR}/configs/config_platform.h
        COPYONLY
    )
endif ()

ExternalProject_Add (${PROJECT_NAME}
    DOWNLOAD_DIR "@VIRGIL_DEPENDS_PACKAGE_DOWNLOAD_DIR@"
    URL "https://github.com/VirgilSecurity/mbedtls/archive/25057a3d714c5f8f77ebbb23a153ba5d84e43ea7.tar.gz"
    URL_HASH SHA1=93075f9e2242b1188334c9f88fe13f3efcda5162
    PREFIX "@VIRGIL_DEPENDS_PACKAGE_BUILD_DIR@"
    CMAKE_ARGS "@VIRGIL_DEPENDS_CMAKE_ARGS@" "${MBEDTLS_CMAKE_ARGS}"
    UPDATE_COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_BINARY_DIR}/configs
            ${CMAKE_CURRENT_BINARY_DIR}/src/${PROJECT_NAME}/include/mbedtls
)

add_custom_target ("${PROJECT_NAME}-build" ALL COMMENT "Build package ${PROJECT_NAME}")
add_dependencies ("${PROJECT_NAME}-build" ${PROJECT_NAME})
