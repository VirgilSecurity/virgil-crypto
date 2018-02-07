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

cmake_minimum_required (VERSION @CMAKE_VERSION@ FATAL_ERROR)

project (tinyformat VERSION 2.0.1 LANGUAGES CXX)

# Define names for configuration files
set (INCLUDE_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "The directory the headers are installed in")
set (INSTALL_CFG_DIR_NAME
    "lib/cmake/${PROJECT_NAME}" CACHE STRING
    "Path to the CMake configuration files be installed"
)
set (generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")
set (version_config "${generated_dir}/${PROJECT_NAME}-config-version.cmake")
set (project_config "${generated_dir}/${PROJECT_NAME}-config.cmake")

# Create configuration files
include (CMakePackageConfigHelpers)

# Write Version Config
write_basic_package_version_file (
    "${version_config}" COMPATIBILITY SameMajorVersion
)

# Write  Project Config
configure_package_config_file (
    "cmake/config.cmake.in"
    "${project_config}"
    INSTALL_DESTINATION "${INSTALL_CFG_DIR_NAME}"
    PATH_VARS INCLUDE_INSTALL_DIR
)

# Install headers
install (
    DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/src/"
    DESTINATION "include/tinyformat"
)

# Install configurations
install (
    FILES "${project_config}" "${version_config}"
    DESTINATION "${INSTALL_CFG_DIR_NAME}"
)
