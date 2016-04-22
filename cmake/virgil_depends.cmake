#
# Copyright (C) 2016 Virgil Security Inc.
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
# This is in-house dependency loader based on pure CMake features.
# Usage:
#     1. Create cmake configuration file for target dependency from the next template
#
#         cmake_minimum_required (VERSION @CMAKE_VERSION@ FATAL_ERROR)
#
#         project ("@VIRGIL_DEPENDS_PACKAGE_NAME@-depends")
#
#         include (ExternalProject)
#
#         # Configure additional CMake parameters
#         file (WRITE "@VIRGIL_DEPENDS_ARGS_FILE@"
#             "set (XXXXXXX OFF CACHE INTERNAL \"\")\n"
#             "set (YYYYYYY ON CACHE INTERNAL \"\")\n"
#         )
#
#         ExternalProject_Add (${PROJECT_NAME}
#             DOWNLOAD_DIR "@VIRGIL_DEPENDS_CACHE_DIR@"
#             URL "https://github.com/....."
#             URL_HASH SHA256=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
#             PREFIX "@VIRGIL_DEPENDS_BUILD_DIR@"
#             CMAKE_ARGS "@VIRGIL_DEPENDS_CMAKE_ARGS@"
#         )
#
#         add_custom_target ("${PROJECT_NAME}-build" ALL COMMENT "Build package ${PROJECT_NAME}")
#         add_dependencies ("${PROJECT_NAME}-build" ${PROJECT_NAME})
#
#     2. In the project just put
#
#          include (virgil_depends)
#
#          virgil_depends (
#              PACKAGE_NAME "zzzzz"
#              VERSION "x.y"
#              CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dir_to_config_file_from_step_1"
#              CMAKE_ARGS "${OPTIONAL_VARIABLE_WITH_ADITIONAL_CMAKE_PARAMETERS}"
#          )
#


cmake_minimum_required(VERSION 3.2 FATAL_ERROR)

include (CMakeParseArguments)

function (virgil_depends_log_error)
    message ("")
    foreach(msg ${ARGV})
        message("[** ERROR **] ${msg}")
    endforeach()
    message ("")
    message(FATAL_ERROR "")
endfunction (virgil_depends_log_error)

function (virgil_depends_log_info)
    if (NOT VIRGIL_DEPENDS_LOG_INFO AND NOT VIRGIL_DEPENDS_LOG_DEBUG)
        return ()
    endif ()
    message ("")
    foreach(msg ${ARGV})
        message("[** INFO **] ${msg}")
    endforeach()
    message ("")
endfunction (virgil_depends_log_info)

function (virgil_depends_log_debug)
    if (NOT VIRGIL_DEPENDS_LOG_DEBUG)
        return ()
    endif ()
    message ("")
    foreach(msg ${ARGV})
        message("[** DEBUG **] ${msg}")
    endforeach()
    message ("")
endfunction (virgil_depends_log_debug)

function (virgil_depends_write_cache_var file var)
    if (DEFINED ${var})
        virgil_depends_log_debug (
            "Forwarding: ${var} = ${${var}}"
        )
        file (APPEND "${file}"
            "set (${var} \"${${var}}\" CACHE INTERNAL \"\")\n"
        )
    endif ()
endfunction ()

function (virgil_depends_create_cache_file cache_path)
    if (EXISTS "${cache_path}")
        return ()
    endif ()
    # Pass compiler flags if not toolchain case
    if (NOT CMAKE_CROSSCOMPILING)
        string (TOUPPER "${CMAKE_BUILD_TYPE}" configuration)
        foreach (lang C CXX)
            virgil_depends_write_cache_var ("${cache_path}" "CMAKE_${lang}_COMPILER")
            virgil_depends_write_cache_var ("${cache_path}" "CMAKE_${lang}_FLAGS")
            virgil_depends_write_cache_var ("${cache_path}" "CMAKE_${lang}_FLAGS_${configuration}")
        endforeach ()
    endif ()
    # Pass OS X architectures
    virgil_depends_write_cache_var ("${cache_path}" "CMAKE_OSX_ARCHITECTURES")
    # Pass DEBUG
    virgil_depends_write_cache_var ("${cache_path}" "CMAKE_VERBOSE_MAKEFILE")
endfunction ()

# Exported variables:
#     VIRGIL_DEPENDS_PREFIX
function (virgil_depends)
    # Parse arguments
    set (_one_value PACKAGE_NAME VERSION CONFIG_DIR)
    set (_multi_value CMAKE_ARGS)
    cmake_parse_arguments (VIRGIL_DEPENDS "" "${_one_value}" "${_multi_value}" ${ARGN})
    if (VIRGIL_DEPENDS_UNPARSED_ARGUMENTS)
        virgil_depends_log_error ("unexpected argument: ${VIRGIL_DEPENDS_UNPARSED_ARGUMENTS}")
    endif ()
    if (NOT VIRGIL_DEPENDS_PACKAGE_NAME)
        virgil_depends_log_error ("PACKAGE_NAME can't be empty")
    endif ()
    string (TOLOWER "${VIRGIL_DEPENDS_PACKAGE_NAME}" VIRGIL_DEPENDS_PACKAGE_NAME_LOWER)

    if (NOT VIRGIL_DEPENDS_CONFIG_DIR)
        virgil_depends_log_error("CONFIG_DIR can't be empty")
    endif ()
    if (NOT VIRGIL_DEPENDS_VERSION)
        set (VIRGIL_DEPENDS_VERSION)
    endif ()
    if (NOT VIRGIL_DEPENDS_CMAKE_ARGS)
        set (VIRGIL_DEPENDS_CMAKE_ARGS "")
    endif ()

    # Do nothing if given package exists
    if (${VIRGIL_DEPENDS_PACKAGE_NAME}_DIR)
        return ()
    endif ()

    set (VIRGIL_DEPENDS_CACHE_DIR "${CMAKE_SOURCE_DIR}/.depends_cache"
            CACHE PATH "Temporary folder that holds all downloaded dependencies")

    set (VIRGIL_DEPENDS_PREFIX "${CMAKE_BINARY_DIR}/depends/installed")
    set (VIRGIL_DEPENDS_HOME_DIR "${CMAKE_BINARY_DIR}/depends/${VIRGIL_DEPENDS_PACKAGE_NAME}")
    set (VIRGIL_DEPENDS_BUILD_DIR "${VIRGIL_DEPENDS_HOME_DIR}/build")

    set (VIRGIL_DEPENDS_CACHE_FILE "${CMAKE_BINARY_DIR}/cmake_cache.cmake")
    set (VIRGIL_DEPENDS_ARGS_FILE "${VIRGIL_DEPENDS_HOME_DIR}/${VIRGIL_DEPENDS_PACKAGE_NAME}_args.cmake")

    if (EXISTS "${VIRGIL_DEPENDS_CONFIG_DIR}/${VIRGIL_DEPENDS_PACKAGE_NAME}.cmake")
        set (VIRGIL_DEPENDS_PACKAGE_CONFIG_FILE
                "${VIRGIL_DEPENDS_CONFIG_DIR}/${VIRGIL_DEPENDS_PACKAGE_NAME}.cmake")
    elseif (EXISTS "${VIRGIL_DEPENDS_CONFIG_DIR}/${VIRGIL_DEPENDS_PACKAGE_NAME_LOWER}.cmake")
        set (VIRGIL_DEPENDS_PACKAGE_CONFIG_FILE
                "${VIRGIL_DEPENDS_CONFIG_DIR}/${VIRGIL_DEPENDS_PACKAGE_NAME_LOWER}.cmake")
    else ()
        virgil_depends_log_error(
            "${VIRGIL_DEPENDS_PACKAGE_NAME}.cmake file nor ${VIRGIL_DEPENDS_PACKAGE_NAME_LOWER}.cmake"
            "    are exist in ${VIRGIL_DEPENDS_CONFIG_DIR}"
        )
    endif ()

    virgil_depends_create_cache_file ("${VIRGIL_DEPENDS_CACHE_FILE}")
    file (WRITE "${VIRGIL_DEPENDS_ARGS_FILE}" "")

    file (GLOB _cfg_files "${VIRGIL_DEPENDS_CONFIG_DIR}/*")
    foreach (_file ${_cfg_files})
        file (COPY "${_file}" DESTINATION "${VIRGIL_DEPENDS_HOME_DIR}")
    endforeach ()
    set (_cfg_files)
    set (_file)

    set (VIRGIL_DEPENDS_CMAKE_ARGS
        "-G${CMAKE_GENERATOR}"
        "-C${VIRGIL_DEPENDS_CACHE_FILE}"
        "-C${VIRGIL_DEPENDS_ARGS_FILE}"
        "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
        "-DCMAKE_INSTALL_PREFIX=${VIRGIL_DEPENDS_PREFIX}"
        "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}"
        "${VIRGIL_DEPENDS_CMAKE_ARGS}"
    )

    configure_file (
        "${VIRGIL_DEPENDS_PACKAGE_CONFIG_FILE}"
        "${VIRGIL_DEPENDS_HOME_DIR}/CMakeLists.txt"
        @ONLY
    )

    set (cmd
        "${CMAKE_COMMAND}"
        "-H${VIRGIL_DEPENDS_HOME_DIR}"
        "-B${VIRGIL_DEPENDS_BUILD_DIR}"
        "${VIRGIL_DEPENDS_CMAKE_ARGS}"
    )

    # Configure target package
    execute_process (
        COMMAND ${cmd}
        WORKING_DIRECTORY "${VIRGIL_DEPENDS_HOME_DIR}"
        RESULT_VARIABLE _generate_result
        "OUTPUT_QUIET"
    )

    if (_generate_result EQUAL 0)
        virgil_depends_log_info (
              "Configure step successful (dir: ${VIRGIL_DEPENDS_HOME_DIR})"
        )
    else ()
        virgil_depends_log_error (
              "Configure step failed (dir: ${VIRGIL_DEPENDS_HOME_DIR})"
        )
    endif ()

    # Build target package
    set (cmd
        "${CMAKE_COMMAND}"
        --build
        "${VIRGIL_DEPENDS_BUILD_DIR}"
    )

    execute_process(
        COMMAND ${cmd}
        WORKING_DIRECTORY "${VIRGIL_DEPENDS_HOME_DIR}"
        RESULT_VARIABLE _build_result
        ${logging_params}
    )

    if (_build_result EQUAL 0)
        virgil_depends_log_info (
              "Build step successful (dir: ${VIRGIL_DEPENDS_BUILD_DIR})"
        )
    else ()
        virgil_depends_log_error(
              "Build step failed (dir: ${VIRGIL_DEPENDS_BUILD_DIR}"
        )
    endif ()

    find_package (
        ${VIRGIL_DEPENDS_PACKAGE_NAME} ${VIRGIL_DEPENDS_VERSION}
        REQUIRED CONFIG HINTS "${VIRGIL_DEPENDS_PREFIX}" NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH
    )

    set (VIRGIL_DEPENDS_PREFIX ${VIRGIL_DEPENDS_PREFIX} PARENT_SCOPE)
endfunction (virgil_depends)
