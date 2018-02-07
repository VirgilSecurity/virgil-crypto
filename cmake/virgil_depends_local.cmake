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
#         file (APPEND "@VIRGIL_DEPENDS_ARGS_FILE@"
#             "set (XXXXXXX OFF CACHE INTERNAL \"\")\n"
#             "set (YYYYYYY ON CACHE INTERNAL \"\")\n"
#         )
#
#         ExternalProject_Add (${PROJECT_NAME}
#             DOWNLOAD_DIR "@VIRGIL_DEPENDS_PACKAGE_DOWNLOAD_DIR@"
#             URL "https://github.com/....."
#             URL_HASH SHA256=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
#             PREFIX "@VIRGIL_DEPENDS_PACKAGE_BUILD_DIR@"
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
#              CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dir_to_config_file_from_step_1"
#              CMAKE_ARGS "${OPTIONAL_VARIABLE_WITH_ADITIONAL_CMAKE_PARAMETERS}"
#          )
#
#          virgil_find_package (zzzzz x.y)
#

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

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
        foreach (lang ASM C CXX)
            virgil_depends_write_cache_var ("${cache_path}" "CMAKE_${lang}_COMPILER")
            virgil_depends_write_cache_var ("${cache_path}" "CMAKE_${lang}_FLAGS")
            virgil_depends_write_cache_var ("${cache_path}" "CMAKE_${lang}_FLAGS_${configuration}")
        endforeach ()
    endif ()
    # Pass OS X architectures
    virgil_depends_write_cache_var ("${cache_path}" "CMAKE_OSX_ARCHITECTURES")
    # Pass DEBUG
    virgil_depends_write_cache_var ("${cache_path}" "CMAKE_VERBOSE_MAKEFILE")
    # Pass SHARED
    virgil_depends_write_cache_var ("${cache_path}" "BUILD_SHARED_LIBS")
    # Pass RPATH settings
    virgil_depends_write_cache_var ("${cache_path}" "CMAKE_MACOSX_RPATH")
    virgil_depends_write_cache_var ("${cache_path}" "CMAKE_INSTALL_NAME_DIR")
    virgil_depends_write_cache_var ("${cache_path}" "CMAKE_INSTALL_RPATH")
    virgil_depends_write_cache_var ("${cache_path}" "CMAKE_BUILD_RPATH")
    virgil_depends_write_cache_var ("${cache_path}" "CMAKE_SKIP_BUILD_RPATH")
    virgil_depends_write_cache_var ("${cache_path}" "CMAKE_BUILD_WITH_INSTALL_RPATH")
    virgil_depends_write_cache_var ("${cache_path}" "CMAKE_INSTALL_RPATH_USE_LINK_PATH")
    # Pass find package paths
    virgil_depends_write_cache_var ("${cache_path}" "CMAKE_PREFIX_PATH")
    # Pass VIRGIL_DEPENDS_*
    virgil_depends_write_cache_var ("${cache_path}" "VIRGIL_DEPENDS_PREFIX")
    virgil_depends_write_cache_var ("${cache_path}" "VIRGIL_DEPENDS_HOME_DIR")
    virgil_depends_write_cache_var ("${cache_path}" "VIRGIL_DEPENDS_CACHE_DIR")
    virgil_depends_write_cache_var ("${cache_path}" "VIRGIL_DEPENDS_CMAKE_FILE")
endfunction ()

# Exported variables:
#     VIRGIL_DEPENDS_PREFIX
function (virgil_depends)
    # Parse arguments
    set (_one_value PACKAGE_NAME CONFIG_DIR)
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
    if (NOT VIRGIL_DEPENDS_CMAKE_ARGS)
        # Pass upstream CMAKE_ARGS to downstream
        if (CMAKE_ARGS)
            set (VIRGIL_DEPENDS_CMAKE_ARGS "${CMAKE_ARGS}")
        else ()
            set (VIRGIL_DEPENDS_CMAKE_ARGS "")
        endif (CMAKE_ARGS)
    endif ()

    # Do nothing if given package exists
    if (${VIRGIL_DEPENDS_PACKAGE_NAME}_DIR)
        return ()
    endif ()

    # Configure global variables, that will be available for downstream projects
    set (VIRGIL_DEPENDS_CACHE_DIR "${CMAKE_SOURCE_DIR}/.depends_cache"
            CACHE PATH "Temporary folder that holds all downloaded dependencies")

    set (VIRGIL_DEPENDS_HOME_DIR "${CMAKE_BINARY_DIR}/depends"
            CACHE PATH "Temporary folder that holds all build and installed dependencies")

    set (VIRGIL_DEPENDS_PREFIX "${VIRGIL_DEPENDS_HOME_DIR}/installed"
            CACHE PATH "Path to the installed depenencies")

    set (VIRGIL_DEPENDS_PACKAGE_DOWNLOAD_DIR "${VIRGIL_DEPENDS_CACHE_DIR}/${VIRGIL_DEPENDS_PACKAGE_NAME}")
    set (VIRGIL_DEPENDS_PACKAGE_SOURCE_DIR "${VIRGIL_DEPENDS_HOME_DIR}/${VIRGIL_DEPENDS_PACKAGE_NAME}")
    set (VIRGIL_DEPENDS_PACKAGE_BUILD_DIR "${VIRGIL_DEPENDS_PACKAGE_SOURCE_DIR}/build")

    set (VIRGIL_DEPENDS_CACHE_FILE "${VIRGIL_DEPENDS_PACKAGE_SOURCE_DIR}/cmake_cache.cmake")
    set (VIRGIL_DEPENDS_ARGS_FILE "${VIRGIL_DEPENDS_PACKAGE_SOURCE_DIR}/cmake_args.cmake")

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
        file (COPY "${_file}" DESTINATION "${VIRGIL_DEPENDS_PACKAGE_SOURCE_DIR}")
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
        "${VIRGIL_DEPENDS_PACKAGE_SOURCE_DIR}/CMakeLists.txt"
        @ONLY
    )

    set (cmd
        "${CMAKE_COMMAND}"
        "-H${VIRGIL_DEPENDS_PACKAGE_SOURCE_DIR}"
        "-B${VIRGIL_DEPENDS_PACKAGE_BUILD_DIR}"
        "${VIRGIL_DEPENDS_CMAKE_ARGS}"
    )

    # Configure target package
    execute_process (
        COMMAND ${cmd}
        WORKING_DIRECTORY "${VIRGIL_DEPENDS_PACKAGE_SOURCE_DIR}"
        RESULT_VARIABLE _generate_result
        "OUTPUT_QUIET"
    )

    if (_generate_result EQUAL 0)
        virgil_depends_log_info (
              "Configure step successful (dir: ${VIRGIL_DEPENDS_PACKAGE_SOURCE_DIR})"
        )
    else ()
        virgil_depends_log_error (
              "Configure step failed (dir: ${VIRGIL_DEPENDS_PACKAGE_SOURCE_DIR})"
        )
    endif ()

    # Build target package
    set (cmd
        "${CMAKE_COMMAND}"
        --build
        "${VIRGIL_DEPENDS_PACKAGE_BUILD_DIR}"
    )

    execute_process (
        COMMAND ${cmd}
        WORKING_DIRECTORY "${VIRGIL_DEPENDS_PACKAGE_SOURCE_DIR}"
        RESULT_VARIABLE _build_result
    )

    if (_build_result EQUAL 0)
        virgil_depends_log_info (
              "Build step successful (dir: ${VIRGIL_DEPENDS_PACKAGE_BUILD_DIR})"
        )
    else ()
        virgil_depends_log_error(
              "Build step failed (dir: ${VIRGIL_DEPENDS_PACKAGE_BUILD_DIR}"
        )
    endif ()

    # Install target package
    set (cmd
        "${CMAKE_COMMAND}"
        --build
        "${VIRGIL_DEPENDS_PACKAGE_BUILD_DIR}"
        --target install
    )

    execute_process (
        COMMAND ${cmd}
        WORKING_DIRECTORY "${VIRGIL_DEPENDS_PACKAGE_SOURCE_DIR}"
        RESULT_VARIABLE _install_result
    )

    if (_install_result EQUAL 0)
        virgil_depends_log_info (
              "Install step successful (dir: ${VIRGIL_DEPENDS_PACKAGE_BUILD_DIR})"
        )
    else ()
        # Just ignore, because not all packages have target 'install'
        virgil_depends_log_debug (
              "Install step failed (dir: ${VIRGIL_DEPENDS_PACKAGE_BUILD_DIR})"
        )
    endif ()
endfunction (virgil_depends)

function (virgil_find_package)
    find_package (${ARGN}
        REQUIRED CONFIG HINTS "${VIRGIL_DEPENDS_PREFIX}" NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH
    )
endfunction (virgil_find_package)
