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

#.rst:
# FindPHP
# --------
#
# Find PHP.
#
# Specify one or more of the following components as you call this find module.
#
# ::
#
#   Runtime  = PHP executable
#   Test     = PHPUnit
#   Devel    = Headers and libraries required to build PHP extension
#
# This module sets the following result variables:
#
# ::
#
#   PHP_EXECUTABLE        - the full path to the 'php' executable
#   PHPUNIT_EXECUTABLE    - the full path to the 'phpunit' executable
#   PHP_CONFIG_EXECUTABLE - the full path to the 'php-config' executable (Unix only)
#   PHP_INCLUDE_DIR       - the full path to the root PHP header directory
#   PHP_INCLUDE_DIRS      - the full paths to the PHP header directories
#   PHP_LIBRARIES         - the full paths to the PHP libraries
#   PHP_EXTENSIONS_DIR    - the full path to the directory containing PHP extensions
#   PHP_DEFINES           - list of defines that should be applied for successful extension build
#   PHP_VERSION_STRING    - Version of PHP found, e.g. 7.2.6
#   PHP_VERSION_MAJOR     - The major version of the package found.
#   PHP_VERSION_MINOR     - The minor version of the package found.
#   PHP_VERSION_PATCH     - The patch version of the package found.
#   PHP_VERSION           - This is set to: $major[.$minor[.$patch]]
#   PHP_FOUND             - TRUE if all components are found.
#   PHP_<component>_FOUND - TRUE if <component> is found.
#
#
# Note, for Unix-like systems 'php-config' utility is used to find 'Devel' components.
# Note, for Windows 'PHP_HOME', 'PHP_DEVEL_HOME' and 'PHPUNIT_HOME' environment variable are used find requested components.

# ---------------------------------------------------------------------------
#   Find PHP within Windows OS
# ---------------------------------------------------------------------------
if(WIN32)
    #
    # Define variables with it's ENV equivalent if needed.
    #
    if(NOT DEFINED PHP_HOME AND DEFINED ENV{PHP_HOME})
        set(PHP_HOME "$ENV{PHP_HOME}")
    endif()

    if(NOT DEFINED PHP_DEVEL_HOME AND DEFINED ENV{PHP_DEVEL_HOME})
        set(PHP_DEVEL_HOME "$ENV{PHP_DEVEL_HOME}")
    endif()

    if(NOT DEFINED PHPUNIT_HOME AND DEFINED ENV{PHPUNIT_HOME})
        set(PHPUNIT_HOME "$ENV{PHPUNIT_HOME}")
    endif()

    #
    # Find executables
    #
    find_program(PHP_EXECUTABLE NAMES php.exe PATHS "${PHP_HOME}")
    find_program(PHPUNIT_EXECUTABLE NAMES phpunit phpunit.phar PATHS "${PHPUNIT_HOME}")

    #
    # Set 'PHP_HOME' and 'PHPUNIT_HOME' if executables are found and variable are not defined.
    #
    if(NOT PHP_HOME AND PHP_EXECUTABLE)
        get_filename_component(PHP_HOME "${PHP_EXECUTABLE}" DIRECTORY)
    endif()

    if(NOT PHPUNIT_HOME AND PHPUNIT_EXECUTABLE)
        get_filename_component(PHPUNIT_HOME "${PHPUNIT_EXECUTABLE}" DIRECTORY)
    endif()

    #
    # Find headers and libraries
    #
    if(PHP_DEVEL_HOME)
        get_filename_component(PHP_INCLUDE_DIR "${PHP_DEVEL_HOME}/include" ABSOLUTE)

        set(_INCLUDE_DIRS
                "${PHP_DEVEL_HOME}/include"
                "${PHP_DEVEL_HOME}/include/ext"
                "${PHP_DEVEL_HOME}/include/ext/date/lib"
                "${PHP_DEVEL_HOME}/include/main"
                "${PHP_DEVEL_HOME}/include/TSRM"
                "${PHP_DEVEL_HOME}/include/win32"
                "${PHP_DEVEL_HOME}/include/Zend"
                )

        #
        # Normalize paths
        #
        set(PHP_INCLUDE_DIRS)

        foreach(dir ${_INCLUDE_DIRS})
            get_filename_component(path "${dir}" ABSOLUTE)
            list(APPEND PHP_INCLUDE_DIRS "${path}")
        endforeach(dir)

        unset(_INCLUDE_DIRS)

        find_library(PHP_LIBRARIES NAMES php5 php5ts php7 php7ts php phpts PATHS "${PHP_DEVEL_HOME}/lib")
    endif()

    #
    # Define PHP defines
    #
    if(PHP_LIBRARIES)
        set(PHP_DEFINES)

        list(APPEND PHP_DEFINES "PHP_WIN32=1" "ZEND_WIN32=1" "ZEND_WIN32_FORCE_INLINE")

        if("${PHP_LIBRARIES}" MATCHES "ts")
            list(APPEND PHP_DEFINES "ZTS=1")
        endif()
    endif()

# ---------------------------------------------------------------------------
#   Find PHP within Unix-like OS
# ---------------------------------------------------------------------------
else()
    find_program(PHP_CONFIG_EXECUTABLE NAMES php5-config php-config)
    find_program(PHPUNIT_EXECUTABLE NAMES phpunit phpunit.phar)


    if(PHP_CONFIG_EXECUTABLE)
        #
        # Define PHP_EXECUTABLE
        #
        execute_process(
                COMMAND ${PHP_CONFIG_EXECUTABLE} --php-binary
                OUTPUT_VARIABLE PHP_EXECUTABLE
                OUTPUT_STRIP_TRAILING_WHITESPACE
                )

        #
        # Define PHP_EXTENSIONS_DIR
        #
        execute_process(
                COMMAND ${PHP_CONFIG_EXECUTABLE} --extension-dir
                OUTPUT_VARIABLE PHP_EXTENSIONS_DIR
                OUTPUT_STRIP_TRAILING_WHITESPACE
                )

        #
        # Define PHP_INCLUDE_DIR
        #
        execute_process(
                COMMAND ${PHP_CONFIG_EXECUTABLE} --include-dir
                OUTPUT_VARIABLE PHP_INCLUDE_DIR
                OUTPUT_STRIP_TRAILING_WHITESPACE
                )

        #
        # Define PHP_INCLUDE_DIRS
        #
        execute_process(
                COMMAND ${PHP_CONFIG_EXECUTABLE} --includes
                OUTPUT_VARIABLE PHP_INCLUDE_DIRS
                OUTPUT_STRIP_TRAILING_WHITESPACE
                )
        string(REPLACE "-I" "" PHP_INCLUDE_DIRS "${PHP_INCLUDE_DIRS}")
        string(REPLACE " " ";" PHP_INCLUDE_DIRS "${PHP_INCLUDE_DIRS}")
      endif()

      #
      # Define PHP_LIBRARIES as empty.
      # It is redundant on Unix-like OS because of dynamic linkage.
      #
      set(PHP_LIBRARIES "")

      #
      # Define PHP_DEFINES as empty.
      # Nothig to define for Unix-like OS.
      #
      set(PHP_DEFINES "")
endif()


# ---------------------------------------------------------------------------
#   Get information from 'php -i' output
# ---------------------------------------------------------------------------
if(PHP_EXECUTABLE)
    execute_process(
            COMMAND "${PHP_EXECUTABLE}" "-i"
            RESULT_VARIABLE info_res
            OUTPUT_VARIABLE info_var
            ERROR_VARIABLE info_err
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_STRIP_TRAILING_WHITESPACE
            )

    if(info_res EQUAL 0)
        set(PHP_INFO "${info_var}")
    endif()
endif()

if(PHP_INFO)
    #
    # Get directory with extensions
    #
    string(REGEX MATCH "extension_dir[ ]*=>[ ]*([^=]+)" ext_dir_line "${PHP_INFO}")
    string(REGEX REPLACE "extension_dir[ ]*=>[ ]*([^=]+)" "\\1" ext_dir "${ext_dir_line}")

    if(IS_ABSOLUTE "${ext_dir}")
        set(PHP_EXTENSIONS_DIR "${ext_dir}")

    else()
        set(PHP_EXTENSIONS_DIR "${PHP_HOME}/${ext_dir}")
    endif()
    get_filename_component(PHP_EXTENSIONS_DIR "${PHP_EXTENSIONS_DIR}" ABSOLUTE)

    #
    # Detect PHP version
    #
    string(REGEX MATCH "PHP Version => [0-9]+\\.[0-9]+\\.[0-9]+" version_line "${PHP_INFO}")
    string(REGEX REPLACE "PHP Version => ([0-9]+\\.[0-9]+\\.[0-9]+)" "\\1" PHP_VERSION_STRING "${version_line}")

    string(REGEX REPLACE "([0-9]+)\\.([0-9]+)\\.([0-9]+)" "\\1" PHP_VERSION_MAJOR "${PHP_VERSION_STRING}")
    string(REGEX REPLACE "([0-9]+)\\.([0-9]+)\\.([0-9]+)" "\\2" PHP_VERSION_MINOR "${PHP_VERSION_STRING}")
    string(REGEX REPLACE "([0-9]+)\\.([0-9]+)\\.([0-9]+)" "\\3" PHP_VERSION_PATCH "${PHP_VERSION_STRING}")

    set(PHP_VERSION "${PHP_VERSION_MAJOR}.${PHP_VERSION_MINOR}.${PHP_VERSION_PATCH}")
endif()


# ---------------------------------------------------------------------------
#   Handle package arguments
# ---------------------------------------------------------------------------
include(FindPackageHandleStandardArgs)

if(PHP_FIND_COMPONENTS)

    foreach(component ${PHP_FIND_COMPONENTS})

        if(component STREQUAL "Runtime")
            set(_PHP_RUNTIME_REQUIRED_VARS PHP_EXECUTABLE)

            if(PHP_EXECUTABLE)
                set(PHP_Runtime_FOUND TRUE)
            endif()

        elseif(component STREQUAL "Devel")
            set(_PHP_DEVEL_REQUIRED_VARS)

            if (WIN32)
                list(APPEND _PHP_DEVEL_REQUIRED_VARS PHP_LIBRARIES PHP_DEFINES)
            endif()

            list(APPEND _PHP_DEVEL_REQUIRED_VARS
                    PHP_INCLUDE_DIR
                    PHP_INCLUDE_DIRS
                    PHP_EXTENSIONS_DIR
                    )

            if(WIN32)
                if(PHP_INCLUDE_DIR AND PHP_INCLUDE_DIRS AND PHP_LIBRARIES AND PHP_DEFINES)
                    set(PHP_Devel_FOUND TRUE)
                endif()
            else()
                if(PHP_INCLUDE_DIR AND PHP_INCLUDE_DIRS)
                    set(PHP_Devel_FOUND TRUE)
                endif()
            endif()

        elseif(component STREQUAL "Test")
            set(_PHP_TEST_REQUIRED_VARS PHPUNIT_EXECUTABLE)

            if(PHPUNIT_EXECUTABLE)
                set(PHP_Test_FOUND TRUE)
            endif()
        endif()
    endforeach()

    find_package_handle_standard_args(PHP
            REQUIRED_VARS
                ${_PHP_DEVEL_REQUIRED_VARS}
                ${_PHP_RUNTIME_REQUIRED_VARS}
                ${_PHP_TEST_REQUIRED_VARS}

            HANDLE_COMPONENTS

            VERSION_VAR
                PHP_VERSION
            )

    unset(_PHP_RUNTIME_REQUIRED_VARS)
    unset(_PHP_DEVEL_REQUIRED_VARS)
    unset(_PHP_TEST_REQUIRED_VARS)
else()

    if(WIN32)
        find_package_handle_standard_args(PHP
                REQUIRED_VARS
                    PHP_LIBRARIES
                    PHP_INCLUDE_DIR
                    PHP_INCLUDE_DIRS
                    PHP_DEFINES

                VERSION_VAR
                    PHP_VERSION
                )
    else()
        find_package_handle_standard_args(PHP
                REQUIRED_VARS
                    PHP_INCLUDE_DIR
                    PHP_INCLUDE_DIRS

                VERSION_VAR
                    PHP_VERSION
                )
    endif()
endif()

# ---------------------------------------------------------------------------
#   Configuration of the cache
# ---------------------------------------------------------------------------
set(PHP_INCLUDE_DIRS "${PHP_INCLUDE_DIRS}" CACHE STRING "The list of paths to PHP headers.")
set(PHP_LIBRARIES "${PHP_LIBRARIES}" CACHE STRING "The list of paths to PHP libraries.")

mark_as_advanced(
        PHP_EXECUTABLE
        PHP_CONFIG_EXECUTABLE
        PHPUNIT_EXECUTABLE
        PHP_INCLUDE_DIR
        PHP_INCLUDE_DIRS
        PHP_LIBRARIES
        )
