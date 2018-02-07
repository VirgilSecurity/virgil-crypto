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

# This file is based off of the Platform/Darwin.cmake and Platform/UnixPaths.cmake
# files which are included with CMake 2.8.4
# It has been altered for Apple *OS development
# Initial source: https://code.google.com/p/ios-cmake/

# Options:
#
# APPLE_PLATFORM
#   This decides which SDK will be selected. Possible values:
#     * IOS         - Apple iPhone / iPad / iPod Touch SDK will be selected;
#     * IOS_SIM     - Apple iPhone / iPad / iPod Touch SDK for simulator will be selected;
#     * TVOS        - Apple TV SDK will be selected;
#     * TVOS_SIM    - Apple TV SDK for simulator will be selected;
#     * WATCHOS     - Apple Watch SDK will be selected;
#     * WATCHOS_SIM - Apple Watch SDK for simulator will be selected;
#     * MACOS       - Apple MacOS SDK will be selected.
#
# APPLE_BITCODE
#   Same as XCode option, default is YES
#
# CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT = automatic(default) or /path/to/platform/Developer folder
#   By default this location is automatcially chosen based on the PLATFORM value above.
#   If set manually, it will override the default location and force the user of a particular Developer Platform
#
# CMAKE_APPLE_SDK_ROOT = automatic(default) or /path/to/platform/Developer/SDKs/SDK folder
#   By default this location is automatcially chosen based on the CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT value.
#   In this case it will always be the most up-to-date SDK found in the CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT path.
#   If set manually, this will force the use of a specific SDK version
#
# Macros:
#
# set_xcode_property (TARGET XCODE_PROPERTY XCODE_VALUE)
#   A convenience macro for setting xcode specific properties on targets
#   example: set_xcode_property (myioslib IPHONEOS_DEPLOYMENT_TARGET "3.1")
#
# find_host_package (PROGRAM ARGS)
#   A macro used to find executable programs on the host system, not within the Apple *OS environment.
#   Thanks to the android-cmake project for providing the command


# ---------------------------------------------------------------------------
#   Re-entrance guard
# ---------------------------------------------------------------------------

include_guard()

# ---------------------------------------------------------------------------
#   Define toolchain required variables
# ---------------------------------------------------------------------------

set(CMAKE_SYSTEM_NAME Darwin)
set(CMAKE_SYSTEM_VERSION 13)
set(UNIX TRUE)
set(APPLE TRUE)

# ---------------------------------------------------------------------------
#   Define compiler
# ---------------------------------------------------------------------------

# Force the compilers to clang for Apple *OS
set(CMAKE_C_COMPILER /usr/bin/clang)
set(CMAKE_CXX_COMPILER /usr/bin/clang++)
set(CMAKE_AR ar CACHE FILEPATH "" FORCE)
set(CMAKE_RANLIB ranlib CACHE FILEPATH "" FORCE)

# Skip the platform compiler checks for cross compiling
set(CMAKE_C_COMPILER_WORKS TRUE)
set(CMAKE_CXX_COMPILER_WORKS TRUE)

# ---------------------------------------------------------------------------
#   Define specific platfrom information
# ---------------------------------------------------------------------------

set(APPLE_PLATFORM "IOS" CACHE STRING "Target apple platform")
set(APPLE_BITCODE TRUE CACHE BOOL "ON/OFF support of the Apple bitcode")
set(APPLE_EXTENSION TRUE CACHE BOOL "ON/OFF support of the Apple Extensions")

set(IOS_DEVICE_FAMILY "1,2" CACHE STRING "iPhone (1), iPad(2), iPhone/iPad(1,2)")
set(IOS_DEPLOYMENT_TARGET "8.0" CACHE STRING "iOS deployment version")

set(WATCHOS_DEPLOYMENT_TARGET "2.0" CACHE STRING "WatchOS deployment version")
set(WATCHOS_DEVICE_FAMILY "4" CACHE STRING "Apple Watch (4)")

set(TVOS_DEPLOYMENT_TARGET "9.0" CACHE STRING "TVOS deployment version")
set(TVOS_DEVICE_FAMILY "4" CACHE STRING "Apple TV (4)")

set(MACOS_DEPLOYMENT_TARGET "10.9" CACHE STRING "MACOS deployment version")

# Touch cache variables to suppress warning "Unused variable"
foreach(_apple_os IOS WATCHOS TVOS MACOS)
    if(${_apple_os}_DEPLOYMENT_TARGET)
    endif()

    if(${_apple_os}_DEVICE_FAMILY)
    endif()
endforeach()

# Check the platform selection and setup for developer root and define
if(APPLE_PLATFORM STREQUAL "IOS")
    set(APPLE_PLATFORM_LOCATION "iPhoneOS.platform")
    set(CMAKE_XCODE_EFFECTIVE_PLATFORMS "-iphoneos")
    set(APPLE_ARCH armv7 armv7s arm64)
    set(APPLE_VERSION_FLAG "-miphoneos-version-min=${IOS_DEPLOYMENT_TARGET}")
    set(APPLE_DEVICE_FAMILY "${IOS_DEVICE_FAMILY}")
    set(APPLE_DEPLOYMENT_TARGET "${IOS_DEPLOYMENT_TARGET}")

elseif(APPLE_PLATFORM STREQUAL "IOS_SIM")
    set(APPLE_PLATFORM_LOCATION "iPhoneSimulator.platform")
    set(CMAKE_XCODE_EFFECTIVE_PLATFORMS "-iphonesimulator")
    set(APPLE_ARCH i386 x86_64)
    set(APPLE_VERSION_FLAG "-mios-simulator-version-min=${IOS_DEPLOYMENT_TARGET}")
    set(APPLE_DEVICE_FAMILY "${IOS_DEVICE_FAMILY}")
    set(APPLE_DEPLOYMENT_TARGET "${IOS_DEPLOYMENT_TARGET}")

elseif(APPLE_PLATFORM STREQUAL "WATCHOS")
    set(APPLE_PLATFORM_LOCATION "WatchOS.platform")
    set(CMAKE_XCODE_EFFECTIVE_PLATFORMS "-watchos")
    set(APPLE_ARCH armv7k)
    set(APPLE_VERSION_FLAG "-mwatchos-version-min=${WATCHOS_DEPLOYMENT_TARGET}")
    set(APPLE_DEVICE_FAMILY "${WATCHOS_DEVICE_FAMILY}")
    set(APPLE_DEPLOYMENT_TARGET "${WATCHOS_DEPLOYMENT_TARGET}")

elseif(APPLE_PLATFORM STREQUAL "WATCHOS_SIM")
    set(APPLE_PLATFORM_LOCATION "WatchSimulator.platform")
    set(CMAKE_XCODE_EFFECTIVE_PLATFORMS "-watchsimulator")
    set(APPLE_ARCH i386)
    set(APPLE_VERSION_FLAG "-mwatchos-simulator-version-min=${WATCHOS_DEPLOYMENT_TARGET}")
    set(APPLE_DEVICE_FAMILY "${WATCHOS_DEVICE_FAMILY}")
    set(APPLE_DEPLOYMENT_TARGET "${WATCHOS_DEPLOYMENT_TARGET}")

elseif(APPLE_PLATFORM STREQUAL "TVOS")
    set(APPLE_PLATFORM_LOCATION "AppleTVOS.platform")
    set(CMAKE_XCODE_EFFECTIVE_PLATFORMS "-appletvos")
    set(APPLE_ARCH arm64)
    set(APPLE_VERSION_FLAG "-mtvos-version-min=${TVOS_DEPLOYMENT_TARGET}")
    set(APPLE_DEVICE_FAMILY "${TVOS_DEVICE_FAMILY}")
    set(APPLE_DEPLOYMENT_TARGET "${TVOS_DEPLOYMENT_TARGET}")

elseif(APPLE_PLATFORM STREQUAL "TVOS_SIM")
    set(APPLE_PLATFORM_LOCATION "AppleTVSimulator.platform")
    set(CMAKE_XCODE_EFFECTIVE_PLATFORMS "-appletvsimulator")
    set(APPLE_ARCH x86_64)
    set(APPLE_VERSION_FLAG "-mtvos-simulator-version-min=${TVOS_DEPLOYMENT_TARGET}")
    set(APPLE_DEVICE_FAMILY "${TVOS_DEVICE_FAMILY}")
    set(APPLE_DEPLOYMENT_TARGET "${TVOS_DEPLOYMENT_TARGET}")

elseif(APPLE_PLATFORM STREQUAL "MACOS")
    set(APPLE_PLATFORM_LOCATION "MacOSX.platform")
    set(CMAKE_XCODE_EFFECTIVE_PLATFORMS "-macos")
    set(APPLE_ARCH i386 x86_64)
    set(APPLE_VERSION_FLAG "-mmacos-version-min=${MACOS_DEPLOYMENT_TARGET}")
    set(APPLE_DEVICE_FAMILY)
    set(APPLE_DEPLOYMENT_TARGET "${MACOS_DEPLOYMENT_TARGET}")

else()
    message (FATAL_ERROR
        "Unsupported APPLE_PLATFORM value selected. "
        "Please choose one of: IOS, IOS_SIM, TVOS TvOS_SIM, WATCHOS, WATCHOS_SIM, MACOS")
endif()

set(CMAKE_OSX_ARCHITECTURES ${APPLE_ARCH} CACHE STRING  "Build architecture for Apple *OS")

# Define RPATH policy
set(CMAKE_MACOSX_RPATH TRUE)
set(CMAKE_INSTALL_NAME_DIR "@rpath")
set(CMAKE_BUILD_WITH_INSTALL_NAME_DIR TRUE)

# Define XCode ENABLE_BITCODE option
if(APPLE_BITCODE)
    if(APPLE_PLATFORM MATCHES "_SIM")
        set(APPLE_BITCODE_FLAG "-fembed-bitcode-marker")
    else()
        set(APPLE_BITCODE_FLAG "-fembed-bitcode")
    endif()
endif()

# Define XCode ENABLE_BITCODE option
if(APPLE_EXTENSION)
    set(APPLE_EXTENSION_FLAG "-fapplication-extension")
endif()

# ---------------------------------------------------------------------------
#   Define: CMAKE_OSX_SYSROOT
# ---------------------------------------------------------------------------

# Setup Apple *OS developer location unless specified manually with CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT
set(CMAKE_APPLE_DEVELOPER_ROOT "/Applications/Xcode.app/Contents/Developer")

if(NOT DEFINED CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT)
    set(CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT "${CMAKE_APPLE_DEVELOPER_ROOT}/Platforms/${APPLE_PLATFORM_LOCATION}/Developer")
endif(NOT DEFINED CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT)

set(CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT ${CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT} CACHE PATH "Location of Apple Platform")

# Find and use the most recent Apple SDK unless specified manually with CMAKE_APPLE_SDK_ROOT
if(NOT DEFINED CMAKE_APPLE_SDK_ROOT)
    file(GLOB _CMAKE_APPLE_SDKS "${CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT}/SDKs/*")

    if(_CMAKE_APPLE_SDKS)
        list(SORT _CMAKE_APPLE_SDKS)
        list(REVERSE _CMAKE_APPLE_SDKS)
        list(GET _CMAKE_APPLE_SDKS 0 CMAKE_APPLE_SDK_ROOT)

    else(_CMAKE_APPLE_SDKS)
        message(FATAL_ERROR "No Apple *OS SDK's found in default search path ${CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT}."
                " Manually set CMAKE_APPLE_SDK_ROOT or install the Apple *OS SDK.")
    endif(_CMAKE_APPLE_SDKS)

    message (STATUS "Apple SDK: ${CMAKE_APPLE_SDK_ROOT}")
endif(NOT DEFINED CMAKE_APPLE_SDK_ROOT)

set(CMAKE_APPLE_SDK_ROOT ${CMAKE_APPLE_SDK_ROOT} CACHE PATH "Location of the selected Apple *OS SDK")

# Set the sysroot default to the most recent SDK
set(CMAKE_OSX_SYSROOT ${CMAKE_APPLE_SDK_ROOT} CACHE PATH "Sysroot used for Apple *OS support")


# Set the find root to the Apple *OS developer roots and to user defined paths
set(CMAKE_FIND_ROOT_PATH
    ${CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT}
    ${CMAKE_APPLE_DEVELOPER_ROOT}
    ${CMAKE_APPLE_DEVELOPER_ROOT}/usr/bin
    ${CMAKE_APPLE_SDK_ROOT}
    ${CMAKE_PREFIX_PATH}
    CACHE STRING "Apple *OS find search path root"
)

# default to searching for frameworks first
set(CMAKE_FIND_FRAMEWORK FIRST)

# set up the default search directories for frameworks
set(CMAKE_SYSTEM_FRAMEWORK_PATH
    ${CMAKE_APPLE_SDK_ROOT}/System/Library/Frameworks
    ${CMAKE_APPLE_SDK_ROOT}/System/Library/PrivateFrameworks
    ${CMAKE_APPLE_SDK_ROOT}/Developer/Library/Frameworks
)

# Only search the Apple *OS sdks, not the remainder of the host filesystem
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# ---------------------------------------------------------------------------
#   Define compiler falgs
# ---------------------------------------------------------------------------

# Pass minimum version flag and bitcode flag.
set(CMAKE_C_FLAGS "${APPLE_VERSION_FLAG} ${APPLE_BITCODE_FLAG} ${APPLE_EXTENSION_FLAG}" CACHE STRING "")
set(CMAKE_CXX_FLAGS "${APPLE_VERSION_FLAG} ${APPLE_BITCODE_FLAG} ${APPLE_EXTENSION_FLAG}" CACHE STRING "")

# ---------------------------------------------------------------------------
#   Helper functions
# ---------------------------------------------------------------------------

# This little macro lets you set any XCode specific property
macro(set_xcode_property TARGET XCODE_PROPERTY XCODE_VALUE)
    set_property(TARGET ${TARGET} PROPERTY XCODE_ATTRIBUTE_${XCODE_PROPERTY} ${XCODE_VALUE})
endmacro(set_xcode_property)

# This macro lets you find executable programs on the host system
macro(find_host_package)
    set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY NEVER)
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE NEVER)
    set(APPLE FALSE)

    find_package(${ARGN})

    set(APPLE TRUE)
    set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
endmacro(find_host_package)

# This function uses this toolchain variables to configure
# given target as an Apple Framework
#
# target_apple_framework(<target>
#                        [NAME name]
#                        [VERSION version]
#                        [IDENTIFIER identifier]
#                        [DEVELOPMENT_TEAM team]
#                        [CODE_SIGN_IDENTITY identity]
#                        [CODE_SIGN])
#
# Required target properties:
#   - VERSION
#   - SOVERSION
#   - PUBLIC_HEADER
function(target_apple_framework target)
    #
    # Parse arguments
    #
    set(_option_value CODE_SIGN)
    set(_one_value NAME VERSION IDENTIFIER DEVELOPMENT_TEAM CODE_SIGN_IDENTITY)
    cmake_parse_arguments(FRAMEWORK "${_option_value}" "${_one_value}" "" ${ARGN})

    if(FRAMEWORK_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "Unexpected argument: ${FRAMEWORK_UNPARSED_ARGUMENTS}")
    endif()

    if(NOT FRAMEWORK_NAME)
        message(FATAL_ERROR "Required argument is not given: FRAMEWORK_NAME")
    endif()

    if(NOT FRAMEWORK_IDENTIFIER)
        message(FATAL_ERROR "Required argument is not given: FRAMEWORK_IDENTIFIER")
    endif()

    if(NOT FRAMEWORK_VERSION)
        set(FRAMEWORK_VERSION "A")
    endif()

    #
    # Configure Info.plist
    #
    get_target_property(BUNDLE_VERSION ${target} VERSION)
    get_target_property(BUNDLE_SOVERSION ${target} SOVERSION)

    configure_file(
        "${CMAKE_CURRENT_LIST_DIR}/Info.plist.in"
        "${CMAKE_CURRENT_BINARY_DIR}/Info.plist"
    )

    set_target_properties(${target} PROPERTIES
        MACOSX_FRAMEWORK_INFO_PLIST "${CMAKE_CURRENT_BINARY_DIR}/Info.plist"
    )

    #
    # Set common framework attributes
    #
    set_target_properties(${target} PROPERTIES
        FRAMEWORK TRUE
        FRAMEWORK_VERSION ${FRAMEWORK_VERSION}
        OUTPUT_NAME "${FRAMEWORK_NAME}"
        MACOSX_FRAMEWORK_IDENTIFIER ${FRAMEWORK_IDENTIFIER}
        MACOSX_FRAMEWORK_INFO_PLIST "${CMAKE_CURRENT_BINARY_DIR}/Info.plist"
    )

    #
    # Set Xcode attributes:
    #   - XCODE_ATTRIBUTE_{APPLE_PLATFORM}_DEPLOYMENT_TARGET
    #   - XCODE_ATTRIBUTE_TARGETED_DEVICE_FAMILY
    #
    if(APPLE_PLATFORM STREQUAL "IOS" OR APPLE_PLATFORM STREQUAL "IOS_SIM")
        set_xcode_property(${target} IPHONEOS_DEPLOYMENT_TARGET "${IOS_DEPLOYMENT_TARGET}")


    elseif(APPLE_PLATFORM STREQUAL "WATCHOS" OR APPLE_PLATFORM STREQUAL "WATCHOS_SIM")
        set_xcode_property(${target} WATCHOS_DEPLOYMENT_TARGET "${WATCHOS_DEPLOYMENT_TARGET}")

    elseif(APPLE_PLATFORM STREQUAL "TVOS" OR APPLE_PLATFORM STREQUAL "TVOS_SIM")
        set_xcode_property(${target} TVOS_DEPLOYMENT_TARGET "${TVOS_DEPLOYMENT_TARGET}")

    elseif(APPLE_PLATFORM STREQUAL "MACOS")
        set_xcode_property(${target} MACOSX_DEPLOYMENT_TARGET "${MACOS_DEPLOYMENT_TARGET}")

    endif()

    set_xcode_property(${target} TARGETED_DEVICE_FAMILY "${APPLE_DEVICE_FAMILY}")

    if (FRAMEWORK_CODE_SIGN)
        set_xcode_property(${target} DEVELOPMENT_TEAM "${FRAMEWORK_DEVELOPMENT_TEAM}")
        set_xcode_property(${target} CODE_SIGN_IDENTITY "${FRAMEWORK_CODE_SIGN_IDENTITY}")
    endif()

    #
    # Sign framework
    #
    if(FRAMEWORK_CODE_SIGN AND NOT CMAKE_GENERATOR STREQUAL "Xcode")
        if(NOT FRAMEWORK_CODE_SIGN_IDENTITY)
            # Ad-Hoc codesign
            set(NO_CODE_SIGN_IDENTITY "-")
        endif()

        add_custom_target(sign-${target} ALL
            COMMAND /usr/bin/codesign
                    --force $<TARGET_FILE_DIR:${target}>
                    --sign "${FRAMEWORK_CODE_SIGN_IDENTITY}" "${NO_CODE_SIGN_IDENTITY}"
            DEPENDS ${target}
            COMMENT "Sign the framework with identity: ${FRAMEWORK_CODE_SIGN_IDENTITY} ${NO_CODE_SIGN_IDENTITY}"
        )
    endif()
endfunction(target_apple_framework)
