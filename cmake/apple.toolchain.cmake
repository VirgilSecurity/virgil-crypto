# This file is based off of the Platform/Darwin.cmake and Platform/UnixPaths.cmake
# files which are included with CMake 2.8.4
# It has been altered for Apple *OS development
# Initial source: https://code.google.com/p/ios-cmake/

# Options:
#
# PLATFORM
#   This decides which SDK will be selected. Possible values:
#     * ios          - Apple iPhone / iPad / iPod Touch SDK will be selected;
#     * appletvos    - Apple TV SDK will be selected;
#     * applewatchos - Apple Watch SDK will be selected;
#
# SIMULATOR
#   This forces SDKS will be selected from the <Platform>Simulator.platform folder,
#   if omitted <Platform>OS.platform is used.
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
#  A convenience macro for setting xcode specific properties on targets
#  example: set_xcode_property (myioslib IPHONEOS_DEPLOYMENT_TARGET "3.1")
#
# find_host_package (PROGRAM ARGS)
#  A macro used to find executable programs on the host system, not within the Apple *OS environment.
#  Thanks to the android-cmake project for providing the command

# Standard settings
set (CMAKE_SYSTEM_NAME Darwin)
set (CMAKE_SYSTEM_VERSION 1)
set (UNIX True)
set (APPLE True)

set (LANG "cpp" CACHE STRING "Target language")

if (PLATFORM STREQUAL "ios")
    set (APPLE_IOS True)
elseif (PLATFORM STREQUAL "appletvos")
    set (APPLE_TV True)
elseif (PLATFORM STREQUAL "applewatchos")
    set (APPLE_WATCH True)
endif ()

# Required as of cmake 2.8.10
set (CMAKE_OSX_DEPLOYMENT_TARGET "" CACHE STRING "Force unset of the deployment target for Apple *OS" FORCE)

# Determine the cmake host system version so we know where to find the Apple *OS SDKs
find_program (CMAKE_UNAME uname /bin /usr/bin /usr/local/bin)
if (CMAKE_UNAME)
    exec_program(uname ARGS -r OUTPUT_VARIABLE CMAKE_HOST_SYSTEM_VERSION)
    string (REGEX REPLACE "^([0-9]+)\\.([0-9]+).*$" "\\1" DARWIN_MAJOR_VERSION "${CMAKE_HOST_SYSTEM_VERSION}")
endif (CMAKE_UNAME)

# All Apple *OS/Darwin specific settings - some may be redundant
set (CMAKE_SHARED_LIBRARY_PREFIX "lib")
set (CMAKE_SHARED_LIBRARY_SUFFIX ".dylib")
set (CMAKE_SHARED_MODULE_PREFIX "lib")
set (CMAKE_SHARED_MODULE_SUFFIX ".so")
set (CMAKE_MODULE_EXISTS 1)
set (CMAKE_DL_LIBS "")

set (CMAKE_C_OSX_COMPATIBILITY_VERSION_FLAG "-compatibility_version ")
set (CMAKE_C_OSX_CURRENT_VERSION_FLAG "-current_version ")
set (CMAKE_CXX_OSX_COMPATIBILITY_VERSION_FLAG "${CMAKE_C_OSX_COMPATIBILITY_VERSION_FLAG}")
set (CMAKE_CXX_OSX_CURRENT_VERSION_FLAG "${CMAKE_C_OSX_CURRENT_VERSION_FLAG}")

# hack: if a new cmake (which uses CMAKE_INSTALL_NAME_TOOL) runs on an old build tree
# (where install_name_tool was hardcoded) and where CMAKE_INSTALL_NAME_TOOL isn't in the cache
# and still cmake didn't fail in CMakeFindBinUtils.cmake (because it isn't rerun)
# hardcode CMAKE_INSTALL_NAME_TOOL here to install_name_tool, so it behaves as it did before, Alex
if (NOT DEFINED CMAKE_INSTALL_NAME_TOOL)
    find_program(CMAKE_INSTALL_NAME_TOOL install_name_tool)
endif (NOT DEFINED CMAKE_INSTALL_NAME_TOOL)

# Check the platform selection and setup for developer root
if (APPLE_IOS)
    if (SIMULATOR)
        set (APPLE_PLATFORM_LOCATION "iPhoneSimulator.platform")
        # This causes the installers to properly locate the output libraries
        set (CMAKE_XCODE_EFFECTIVE_PLATFORMS "-iphonesimulator")
    else ()
        set (APPLE_PLATFORM_LOCATION "iPhoneOS.platform")
        # This causes the installers to properly locate the output libraries
        set (CMAKE_XCODE_EFFECTIVE_PLATFORMS "-iphoneos")
    endif ()
elseif (APPLE_WATCH)
    if (SIMULATOR)
        set (APPLE_PLATFORM_LOCATION "WatchSimulator.platform")
        # This causes the installers to properly locate the output libraries
        set (CMAKE_XCODE_EFFECTIVE_PLATFORMS "-watchsimulator")
    else ()
        set (APPLE_PLATFORM_LOCATION "WatchOS.platform")
        # This causes the installers to properly locate the output libraries
        set (CMAKE_XCODE_EFFECTIVE_PLATFORMS "-watchos")
    endif ()
elseif (APPLE_TV)
    if (SIMULATOR)
        set (APPLE_PLATFORM_LOCATION "AppleTVSimulator.platform")
        # This causes the installers to properly locate the output libraries
        set (CMAKE_XCODE_EFFECTIVE_PLATFORMS "-appletvsimulator")
    else ()
        set (APPLE_PLATFORM_LOCATION "AppleTVOS.platform")
        # This causes the installers to properly locate the output libraries
        set (CMAKE_XCODE_EFFECTIVE_PLATFORMS "-appletvos")
    endif ()
else ()
    message (FATAL_ERROR "Unsupported PLATFORM value selected. Please choose one: ios, tv, watch")
endif ()

# Setup Apple *OS developer location unless specified manually with CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT
# Xcode 4.3 changed the installation location, so choose the most recent one available
set (CMAKE_APPLE_DEVELOPER_ROOT "/Applications/Xcode.app/Contents/Developer")
if (NOT DEFINED CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT)
    set (CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT "${CMAKE_APPLE_DEVELOPER_ROOT}/Platforms/${APPLE_PLATFORM_LOCATION}/Developer")
endif (NOT DEFINED CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT)
set (CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT ${CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT} CACHE PATH "Location of Apple Platform")

# Find and use the most recent Apple SDK unless specified manually with CMAKE_APPLE_SDK_ROOT
if (NOT DEFINED CMAKE_APPLE_SDK_ROOT)
    file (GLOB _CMAKE_APPLE_SDKS "${CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT}/SDKs/*")
    if (_CMAKE_APPLE_SDKS)
        list (SORT _CMAKE_APPLE_SDKS)
        list (REVERSE _CMAKE_APPLE_SDKS)
        list (GET _CMAKE_APPLE_SDKS 0 CMAKE_APPLE_SDK_ROOT)
    else (_CMAKE_APPLE_SDKS)
        message (FATAL_ERROR "No Apple *OS SDK's found in default search path ${CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT}."
                " Manually set CMAKE_APPLE_SDK_ROOT or install the Apple *OS SDK.")
    endif (_CMAKE_APPLE_SDKS)
    message (STATUS "Toolchain using default Apple *OS SDK: ${CMAKE_APPLE_SDK_ROOT}")
endif (NOT DEFINED CMAKE_APPLE_SDK_ROOT)
set (CMAKE_APPLE_SDK_ROOT ${CMAKE_APPLE_SDK_ROOT} CACHE PATH "Location of the selected Apple *OS SDK")

# Set the sysroot default to the most recent SDK
set (CMAKE_OSX_SYSROOT ${CMAKE_APPLE_SDK_ROOT} CACHE PATH "Sysroot used for Apple *OS support")

# set the architecture for Apple *OS
if (SIMULATOR)
    set (APPLE_ARCH i386 x86_64)
else ()
    if (APPLE_IOS)
        set (APPLE_ARCH armv7 armv7s arm64)
    elseif (APPLE_WATCH)
        set (APPLE_ARCH armv7k)
    elseif (APPLE_TV)
        set (APPLE_ARCH arm64)
    endif ()
endif ()
set (CMAKE_OSX_ARCHITECTURES ${APPLE_ARCH} CACHE STRING  "Build architecture for Apple *OS")

# Set IOS Min Version
set (APPLE_IOS_VERSION_MIN "7.0" CACHE STRING "Minimum supported Apple iOS version.")
set (APPLE_WATCH_VERSION_MIN "2.0" CACHE STRING "Minimum supported Apple Watch version.")
set (APPLE_TV_VERSION_MIN "9.0" CACHE STRING "Minimum supported Apple TV version.")

if (APPLE_IOS)
    if (SIMULATOR)
        set (APPLE_VERSION_FLAG "-mios-simulator-version-min=${APPLE_IOS_VERSION_MIN}")
    else ()
        set (APPLE_VERSION_FLAG "-miphoneos-version-min=${APPLE_IOS_VERSION_MIN}")
    endif ()
    set (APPLE_PLATFORM_VERSION_MIN ${APPLE_IOS_VERSION_MIN})
elseif (APPLE_WATCH)
    if (SIMULATOR)
        set (APPLE_VERSION_FLAG "-mwatchos-simulator-version-min=${APPLE_WATCH_VERSION_MIN}")
    else ()
        set (APPLE_VERSION_FLAG "-mwatchos-version-min=${APPLE_WATCH_VERSION_MIN}")
    endif ()
    set (APPLE_PLATFORM_VERSION_MIN ${APPLE_WATCH_VERSION_MIN})
elseif (APPLE_TV)
    if (SIMULATOR)
        set (APPLE_VERSION_FLAG "-mtvos-simulator-version-min=${APPLE_TV_VERSION_MIN}")
    else ()
        set (APPLE_VERSION_FLAG "-mtvos-version-min=${APPLE_TV_VERSION_MIN}")
    endif ()
    set (APPLE_PLATFORM_VERSION_MIN ${APPLE_TV_VERSION_MIN})
endif ()
set (PLATFORM_VERSION ${APPLE_PLATFORM_VERSION_MIN} CACHE STRING "Minimum version of the target platform")

# Set the find root to the Apple *OS developer roots and to user defined paths
set (CMAKE_FIND_ROOT_PATH
    ${CMAKE_APPLE_PLATFORM_DEVELOPER_ROOT}
    ${CMAKE_APPLE_DEVELOPER_ROOT}
    ${CMAKE_APPLE_DEVELOPER_ROOT}/usr/bin
    ${CMAKE_APPLE_SDK_ROOT}
    ${CMAKE_PREFIX_PATH}
    CACHE string "Apple *OS find search path root"
)

# default to searching for frameworks first
set (CMAKE_FIND_FRAMEWORK FIRST)

# set up the default search directories for frameworks
set (CMAKE_SYSTEM_FRAMEWORK_PATH
    ${CMAKE_APPLE_SDK_ROOT}/System/Library/Frameworks
    ${CMAKE_APPLE_SDK_ROOT}/System/Library/PrivateFrameworks
    ${CMAKE_APPLE_SDK_ROOT}/Developer/Library/Frameworks
)

# only search the Apple *OS sdks, not the remainder of the host filesystem
set (CMAKE_FIND_ROOT_PATH_MODE_PROGRAM ONLY)
set (CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set (CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# Force the compilers to clang for Apple *OS
include (CMakeForceCompiler)
CMAKE_FORCE_C_COMPILER (/usr/bin/clang Apple)
CMAKE_FORCE_CXX_COMPILER (/usr/bin/clang++ Apple)

# Force ar
set (CMAKE_AR /usr/bin/ar CACHE FILEPATH "" FORCE)
set (CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR> <LINK_FLAGS> crs <TARGET> <OBJECTS>")
set (CMAKE_C_ARCHIVE_APPEND "<CMAKE_AR> <LINK_FLAGS> rs <TARGET> <OBJECTS>")
set (CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> <LINK_FLAGS> crs <TARGET> <OBJECTS>")
set (CMAKE_CXX_ARCHIVE_APPEND "<CMAKE_AR> <LINK_FLAGS> rs <TARGET> <OBJECTS>")

# Skip the platform compiler checks for cross compiling
set (CMAKE_CXX_COMPILER_WORKS TRUE)
set (CMAKE_C_COMPILER_WORKS TRUE)

# Hidden visibilty is required for cxx on Apple *OS
set (CMAKE_C_FLAGS "${APPLE_VERSION_FLAG} -isysroot ${CMAKE_OSX_SYSROOT}" CACHE STRING "")
set (CMAKE_CXX_FLAGS
    "${APPLE_VERSION_FLAG} -fvisibility=hidden -fvisibility-inlines-hidden -std=gnu++11 -isysroot ${CMAKE_OSX_SYSROOT}"
    CACHE STRING ""
)

set (CMAKE_C_LINK_FLAGS "-Wl,-search_paths_first ${CMAKE_C_LINK_FLAGS}")
set (CMAKE_CXX_LINK_FLAGS "-Wl,-search_paths_first ${CMAKE_CXX_LINK_FLAGS}")

set (CMAKE_PLATFORM_HAS_INSTALLNAME 1)
set (CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS "-dynamiclib -headerpad_max_install_names")
set (CMAKE_SHARED_MODULE_CREATE_C_FLAGS "-bundle -headerpad_max_install_names")
set (CMAKE_SHARED_MODULE_LOADER_C_FLAG "-Wl,-bundle_loader,")
set (CMAKE_SHARED_MODULE_LOADER_CXX_FLAG "-Wl,-bundle_loader,")
set (CMAKE_FIND_LIBRARY_SUFFIXES ".dylib" ".so" ".a")

# Define target platform as Apple *OS
set (PLATFORM_VERSION ${APPLE_PLATFORM_VERSION_MIN} CACHE STRING "Apple *OS minimum supported version")

string (REPLACE ";" "-" PLATFORM_ARCH "${APPLE_ARCH}")
set (PLATFORM_ARCH ${PLATFORM_ARCH} CACHE STRING "Target processor architecture")

# This little macro lets you set any XCode specific property
macro (set_xcode_property TARGET XCODE_PROPERTY XCODE_VALUE)
    set_property (TARGET ${TARGET} PROPERTY XCODE_ATTRIBUTE_${XCODE_PROPERTY} ${XCODE_VALUE})
endmacro (set_xcode_property)

# This macro lets you find executable programs on the host system
macro (find_host_package)
    set (CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
    set (CMAKE_FIND_ROOT_PATH_MODE_LIBRARY NEVER)
    set (CMAKE_FIND_ROOT_PATH_MODE_INCLUDE NEVER)
    set (IOS FALSE)

    find_package(${ARGN})

    set (IOS TRUE)
    set (CMAKE_FIND_ROOT_PATH_MODE_PROGRAM ONLY)
    set (CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
    set (CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
endmacro (find_host_package)
