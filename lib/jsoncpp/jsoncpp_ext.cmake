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

# An extrenal project for JsonCpp library build
#
# Define variables:
#     - JSONCPP_LIBRARY_NAME - library file name
#     - JSONCPP_INCLUDE_DIR  - full path to the library includes
#     - JSONCPP_LIBRARY      - full patch to the library
#

include(CheckCCompilerFlag)

# Configure compiler settings
check_c_compiler_flag (-fPIC COMPILER_SUPPORT_PIC)
if (COMPILER_SUPPORT_PIC)
    set (CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -fPIC")
endif()

check_c_compiler_flag (-fPIC COMPILER_SUPPORT_ARCH)
if (CMAKE_OSX_ARCHITECTURES AND COMPILER_SUPPORT_ARCH)
    foreach (arch ${CMAKE_OSX_ARCHITECTURES})
        set (CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -arch ${arch}")
    endforeach (arch)
endif (CMAKE_OSX_ARCHITECTURES AND COMPILER_SUPPORT_ARCH)

# Add external project build steps
ExternalProject_Add (jsoncpp_project
    GIT_REPOSITORY "https://github.com/open-source-parsers/jsoncpp.git"
    PREFIX "${CMAKE_CURRENT_BINARY_DIR}/jsoncpp"
    CMAKE_ARGS
            -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
            -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
            -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
            -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
            -DCMAKE_CXX_FLAGS:STRING=${CMAKE_CXX_FLAGS}
            -DJSONCPP_WITH_TESTS:BOOL=OFF
            -DJSONCPP_WITH_POST_BUILD_UNITTEST:BOOL=OFF
            -DJSONCPP_LIB_BUILD_SHARED:BOOL=OFF
)

# Payload targets and output variables
ExternalProject_Get_Property (jsoncpp_project INSTALL_DIR)

set (JSONCPP_LIBRARY_NAME ${CMAKE_STATIC_LIBRARY_PREFIX}jsoncpp${CMAKE_STATIC_LIBRARY_SUFFIX})
set (JSONCPP_INCLUDE_DIR "${INSTALL_DIR}/include")
set (JSONCPP_LIBRARY "${INSTALL_DIR}/lib/${JSONCPP_LIBRARY_NAME}")

# Workaround of http://public.kitware.com/Bug/view.php?id=14495
file (MAKE_DIRECTORY ${JSONCPP_INCLUDE_DIR})

add_custom_target (copy_jsoncpp_lib
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${JSONCPP_LIBRARY}" "${EXTERNAL_LIBS_DIR}/${JSONCPP_LIBRARY_NAME}"
    DEPENDS jsoncpp_project
)

add_library (jsoncpp STATIC IMPORTED)
set_property (TARGET jsoncpp PROPERTY IMPORTED_LOCATION ${JSONCPP_LIBRARY})
set_property (TARGET jsoncpp PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${JSONCPP_INCLUDE_DIR})
add_dependencies (jsoncpp jsoncpp_project copy_jsoncpp_lib)

