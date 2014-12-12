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

# An extrenal project for PolarSSL library build
#
# Define variables:
#     - POLARSSL_LIBRARY_NAME - library file name
#     - POLARSSL_INCLUDE_DIR  - full path to the library includes
#     - POLARSSL_LIBRARY      - full patch to the library
#

include(CheckCCompilerFlag)

# Configure compiler settings
check_c_compiler_flag (-fPIC COMPILER_SUPPORT_PIC)
if (COMPILER_SUPPORT_PIC)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
endif()

check_c_compiler_flag (-fPIC COMPILER_SUPPORT_ARCH)
if (CMAKE_OSX_ARCHITECTURES AND COMPILER_SUPPORT_ARCH)
    foreach (arch ${CMAKE_OSX_ARCHITECTURES})
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -arch ${arch}")
    endforeach (arch)
endif (CMAKE_OSX_ARCHITECTURES AND COMPILER_SUPPORT_ARCH)

# Select patch config
if (ENABLE_WRAPPER_AS3)
    set (PATCH_CONFIG_FILE_NAME "patch_config_as3.yml")
else ()
    set (PATCH_CONFIG_FILE_NAME "patch_config_all.yml")
endif ()

# Add external project build steps
set (CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
    -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
    -DCMAKE_C_FLAGS:STRING=${CMAKE_C_FLAGS}
    -DENABLE_PROGRAMS:BOOL=OFF
    -DENABLE_TESTING:BOOL=OFF
)

if (CMAKE_TOOLCHAIN_FILE)
    list (APPEND CMAKE_ARGS
        -DCMAKE_TOOLCHAIN_FILE:PATH=${CMAKE_TOOLCHAIN_FILE}
    )
else ()
    list (APPEND CMAKE_ARGS
        -DCMAKE_C_COMPILER:STRING=${CMAKE_C_COMPILER}
    )
endif ()

ExternalProject_Add (polarssl_project
    URL "${CMAKE_CURRENT_SOURCE_DIR}/polarssl/bundle/polarssl-1.3.8-gpl.tgz"
    PREFIX "${CMAKE_CURRENT_BINARY_DIR}/polarssl"
    CMAKE_ARGS ${CMAKE_ARGS}
    PATCH_COMMAND python "${CMAKE_CURRENT_SOURCE_DIR}/polarssl/patch/patch.py"
            --input=<SOURCE_DIR> --config-name=${PATCH_CONFIG_FILE_NAME}
)

# Payload targets and output variables
ExternalProject_Get_Property (polarssl_project INSTALL_DIR)

set (POLARSSL_LIBRARY_NAME ${CMAKE_STATIC_LIBRARY_PREFIX}polarssl${CMAKE_STATIC_LIBRARY_SUFFIX})
set (POLARSSL_INCLUDE_DIR "${INSTALL_DIR}/include")
set (POLARSSL_LIBRARY "${INSTALL_DIR}/lib/${POLARSSL_LIBRARY_NAME}")

# Workaround of http://public.kitware.com/Bug/view.php?id=14495
file (MAKE_DIRECTORY ${POLARSSL_INCLUDE_DIR})

add_custom_target (copy_polarssl_lib
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${POLARSSL_LIBRARY}" "${EXTERNAL_LIBS_DIR}/${POLARSSL_LIBRARY_NAME}"
    DEPENDS polarssl_project
)

add_library (polarssl STATIC IMPORTED)
set_property (TARGET polarssl PROPERTY IMPORTED_LOCATION ${POLARSSL_LIBRARY})
set_property (TARGET polarssl PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${POLARSSL_INCLUDE_DIR})
add_dependencies (polarssl polarssl_project copy_polarssl_lib)

