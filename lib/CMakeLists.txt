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

cmake_minimum_required (VERSION 2.8 FATAL_ERROR)

project (virgil)

# Include and build external libraries
include (ExternalProject)
include (${CMAKE_CURRENT_SOURCE_DIR}/polarssl/polarssl_ext.cmake)
include (${CMAKE_CURRENT_SOURCE_DIR}/jsoncpp/jsoncpp_ext.cmake)

set (VIRGIL_LIB_INSTALL_DIR c++)

# Configure includes
include_directories (include)
if (CMAKE_MAJOR_VERSION LESS 3)
    include_directories (${POLARSSL_INCLUDE_DIR})
    include_directories (${JSONCPP_INCLUDE_DIR})
endif (CMAKE_MAJOR_VERSION LESS 3)

# Define sources list
file (GLOB src "src/*")
if (PLATFORM_NAME_LOWER STREQUAL "cpp")
    file (GLOB platform_src "src/platform/*")
    list (APPEND src ${platform_src})
endif()

add_library (${PROJECT_NAME} STATIC ${src})
set_property (TARGET ${PROJECT_NAME} PROPERTY OUTPUT_NAME ${PROJECT_NAME})
set_property (TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)
set_property (TARGET ${PROJECT_NAME} PROPERTY INTERFACE_POSITION_INDEPENDENT_CODE ON)

target_link_libraries (${PROJECT_NAME} polarssl jsoncpp)
add_custom_command (TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND}
    ARGS -E copy_if_different
            $<TARGET_FILE:${PROJECT_NAME}>
            ${EXTERNAL_LIBS_DIR}/$<TARGET_FILE_NAME:${PROJECT_NAME}>
)

if (PLATFORM_NAME_LOWER STREQUAL "cpp" OR PLATFORM_EMBEDDED)
    install (TARGETS ${PROJECT_NAME}
            ARCHIVE DESTINATION "${VIRGIL_LIB_INSTALL_DIR}/${INSTALL_LIB_DIR_NAME}")
    install (FILES ${POLARSSL_LIBRARY}
            DESTINATION "${VIRGIL_LIB_INSTALL_DIR}/${INSTALL_LIB_DIR_NAME}")
    install (FILES ${JSONCPP_LIBRARY}
            DESTINATION "${VIRGIL_LIB_INSTALL_DIR}/${INSTALL_LIB_DIR_NAME}")

    install (DIRECTORY include DESTINATION "${VIRGIL_LIB_INSTALL_DIR}")
endif ()
