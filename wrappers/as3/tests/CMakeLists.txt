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

# Input:
#     WRAPPER_SWC - AS3 SWC file name.

find_program (GRADLE_MODULE gradle)

if (GRADLE_MODULE AND DEFINED ENV{FLEX_HOME})

    configure_file (
        ${CMAKE_CURRENT_SOURCE_DIR}/build.gradle.in
        ${CMAKE_CURRENT_BINARY_DIR}/build.gradle
        @ONLY
    )

    file (COPY ${CMAKE_CURRENT_SOURCE_DIR}/lib DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
    file (COPY ${CMAKE_CURRENT_SOURCE_DIR}/src DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
    file (GLOB_RECURSE TEST_FILE_LIST "${CMAKE_CURRENT_SOURCE_DIR}/src/*.as")
    foreach (TEST_FILE ${TEST_FILE_LIST})
        string (REPLACE "${CMAKE_CURRENT_SOURCE_DIR}/" "" TEST_FILE_REL_PATH ${TEST_FILE})
        configure_file (
            ${CMAKE_CURRENT_SOURCE_DIR}/${TEST_FILE_REL_PATH}
            ${CMAKE_CURRENT_BINARY_DIR}/${TEST_FILE_REL_PATH}
            @ONLY
        )
    endforeach (TEST_FILE)

    add_test (
        NAME ${WRAPPER_SWC}
        COMMAND ${GRADLE_MODULE} build
    )

endif ()
