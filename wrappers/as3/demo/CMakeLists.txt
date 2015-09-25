#
# Copyright (C) 2015 Virgil Security Inc.
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

cmake_minimum_required (VERSION 3.2 FATAL_ERROR)

if (DEFINED ENV{FLEX_HOME})

    find_program (FLEX_COMPILER NAMES amxmlc PATHS $ENV{FLEX_HOME}/bin )
    find_program (FLEX_RUNNER NAMES adl PATHS $ENV{FLEX_HOME}/bin )
    if (FLEX_COMPILER)
        configure_file (
            ${CMAKE_CURRENT_SOURCE_DIR}/EncryptApp-AIR.xml
            ${CMAKE_CURRENT_BINARY_DIR}/
            COPYONLY
        )
        add_custom_target (demo
            COMMAND ${FLEX_COMPILER}
                    --static-link-runtime-shared-libraries -compiler.omit-trace-statements=false -debug=true
                    -library-path+=${WRAPPER_SWC} ${CMAKE_CURRENT_SOURCE_DIR}/EncryptApp.mxml -o EncryptApp.swf
            DEPENDS ${WRAPPER_SWC}
        )
    else (FLEX_COMPILER)
        message (WARNING "Flex compiler amxmlc was not found at:" $ENV{FLEX_HOME}/bin)
    endif (FLEX_COMPILER)

    if (FLEX_RUNNER)
        add_custom_target (demo_run
            COMMAND ${FLEX_RUNNER} ${CMAKE_CURRENT_BINARY_DIR}/EncryptApp-AIR.xml
        )
        add_dependencies (demo_run demo)
    else (FLEX_RUNNER)
        message (WARNING "Flex adl was not found at:" $ENV{FLEX_HOME}/bin)
    endif (FLEX_RUNNER)

else ()
    message (WARNING "FLEX_HOME is not defined, target 'demo' is OFF.")
endif ()
