#
# Copyright (C) 2015-2016 Virgil Security Inc.
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
# This module can be used as part of the build process to transform namespaces upper camelcase.
#
# @example:
#     add_custom_command (TARGET ${tgt} POST_BUILD
#          COMMAND ${CMAKE_COMMAND}
#          ARGS
#              -DSRC_DIR:PATH=${PATH_TO_SOURCE_DIR}
#              -DGLOBBING_EXPRESSION:STRING="*.cs"
#              -P "${FULL_PATH_TO_THIS_FILE}"
#     )
#

if (NOT SRC_DIR)
    message (FATAL_ERROR "Source directory is not defined. Please define variable SRC_DIR.")
endif ()

if (NOT IS_DIRECTORY ${SRC_DIR})
    message (FATAL_ERROR "Given source directory does not exists: " ${SRC_DIR})
endif ()

if (NOT GLOBBING_EXPRESSION)
    message (FATAL_ERROR "Globbing expression is not defined. "
            "Please define variable GLOBBING_EXPRESSION to be used as template for coping process.")
endif ()

file (GLOB_RECURSE sources ${SRC_DIR} ${GLOBBING_EXPRESSION})

function (uppercase_namespaces src dst)
    set (local_dst "${src}")
    string (REGEX REPLACE
        "virgil\\.crypto\\.foundation\\.asn1([ .{;]+)" "Virgil.Crypto.Foundation.Asn1\\1" local_dst "${local_dst}"
    )
    string (REGEX REPLACE
        "virgil\\.crypto\\.foundation\\.cms([ .{;]+)" "Virgil.Crypto.Foundation.Cms\\1" local_dst "${local_dst}"
    )
    string (REGEX REPLACE
        "virgil\\.crypto\\.foundation([ .{;]+)" "Virgil.Crypto.Foundation\\1" local_dst "${local_dst}"
    )
    string (REGEX REPLACE
        "virgil\\.crypto\\.pfs([ .{;]+)" "Virgil.Crypto.Pfs\\1" local_dst "${local_dst}"
    )
    string (REGEX REPLACE
        "virgil\\.crypto([ .{;]+)" "Virgil.Crypto\\1" local_dst "${local_dst}"
    )
    set (${dst} "${local_dst}" PARENT_SCOPE)
endfunction (uppercase_namespaces)

foreach (src ${sources})
    file (READ ${src} content)
    uppercase_namespaces ("${content}" modified_content)
    file (WRITE "${src}" "${modified_content}")
endforeach ()
