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
# This module can be used as part of the build process to perferom regex replace in given file.
#
# @example:
#     add_custom_command (TARGET ${tgt} POST_BUILD
#          COMMAND ${CMAKE_COMMAND}
#          ARGS
#              -DSRC:PATH=${PATH_TO_SOURCE_FILE}
#              -DREGULAR_EXPRESSION:STRING="XXX"
#              -DREPLACE_EXPRESSION:STRING="YYY"
#              -P "${FULL_PATH_TO_THIS_FILE}"
#     )
#

if (NOT SRC)
    message (FATAL_ERROR "Source file is not defined. Please define variable SRC.")
endif ()

if (NOT EXISTS ${SRC})
    message (FATAL_ERROR "Given source file does not exists: " ${SRC})
endif ()

if (NOT REGULAR_EXPRESSION)
    message (FATAL_ERROR "Regular expression is not defined. Please define variable REGULAR_EXPRESSION.")
endif ()

if (NOT REPLACE_EXPRESSION)
    message (FATAL_ERROR "Regular expression is not defined. Please define variable REPLACE_EXPRESSION.")
endif ()

file (READ ${SRC} content)
string (REGEX REPLACE "${REGULAR_EXPRESSION}" "${REPLACE_EXPRESSION}" modified_content "${content}")
file (WRITE "${SRC}" "${modified_content}")
