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

# ---------------------------------------------------------------------------
#   Environment
# ---------------------------------------------------------------------------
set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake" ${CMAKE_MODULE_PATH})

set (EMSCRIPTEN $ENV{EMSCRIPTEN})
if (NOT EMSCRIPTEN)
    message (FATAL_ERROR "Enviroment variable: EMSCRIPTEN not found."
        " See http://kripken.github.io/emscripten-site/docs/getting_started/downloads.html")
endif ()

set (WRAPPER_DOC_DIR_NAME "${INSTALL_DOC_DIR_NAME}/${WRAPPER_TARGET}/${VIRGIL_VERSION}")

# ---------------------------------------------------------------------------
#   Patch emscripten to supprt handle exceptions
# ---------------------------------------------------------------------------
set (ORIGINAL_EMBIND_FILE "${EMSCRIPTEN}/system/include/emscripten/bind.h")
set (VIRGIL_EMBIND_FILE "${CMAKE_CURRENT_BINARY_DIR}/virgil_bind.h")

message (STATUS "To be able support custom exception handling\n"
    "       patched header '${VIRGIL_EMBIND_FILE}' is used,\n"
    "       instead of '${ORIGINAL_EMBIND_FILE}' header."
)
execute_process (
    COMMAND perl
        "${CMAKE_CURRENT_LIST_DIR}/patch_embind.pl"
        "${ORIGINAL_EMBIND_FILE}"
        "${VIRGIL_EMBIND_FILE}"
    RESULT_VARIABLE EMBIND_PATCH_RESULT
    OUTPUT_VARIABLE EMBIND_PATCH_OUTPUT
)

# ---------------------------------------------------------------------------
#   Configure sources
# ---------------------------------------------------------------------------
configure_file (
    ${CMAKE_CURRENT_LIST_DIR}/wrapper.cxx
    ${CMAKE_CURRENT_BINARY_DIR}/wrapper.cxx
    @ONLY
)

configure_file (
    ${CMAKE_CURRENT_LIST_DIR}/example.html
    ${CMAKE_CURRENT_BINARY_DIR}/example.html
    @ONLY
)

# ---------------------------------------------------------------------------
#   Build
# ---------------------------------------------------------------------------
add_executable (${WRAPPER_TARGET} "${CMAKE_CURRENT_BINARY_DIR}/wrapper.cxx")
target_link_libraries (${WRAPPER_TARGET} ${WRAPPED_LIB_NAME})

target_compile_options (${WRAPPER_TARGET} PUBLIC -s DISABLE_EXCEPTION_CATCHING=0)

set_property (TARGET ${WRAPPER_TARGET} APPEND_STRING PROPERTY
        LINK_FLAGS " --bind -s DISABLE_EXCEPTION_CATCHING=0")

em_link_js_library (${WRAPPER_TARGET} ${CMAKE_CURRENT_LIST_DIR}/error.js)
em_link_post_js (${WRAPPER_TARGET} ${CMAKE_CURRENT_LIST_DIR}/helpers.js)

# ---------------------------------------------------------------------------
#   Install
# ---------------------------------------------------------------------------
install (TARGETS ${WRAPPER_TARGET} DESTINATION "${INSTALL_LIB_DIR_NAME}")

install (TARGETS ${WRAPPER_TARGET} DESTINATION "${WRAPPER_DOC_DIR_NAME}/example")

install (FILES ${CMAKE_CURRENT_BINARY_DIR}/example.html
    DESTINATION "${WRAPPER_DOC_DIR_NAME}/example"
)
