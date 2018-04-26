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

cmake_minimum_required (VERSION 3.10 FATAL_ERROR)

project (${WRAPPED_LIB_NAME}_asmjs)

# ---------------------------------------------------------------------------
#   Configure environment
# ---------------------------------------------------------------------------
set (LANG "asmjs" CACHE STRING "Language is asmjs" FORCE)
set (LANG_VERSION "" CACHE STRING "No version for asmjs" FORCE)

set (PLATFORM "" CACHE STRING "No platform name for asmjs, because it's crossplatform" FORCE)
set (PLATFORM_VERSION "" CACHE STRING "No platform version for asmjs, because it's crossplatform" FORCE)

set (WRAPPER_TARGET "${PROJECT_NAME}")

# ---------------------------------------------------------------------------
#   Include common emsdk build instructions
# ---------------------------------------------------------------------------
include ("${WRAPPERS_ROOT}/emsdk/CMakeLists.txt")

# ---------------------------------------------------------------------------
#   Add specific 'install' options to the target
# ---------------------------------------------------------------------------
