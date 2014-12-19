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

include (CMakeForceCompiler)

set (AS3                         ON)
set (PLATFORM_EMBEDDED           ON)
set (PLATFORM_NAME               "AS3" CACHE STRING "")
set (PLATFORM_PREFIX             "$ENV{CROSSBRIDGE_HOME}/sdk")

set (CMAKE_SYSTEM_NAME           "Linux" CACHE STRING "Target system.")
set (CMAKE_SYSTEM_PROCESSOR      "LLVM-IR" CACHE STRING "Target processor.")
set (CMAKE_FIND_ROOT_PATH        "${PLATFORM_PREFIX};${PLATFORM_PREFIX}/usr;${PLATFORM_PREFIX}/usr/lib")
set (CMAKE_AR                    "${PLATFORM_PREFIX}/usr/bin/ar" CACHE STRING "")
set (CMAKE_RANLIB                "${PLATFORM_PREFIX}/usr/bin/ranlib" CACHE STRING "")
set (CMAKE_C_COMPILER            "${PLATFORM_PREFIX}/usr/bin/gcc")
set (CMAKE_CXX_COMPILER          "${PLATFORM_PREFIX}/usr/bin/g++")
set (CMAKE_C_FLAGS               "-U__STRICT_ANSI__" CACHE STRING "")
set (CMAKE_CXX_FLAGS             "-U__STRICT_ANSI__" CACHE STRING "")
set (CMAKE_C_FLAGS_RELEASE       "-O3" CACHE STRING "")
set (CMAKE_CXX_FLAGS_RELEASE     "-O3" CACHE STRING "")

cmake_force_c_compiler (${CMAKE_C_COMPILER} FLASCC)
cmake_force_cxx_compiler (${CMAKE_CXX_COMPILER} FLASXX)

set (CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set (CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set (CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set (CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

include_directories (SYSTEM ${PLATFORM_PREFIX}/usr/include)
link_directories (${PLATFORM_PREFIX}/usr/lib)
