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

# Subsequent toolchain loading is not really needed
if (DEFINED CMAKE_CROSSCOMPILING)
    return ()
endif ()

# Touch toolchain variable to suppress "unused variable" warning
if (CMAKE_TOOLCHAIN_FILE)
endif ()

include(CMakeForceCompiler)

set(UNIX                        True CACHE BOOL "NACL SDK available on *nix systems only")
set(LANG                        "cpp" CACHE STRING "Language name")
set(PLATFORM                    "pnacl" CACHE STRING "Platform name")
set(PLATFORM_EMBEDDED           YES CACHE BOOL "Mark target platform as embedded")
set(PLATFORM_TRIPLET            "pnacl")
set(PLATFORM_PREFIX             "$ENV{NACL_SDK_ROOT}/toolchain/mac_pnacl")
set(PLATFORM_PORTS_PREFIX       "${CMAKE_SOURCE_DIR}/ports/PNaCl")
set(PLATFORM_EXE_SUFFIX         ".pexe")

set(CMAKE_SYSTEM_NAME           "Generic" CACHE STRING "Target system.")
set(CMAKE_SYSTEM_PROCESSOR      "LLVM-IR" CACHE STRING "Target processor.")
set(CMAKE_FIND_ROOT_PATH        "${PLATFORM_PORTS_PREFIX}" "${PLATFORM_PREFIX}/usr")
set(CMAKE_AR                    "${PLATFORM_PREFIX}/bin/${PLATFORM_TRIPLET}-ar" CACHE STRING "")
set(CMAKE_RANLIB                "${PLATFORM_PREFIX}/bin/${PLATFORM_TRIPLET}-ranlib" CACHE STRING "")
set(CMAKE_C_COMPILER            "${PLATFORM_PREFIX}/bin/${PLATFORM_TRIPLET}-clang")
set(CMAKE_CXX_COMPILER          "${PLATFORM_PREFIX}/bin/${PLATFORM_TRIPLET}-clang++")
set(CMAKE_C_FLAGS               "-U__STRICT_ANSI__" CACHE STRING "")
set(CMAKE_CXX_FLAGS             "-U__STRICT_ANSI__" CACHE STRING "")
set(CMAKE_C_FLAGS_RELEASE       "-O2 -ffast-math" CACHE STRING "")
set(CMAKE_CXX_FLAGS_RELEASE     "-O2 -ffast-math --pnacl-exceptions=sjlj" CACHE STRING "")
set(CMAKE_C_FLAGS_DEBUG         "-O0 -g" CACHE STRING "")
set(CMAKE_CXX_FLAGS_DEBUG       "-O0 -g --pnacl-exceptions=sjlj" CACHE STRING "")

cmake_force_c_compiler(         ${CMAKE_C_COMPILER} Clang)
cmake_force_cxx_compiler(       ${CMAKE_CXX_COMPILER} Clang)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

macro(pnacl_finalise _target)
  add_custom_command(TARGET ${_target} POST_BUILD
    COMMENT "Finalising ${_target}"
    COMMAND "${PLATFORM_PREFIX}/bin/${PLATFORM_TRIPLET}-finalize" "$<TARGET_FILE:${_target}>")
endmacro()

include_directories(SYSTEM $ENV{NACL_SDK_ROOT}/include)
include_directories(SYSTEM $ENV{NACL_SDK_ROOT}/include/newlib)
link_directories($ENV{NACL_SDK_ROOT}/lib/pnacl/Release)
