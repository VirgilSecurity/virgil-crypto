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

#
# Dependent on variables:
#     - ENABLE_WRAPPER_CSHARP - enable / disable build wrapper for CSharp
#     - ENABLE_WRAPPER_JS     - enable / disable build wrapper for Java Script
#     - ENABLE_WRAPPER_PHP    - enable / disable build wrapper for PHP
#
# Define variables:
#     - WRAPPED_LIB_NAME - name of the wrapped library
#

cmake_minimum_required (VERSION 2.8 FATAL_ERROR)

project (wrappers)

# Define variables
set (WRAPPED_LIB_NAME virgil)

# Add include directory of wrapped module
include_directories (${${WRAPPED_LIB_NAME}_SOURCE_DIR}/include)
include_directories (swig)

# Add wrappers
if (ENABLE_WRAPPER_CSHARP)
    add_subdirectory (csharp)
endif (ENABLE_WRAPPER_CSHARP)

if (ENABLE_WRAPPER_JS)
    # add_subdirectory (javascript)
    add_subdirectory (js)
endif (ENABLE_WRAPPER_JS)

if (ENABLE_WRAPPER_PHP)
    add_subdirectory (php)
endif (ENABLE_WRAPPER_PHP)

if (ENABLE_WRAPPER_AS3)
    add_subdirectory (as3)
endif (ENABLE_WRAPPER_AS3)
