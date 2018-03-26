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

#
# This module can be used as part of the build process to add support of AOT compilator in PINVOKE.cs file generated by swig.


if (NOT SRC)
    message (FATAL_ERROR "Source file is not defined. Please define variable SRC.")
endif ()

if (NOT EXISTS ${SRC})
    message (FATAL_ERROR "Given source file does not exists: " ${SRC})
endif ()

file (READ ${SRC} content)

# replace .DllImport("...." to .DllImport("__Internal" 
string (REGEX REPLACE "${DLL_IMPORT_REGEXP}" "${DLL_IMPORT_REPLACE_EXPR}" modified_content "${content}")

# add annotation [global::ObjCRuntime.MonoNativeFunctionWrapper] for "public delegate" functions
string (REGEX REPLACE "${DELEGATE_REGEXP}" "${DELEGATE_REPLACE_EXPR}" modified_content "${modified_content}")

# add annotation [global::ObjCRuntime.MonoPInvokeCallback(typeof(ExceptionDelegate))] for static void SetPending.. functions 
string (REGEX REPLACE "${SET_PENDING_REGEXP}" "${SET_PENDING_REPLACE_EXPR}" modified_content "${modified_content}")

# add annotation [global::ObjCRuntime.MonoPInvokeCallback(typeof(ExceptionArgumentDelegate))] for static void SetPendingArgument.. functions
string (REGEX REPLACE "${SET_PENDING_ARGUMENT_REGEXP}" "${SET_PENDING_ARGUMENT_REPLACE_EXPR}" modified_content "${modified_content}")

# add annotation [ObjCRuntime.MonoPInvokeCallback(typeof(SWIGStringDelegate))] for "static string CreateString("
string (REGEX REPLACE "${CREATE_STRING_REGEXP}" "${CREATE_STRING_REPLACE_EXPR}" modified_content "${modified_content}")

# add annotation [ObjCRuntime.MonoPInvokeCallback(typeof(CreateManaged_byte_ArrayDelegate))] for "static System.IntPtr CreateManaged_byte_Array("
string (REGEX REPLACE "${CREATE_MANAGED_ARRAY_REGEXP}" "${CREATE_MANAGED_ARRAY_REPLACE_EXPR}" modified_content "${modified_content}")

# add annotation [ObjCRuntime.MonoPInvokeCallback(typeof(GetManaged_byte_ArraySizeDelegate))] for "static int GetManaged_byte_ArraySize"
string (REGEX REPLACE "${GET_ARRAY_SIZE_REGEXP}" "${GET_ARRAY_SIZE_REPLACE_EXPR}" modified_content "${modified_content}")

# add annotation [ObjCRuntime.MonoPInvokeCallback(typeof(CopyToUnmanaged_byte_ArrayDelegate))] for "static void CopyToUnmanaged_byte_Array("
string (REGEX REPLACE "${COPY_TO_UNMANAGED_REGEXP}" "${COPY_TO_UNMANAGED_REPLACE_EXPR}" modified_content "${modified_content}")
 
file (WRITE "${SRC}" "${modified_content}")
