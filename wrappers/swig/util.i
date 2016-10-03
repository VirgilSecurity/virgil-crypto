/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

%define DEFINE_NAMESPACE(className, package)
#if defined(SWIG_WRAP_NAMESPACE)
    %nspace package::className;
#endif
%enddef

%define INCLUDE_TYPE(typeName, includePath)
%insert("header") %{
#include <includePath/typeName.h>
%}
%include <includePath/typeName.h>
%enddef

%define INCLUDE_CLASS(className, package, includePath)
DEFINE_NAMESPACE(className, package)
%insert("header") %{
#include <includePath/className.h>
%}
%ignore package::className::className(className&&);
%include <includePath/className.h>
%enddef

%define INCLUDE_CLASS_WITH_DIRECTOR(className, package, includePath)
DEFINE_NAMESPACE(className, package)
%insert("header") %{
#include <includePath/className.h>
%}
%feature("director") className;
%include <includePath/className.h>
%enddef

%define INCLUDE_CLASS_WITH_COPY_CONSTRUCTOR(className, package, includePath)
DEFINE_NAMESPACE(className, package)
%insert("header") %{
#include <includePath/className.h>
%}
#if defined(SWIG_WRAP_COPY_CONSTRUCTOR)
    %copyctor className;
#else
    %ignore package::className::className(const package::className &);
#endif
%include <includePath/className.h>
%enddef

%define DEFINE_USING(className, package)
%insert("header") %{
using package::className;
%}
%enddef
