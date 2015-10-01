/**
 * Copyright (C) 2015 Virgil Security Inc.
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

%{
#include <vector>
%}

namespace virgil { namespace crypto {


%naturalvar VirgilByteArray;

class VirgilByteArray;

// VirgilByteArray
%typemap(jni) VirgilByteArray "jbyteArray"
%typemap(jtype) VirgilByteArray "byte[]"
%typemap(jstype) VirgilByteArray "byte[]"
%typemap(javadirectorin) VirgilByteArray "$jniinput"
%typemap(javadirectorout) VirgilByteArray "$javacall"

%typemap(in) VirgilByteArray
%{ if(!$input) {
     SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
     return $null;
    }
    jbyte *$1_pdata = (jbyte *)jenv->GetByteArrayElements($input, 0);
    size_t $1_size = (size_t)jenv->GetArrayLength($input);
    if (!$1_pdata) return $null;
    $1.assign($1_pdata, $1_pdata + $1_size);
    jenv->ReleaseByteArrayElements($input, $1_pdata, 0); %}

%typemap(directorout) VirgilByteArray
%{ if(!$input) {
     if (!jenv->ExceptionCheck()) {
       SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
     }
     return $null;
   }
    jbyte *$1_pdata = (jbyte *)jenv->GetByteArrayElements($input, 0);
    size_t $1_size = (size_t)jenv->GetArrayLength($input);
    if (!$1_pdata) return $null;
    $result.assign($1_pdata, $1_pdata + $1_size);
    jenv->ReleaseByteArrayElements($input, $1_pdata, 0); %}

%typemap(directorin,descriptor="[B") VirgilByteArray
%{
    $input = jenv->NewByteArray($1.size());
    jenv->SetByteArrayRegion($input, 0, $1.size(), (const jbyte *)&$1[0]);
%}

%typemap(out) VirgilByteArray
%{
    $result = jenv->NewByteArray($1.size());
    jenv->SetByteArrayRegion($result, 0, $1.size(), (const jbyte *)&$1[0]);
%}

%typemap(javain) VirgilByteArray "$javainput"

%typemap(javaout) VirgilByteArray {
    return $jnicall;
  }

// const VirgilByteArray &
%typemap(jni) const VirgilByteArray & "jbyteArray"
%typemap(jtype) const VirgilByteArray & "byte[]"
%typemap(jstype) const VirgilByteArray & "byte[]"
%typemap(javadirectorin) const VirgilByteArray & "$jniinput"
%typemap(javadirectorout) const VirgilByteArray & "$javacall"

%typemap(in) const VirgilByteArray &
%{ if(!$input) {
     SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
     return $null;
   }
    jbyte *$1_pdata = (jbyte *)jenv->GetByteArrayElements($input, 0);
    size_t $1_size = (size_t)jenv->GetArrayLength($input);
    if (!$1_pdata) return $null;
    $*1_ltype $1_data($1_pdata, $1_pdata + $1_size);
    $1 = &$1_data;
    jenv->ReleaseByteArrayElements($input, $1_pdata, 0); %}

%typemap(directorout,warning=SWIGWARN_TYPEMAP_THREAD_UNSAFE_MSG) const VirgilByteArray &
%{ if(!$input) {
     SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
     return $null;
   }
    jbyte *$1_pdata = (jbyte *)jenv->GetByteArrayElements($input, 0);
    size_t $1_size = (size_t)jenv->GetArrayLength($input);
    if (!$1_pdata) return $null;
    /* possible thread/reentrant code problem */
    static $*1_ltype $1_data;
    $1_data = $1_pdata;
    $result = &$1_data;
    jenv->ReleaseByteArrayElements($input, $1_pdata, 0); %}

%typemap(directorin,descriptor="[B") const VirgilByteArray &
%{
    $input = jenv->NewByteArray($1.size());
    jenv->SetByteArrayRegion($input, 0, $1.size(), (const jbyte *)&$1[0]);
%}

%typemap(out) const VirgilByteArray & ($*1_ltype *temp)
%{
    temp = $1;
    $result = jenv->NewByteArray(temp->size());
    jenv->SetByteArrayRegion($result, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
%}

%typemap(javain) const VirgilByteArray & "$javainput"

%typemap(javaout) const VirgilByteArray & {
    return $jnicall;
  }

}}
