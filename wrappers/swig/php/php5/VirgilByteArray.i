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

/**
 * Typemap virgil::crypto::VirgilByteArray to PHP strings.
 */

%{
#define CAST_BYTE_ARRAY_PTR(T) reinterpret_cast<virgil::crypto::VirgilByteArray::const_pointer>(T)
#define CAST_CSTR_PTR(T) reinterpret_cast<const char *>(T)
%}

namespace virgil { namespace crypto {


    %naturalvar VirgilByteArray;

    class VirgilByteArray;

    %typemap(typecheck,precedence=SWIG_TYPECHECK_STRING) VirgilByteArray, const VirgilByteArray& %{
        $1 = ( Z_TYPE_PP($input) == IS_STRING ) ? 1 : 0;
    %}

    %typemap(in) VirgilByteArray %{
        convert_to_string_ex($input);
        $1.assign(CAST_BYTE_ARRAY_PTR(Z_STRVAL_PP($input)), CAST_BYTE_ARRAY_PTR(Z_STRVAL_PP($input) + Z_STRLEN_PP($input)));
    %}

    %typemap(directorout) VirgilByteArray %{
        convert_to_string_ex(&$input);
        $result.assign(CAST_BYTE_ARRAY_PTR(Z_STRVAL_P($input)), CAST_BYTE_ARRAY_PTR(Z_STRVAL_P($input) + Z_STRLEN_P($input)));
    %}

    %typemap(out) VirgilByteArray %{
        ZVAL_STRINGL($result, const_cast<char*>(CAST_CSTR_PTR($1.data())), $1.size(), 1);
    %}

    %typemap(directorin) VirgilByteArray, const VirgilByteArray& %{
        ZVAL_STRINGL($input, const_cast<char*>(CAST_CSTR_PTR($1.data())), $1.size(), 1);
    %}

    %typemap(out) const VirgilByteArray & %{
        ZVAL_STRINGL($result, const_cast<char*>(CAST_CSTR_PTR($1->data())), $1->size(), 1);
    %}

    %typemap(throws) VirgilByteArray, const VirgilByteArray& %{
        zend_throw_exception(NULL, const_cast<char*>(CAST_CSTR_PTR($1.data())), 0 TSRMLS_CC);
        return;
    %}

    /* These next two handle a function which takes a non-const reference to
     * a virgil::crypto::VirgilByteArray and modifies the VirgilByteArray. */
    %typemap(in) VirgilByteArray & ($*1_ltype temp) %{
        convert_to_string_ex($input);
        temp.assign(CAST_BYTE_ARRAY_PTR(Z_STRVAL_PP($input)), CAST_BYTE_ARRAY_PTR(Z_STRVAL_PP($input) + Z_STRLEN_PP($input)));
        $1 = &temp;
    %}

    %typemap(directorout) VirgilByteArray & ($*1_ltype *temp) %{
        convert_to_string_ex(&$input);
        temp = new $*1_ltype(CAST_BYTE_ARRAY_PTR(Z_STRVAL_PP($input)), CAST_BYTE_ARRAY_PTR(Z_STRVAL_PP($input) + Z_STRLEN_PP($input)));
        swig_acquire_ownership(temp);
        $result = temp;
    %}

    %typemap(argout) VirgilByteArray & %{
    ZVAL_STRINGL(*($input), const_cast<char*>(CAST_CSTR_PTR($1->data())), $1->size(), 1);
    %}

    /* SWIG will apply the non-const typemap above to const VirgilByteArray& without
     * this more specific typemap. */
    %typemap(argout) const VirgilByteArray & "";

}}
