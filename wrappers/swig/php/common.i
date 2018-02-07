/**
 * Copyright (C) 2015-2017 Virgil Security Inc.
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

// Add library details to the PHP module.
%pragma(php) phpinfo="
  php_info_print_table_start();
  php_info_print_table_header(2, \"Directive\", \"Value\");
  php_info_print_table_row(2, \"Version\", virgil::crypto::VirgilVersion::fullName().c_str());
#if defined(VIRGIL_CRYPTO_FEATURE_LOW_LEVEL_WRAP)
  php_info_print_table_row(2, \"Low-level API support\", \"enabled\");
#else
  php_info_print_table_row(2, \"Low-level API support\", \"disabled\");
#endif
  php_info_print_table_end();
"

// Redefine SWIG_exception macro for PHP
%{
#undef SWIG_exception
#define SWIG_exception(code, msg) { zend_throw_exception(NULL, (char*)msg, code TSRMLS_CC); return; }
%}

// VirgilByteArray typemap
#define SWIG_VIRGIL_BYTE_ARRAY
#if defined(SWIGPHP5)
%include "php5/VirgilByteArray.i"
#elif defined(SWIGPHP7)
%include "php7/VirgilByteArray.i"
#else
#error Unsupported version of PHP was given. Only PHP5 and PHP7 currently supported.
#endif

// Redefine typemap for enums
%typemap(in)  VirgilKeyPair::Type = int;
%typemap(out) VirgilKeyPair::Type = int;

%typemap(in)  VirgilPBKDF::Algorithm = int;
%typemap(out) VirgilPBKDF::Algorithm = int;

%typemap(in)  VirgilHash::Algorithm = int;
%typemap(out) VirgilHash::Algorithm = int;

%typemap(in)  VirgilTinyCipher::PackageSize = size_t;
%typemap(out) VirgilTinyCipher::PackageSize = size_t;

#if defined(VIRGIL_CRYPTO_FEATURE_LOW_LEVEL_WRAP)

%typemap(in)  VirgilSymmetricCipher::Padding = int;
%typemap(out) VirgilSymmetricCipher::Padding = int;

%typemap(in)  VirgilSymmetricCipher::Algorithm = int;
%typemap(out) VirgilSymmetricCipher::Algorithm = int;

%typemap(in)  VirgilPBE::Algorithm = int;
%typemap(out) VirgilPBE::Algorithm = int;

%typemap(in)  VirgilKDF::Algorithm = int;
%typemap(out) VirgilKDF::Algorithm = int;

%typemap(in)  VirgilCMSContentType = int;
%typemap(out) VirgilCMSContentType = int;

#endif
