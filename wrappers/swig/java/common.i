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

%javaexception("java.io.IOException") virgil::crypto::VirgilDataSource::hasData {}
%javaexception("java.io.IOException") virgil::crypto::VirgilDataSource::read {}
%javaexception("java.io.IOException") virgil::crypto::VirgilDataSink::write {}
%javaexception("java.io.IOException") virgil::crypto::VirgilDataSink::isGood {}

%typemap(javainterfaces) SWIGTYPE "java.lang.AutoCloseable";
%typemap(javacode) SWIGTYPE %{
  @Override
  public void close() {
    delete();
  }
%}

%typemap(javacode) virgil::crypto::VirgilDataSource %{
  @Override
  public void close() throws java.io.IOException {
    delete();
  }
%}

%typemap(javacode) virgil::crypto::VirgilDataSink %{
  @Override
  public void close() throws java.io.IOException {
    delete();
  }
%}

// VirgilByteArray typemap
#define SWIG_VIRGIL_BYTE_ARRAY
%include "java/VirgilByteArray.i"

// Apply a rule for renaming the enum elements to avoid the common prefixes
// which are redundant in C#
%rename("%(regex:/^([A-Z][a-z]+)+_(.*)/\\2/)s", %$isenumitem) "";
