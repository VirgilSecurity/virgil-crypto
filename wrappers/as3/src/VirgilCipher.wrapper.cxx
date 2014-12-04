/**
 * Copyright (C) 2014 Virgil Security Inc.
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

#include <virgil/service/VirgilCipher.h>
using virgil::service::VirgilCipher;

GEN_THROWABLE_CONSTRUCTOR(VirgilCipher, com.virgilsecurity.wrapper)
GEN_DESTRUCTOR(VirgilCipher, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3sig:public function _wrap_VirgilCipher_generateKeyPair():int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilCipher_generateKeyPair() {

    VirgilKeyPair *cKeyPair = new VirgilKeyPair(VirgilCipher::generateKeyPair());

    AS3_DeclareVar(asKeyPair, int);
    AS3_CopyScalarToVar(asKeyPair, cKeyPair);
    AS3_ReturnAS3Var(asKeyPair);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilCipher_encrypt"
            "(asSelf, asDataSource:*, asDataSink:*, asPublicKey:ByteArray):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilCipher_encrypt() {
WRAPPER_THROWABLE_SECTION_START
    VirgilCipher *cSelf = (VirgilCipher *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    AS3::local::var cDataSource;
    AS3_GetVarxxFromVar(cDataSource, asDataSource);
    VirgilDataSourceWrapper cDataSourceWrapper(cDataSource);

    AS3::local::var cDataSink;
    AS3_GetVarxxFromVar(cDataSink, asDataSink);
    VirgilDataSinkWrapper cDataSinkWrapper(cDataSink);

    VirgilByteArray cPublicKey;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPublicKey, cPublicKey);

    VirgilByteArray cEncryptionKey = cSelf->encrypt(cDataSourceWrapper, cDataSinkWrapper, cPublicKey);

    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cEncryptionKey, asEncryptionKey);

    AS3_ReturnAS3Var(asEncryptionKey);
WRAPPER_THROWABLE_SECTION_END
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilCipher_decrypt"
            "(asSelf, asDataSource:*, asDataSink:*, asEncryptionKey:ByteArray,"
            "asPrivateKey:ByteArray, asPrivateKeyPassword:ByteArray):void"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilCipher_decrypt() {
WRAPPER_THROWABLE_SECTION_START
    VirgilCipher *cSelf = (VirgilCipher *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    AS3::local::var cDataSource;
    AS3_GetVarxxFromVar(cDataSource, asDataSource);
    VirgilDataSourceWrapper cDataSourceWrapper(cDataSource);

    AS3::local::var cDataSink;
    AS3_GetVarxxFromVar(cDataSink, asDataSink);
    VirgilDataSinkWrapper cDataSinkWrapper(cDataSink);

    VirgilByteArray cEncryptionKey;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asEncryptionKey, cEncryptionKey);

    VirgilByteArray cPrivateKey;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPrivateKey, cPrivateKey);

    VirgilByteArray cPrivateKeyPassword;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPrivateKeyPassword, cPrivateKeyPassword);

    cSelf->decrypt(cDataSourceWrapper, cDataSinkWrapper, cEncryptionKey, cPrivateKey, cPrivateKeyPassword);

    AS3_ReturnAS3Var(undefined);
WRAPPER_THROWABLE_SECTION_END
}
