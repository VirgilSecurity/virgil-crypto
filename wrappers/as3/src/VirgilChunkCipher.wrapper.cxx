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

#include <virgil/service/VirgilChunkCipher.h>
using virgil::service::VirgilChunkCipher;

GEN_THROWABLE_CONSTRUCTOR(VirgilChunkCipher, com.virgilsecurity.wrapper)
GEN_DESTRUCTOR(VirgilChunkCipher, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilChunkCipher_adjustEncryptionChunkSize"
            "(asSelf, asPreferredChunkSize:uint):uint"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilChunkCipher_adjustEncryptionChunkSize() {
    VirgilChunkCipher *cSelf = (VirgilChunkCipher *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    size_t cPreferredChunkSize = 0;
    AS3_GetScalarFromVar(cPreferredChunkSize, asPreferredChunkSize);

    size_t cAdjustedChunkSize = cSelf->adjustEncryptionChunkSize(cPreferredChunkSize);

    AS3_DeclareVar(asAdjustedChunkSize, uint);
    AS3_CopyScalarToVar(asAdjustedChunkSize, cAdjustedChunkSize);
    AS3_ReturnAS3Var(asAdjustedChunkSize);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilChunkCipher_adjustDecryptionChunkSize"
            "(asSelf, asEncryptionChunkSize:uint):uint"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilChunkCipher_adjustDecryptionChunkSize() {
    VirgilChunkCipher *cSelf = (VirgilChunkCipher *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    size_t cEncryptionChunkSize = 0;
    AS3_GetScalarFromVar(cEncryptionChunkSize, asEncryptionChunkSize);

    size_t cAdjustedChunkSize = cSelf->adjustDecryptionChunkSize(cEncryptionChunkSize);

    AS3_DeclareVar(asAdjustedChunkSize, uint);
    AS3_CopyScalarToVar(asAdjustedChunkSize, cAdjustedChunkSize);
    AS3_ReturnAS3Var(asAdjustedChunkSize);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilChunkCipher_startEncryption"
            "(asSelf, asPublicKey:ByteArray):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilChunkCipher_startEncryption() {
WRAPPER_THROWABLE_SECTION_START
    VirgilChunkCipher *cSelf = (VirgilChunkCipher *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cPublicKey;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPublicKey, cPublicKey);

    VirgilByteArray cEncryptionKey = cSelf->startEncryption(cPublicKey);

    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cEncryptionKey, asEncryptionKey);

    AS3_ReturnAS3Var(asEncryptionKey);
WRAPPER_THROWABLE_SECTION_END
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilChunkCipher_startDecryption"
            "(asSelf, asEncryptionKey:ByteArray, asPrivateKey:ByteArray, asPrivateKeyPassword:ByteArray = null):void"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilChunkCipher_startDecryption() {
WRAPPER_THROWABLE_SECTION_START
    VirgilChunkCipher *cSelf = (VirgilChunkCipher *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cEncryptionKey;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asEncryptionKey, cEncryptionKey);

    VirgilByteArray cPrivateKey;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPrivateKey, cPrivateKey);

    bool cPasswordDefined = false;
    AS3_VAR_IS_DEFINED(asPrivateKeyPassword, cPasswordDefined);

    VirgilByteArray cPrivateKeyPassword;
    if (cPasswordDefined) {
        AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPrivateKeyPassword, cPrivateKeyPassword);
    }

    cSelf->startDecryption(cEncryptionKey, cPrivateKey, cPrivateKeyPassword);

    AS3_ReturnAS3Var(undefined);
WRAPPER_THROWABLE_SECTION_END
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilChunkCipher_process"
            "(asSelf, asData:ByteArray):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilChunkCipher_process() {
WRAPPER_THROWABLE_SECTION_START
    VirgilChunkCipher *cSelf = (VirgilChunkCipher *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cData;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asData, cData);

    VirgilByteArray cEncryptedData = cSelf->process(cData);

    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cEncryptedData, asEncryptedData);

    AS3_ReturnAS3Var(asEncryptedData);
WRAPPER_THROWABLE_SECTION_END
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilChunkCipher_finalize(asSelf):void"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilChunkCipher_finalize() {
    VirgilChunkCipher *cSelf = (VirgilChunkCipher *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    cSelf->finalize();

    AS3_ReturnAS3Var(undefined);
}
