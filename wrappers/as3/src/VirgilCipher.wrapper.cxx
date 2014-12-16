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

#include <virgil/service/VirgilCipherDatagram.h>
using virgil::service::VirgilCipherDatagram;

GEN_THROWABLE_CONSTRUCTOR(VirgilCipher, com.virgilsecurity.wrapper)
GEN_DESTRUCTOR(VirgilCipher, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilCipher_encrypt"
            "(asSelf, asData:ByteArray, asPublicKey:ByteArray):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilCipher_encrypt() {
WRAPPER_THROWABLE_SECTION_START
    VirgilCipher *cSelf = (VirgilCipher *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cData;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asData, cData);

    VirgilByteArray cPublicKey;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPublicKey, cPublicKey);

    VirgilCipherDatagram *cDatagram = new VirgilCipherDatagram(cSelf->encrypt(cData, cPublicKey));

    AS3_DeclareVar(asDatagram, int);
    AS3_CopyScalarToVar(asDatagram, cDatagram);
    AS3_ReturnAS3Var(asDatagram);
WRAPPER_THROWABLE_SECTION_END
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilCipher_decrypt"
            "(asSelf, asData:ByteArray, asEncryptionKey:ByteArray,"
            "asPrivateKey:ByteArray, asPrivateKeyPassword:ByteArray = null):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilCipher_decrypt() {
WRAPPER_THROWABLE_SECTION_START
    VirgilCipher *cSelf = (VirgilCipher *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cData;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asData, cData);

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

    VirgilByteArray cResult = cSelf->decrypt(cData, cEncryptionKey, cPrivateKey, cPrivateKeyPassword);
    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cResult, asResult);

    AS3_ReturnAS3Var(asResult);
WRAPPER_THROWABLE_SECTION_END
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilCipher_encryptWithPassword"
            "(asSelf, asData:ByteArray, asPassword:ByteArray):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilCipher_encryptWithPassword() {
WRAPPER_THROWABLE_SECTION_START
    VirgilCipher *cSelf = (VirgilCipher *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cData;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asData, cData);

    VirgilByteArray cPassword;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPassword, cPassword);

    VirgilByteArray cEncryptedData = cSelf->encryptWithPassword(cData, cPassword);

    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cEncryptedData, asEncryptedData);

    AS3_ReturnAS3Var(asEncryptedData);
WRAPPER_THROWABLE_SECTION_END
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilCipher_decryptWithPassword"
            "(asSelf, asData:ByteArray, asPassword:ByteArray):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilCipher_decryptWithPassword() {
WRAPPER_THROWABLE_SECTION_START
    VirgilCipher *cSelf = (VirgilCipher *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cData;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asData, cData);

    VirgilByteArray cPassword;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPassword, cPassword);

    VirgilByteArray cDecryptedData = cSelf->decryptWithPassword(cData, cPassword);

    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cDecryptedData, asDecryptedData);

    AS3_ReturnAS3Var(asDecryptedData);
WRAPPER_THROWABLE_SECTION_END
}

