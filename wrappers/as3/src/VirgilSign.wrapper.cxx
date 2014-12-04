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

#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;

GEN_DESTRUCTOR(VirgilSign, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_new_VirgilSign"
            "(asSignerCertificate:int, asHashName:ByteArray, asSignedDigest:ByteArray):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_new_VirgilSign() {
    const VirgilCertificate *cSignerCertificate = (VirgilCertificate *)0;
    AS3_GetScalarFromVar(cSignerCertificate, asSignerCertificate)

    VirgilByteArray cHashName;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asHashName, cHashName);

    VirgilByteArray cSignedDigest;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asSignedDigest, cSignedDigest);

    VirgilSign *cSelf = new VirgilSign(*cSignerCertificate, cHashName, cSignedDigest);
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilSign_id(asSelf):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilSign_id() {

    VirgilSign *cSelf = (VirgilSign *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    const VirgilSignId& cSignId = cSelf->id();

    AS3_DeclareVar(asSignId, int);
    AS3_CopyScalarToVar(asSignId, &cSignId);
    AS3_ReturnAS3Var(asSignId);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilSign_setId(asSelf, asSignId:int):void"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilSign_setId() {
    VirgilSign *cSelf = (VirgilSign *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilSignId *cSignId = (VirgilSignId *)0;
    AS3_GetScalarFromVar(cSignId, asSignId);

    cSelf->setId(*cSignId);

    AS3_ReturnAS3Var(undefined);
}
__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilSign_signerCertificate(asSelf):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilSign_signerCertificate() {
    VirgilSign *cSelf = (VirgilSign *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    const VirgilCertificate& cSignerCertificate = cSelf->signerCertificate();

    AS3_DeclareVar(asSignerCertificate, int);
    AS3_CopyScalarToVar(asSignerCertificate, &cSignerCertificate);
    AS3_ReturnAS3Var(asSignerCertificate);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilSign_hashName(asSelf):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilSign_hashName() {
    VirgilSign *cSelf = (VirgilSign *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cHashName = cSelf->hashName();
    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cHashName, asHashName);

    AS3_ReturnAS3Var(asHashName);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilSign_signedDigest(asSelf):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilSign_signedDigest() {
    VirgilSign *cSelf = (VirgilSign *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cSignedDigest = cSelf->signedDigest();
    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cSignedDigest, asSignedDigest);

    AS3_ReturnAS3Var(asSignedDigest);
}
