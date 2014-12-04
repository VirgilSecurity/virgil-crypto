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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
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

#include <virgil/service/data/VirgilUserIdTicket.h>
using virgil::service::data::VirgilUserIdTicket;

#include <virgil/service/data/VirgilUserIdType.h>
using virgil::service::data::VirgilUserIdType;

GEN_DESTRUCTOR(VirgilUserIdTicket, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_new_VirgilUserIdTicket(asUserId:ByteArray, asUserIdType:int):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_new_VirgilUserIdTicket() {
    VirgilByteArray cUserId;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asUserId, cUserId);

    VirgilUserIdType *cUserIdType = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cUserIdType, asUserIdType);

    VirgilUserIdTicket *cSelf = new VirgilUserIdTicket(cUserId, *cUserIdType);
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilUserIdTicket_userId(asSelf):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdTicket_userId() {
    VirgilUserIdTicket *cSelf = (VirgilUserIdTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cUserId = cSelf->userId();
    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cUserId, asUserId);

    AS3_ReturnAS3Var(asUserId);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilUserIdTicket_userIdType(asSelf):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdTicket_userIdType() {
    VirgilUserIdTicket *cSelf = (VirgilUserIdTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    const VirgilUserIdType& cUserIdType = cSelf->userIdType();

    AS3_DeclareVar(asUserIdType, int);
    AS3_CopyScalarToVar(asUserIdType, &cUserIdType);
    AS3_ReturnAS3Var(asUserIdType);
}
