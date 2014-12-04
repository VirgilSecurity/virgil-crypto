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

#include <virgil/service/data/VirgilTicket.h>
using virgil::service::data::VirgilTicket;

GEN_CONSTRUCTOR(VirgilTicket, com.virgilsecurity.wrapper)
GEN_DESTRUCTOR(VirgilTicket, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilTicket_id(asSelf):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilTicket_id() {

    VirgilTicket *cSelf = (VirgilTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    const VirgilTicketId& cTicketId = cSelf->id();

    AS3_DeclareVar(asTicketId, int);
    AS3_CopyScalarToVar(asTicketId, &cTicketId);
    AS3_ReturnAS3Var(asTicketId);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilTicket_setId(asSelf, asTicketId:int):void"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilTicket_setId() {
    VirgilTicket *cSelf = (VirgilTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilTicketId *cTicketId = (VirgilTicketId *)0;
    AS3_GetScalarFromVar(cTicketId, asTicketId);

    cSelf->setId(*cTicketId);

    AS3_ReturnAS3Var(undefined);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilTicket_isUserIdTicket(asSelf):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilTicket_isUserIdTicket() {

    VirgilTicket *cSelf = (VirgilTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    bool cIsUserIdTicket = cSelf->isUserIdTicket();

    AS3_Return(cIsUserIdTicket);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilTicket_asUserIdTicket(asSelf):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilTicket_asUserIdTicket() {
WRAPPER_THROWABLE_SECTION_START
    VirgilTicket *cSelf = (VirgilTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    const virgil::service::data::VirgilUserIdTicket& cUserIdTicket = cSelf->asUserIdTicket();

    AS3_DeclareVar(asUserIdTicket, int);
    AS3_CopyScalarToVar(asUserIdTicket, &cUserIdTicket);
    AS3_ReturnAS3Var(asUserIdTicket);
WRAPPER_THROWABLE_SECTION_END
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilTicket_isUserInfoTicket(asSelf):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilTicket_isUserInfoTicket() {

    VirgilTicket *cSelf = (VirgilTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    bool cIsUserInfoTicket = cSelf->isUserInfoTicket();

    AS3_Return(cIsUserInfoTicket);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilTicket_asUserInfoTicket(asSelf):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilTicket_asUserInfoTicket() {
WRAPPER_THROWABLE_SECTION_START
    VirgilTicket *cSelf = (VirgilTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    const virgil::service::data::VirgilUserInfoTicket& cUserInfoTicket = cSelf->asUserInfoTicket();

    AS3_DeclareVar(asUserInfoTicket, int);
    AS3_CopyScalarToVar(asUserInfoTicket, &cUserInfoTicket);
    AS3_ReturnAS3Var(asUserInfoTicket);
WRAPPER_THROWABLE_SECTION_END
}
