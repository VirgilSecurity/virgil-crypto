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

#include <virgil/service/data/VirgilTicketId.h>
using virgil::service::data::VirgilTicketId;

GEN_CONSTRUCTOR(VirgilTicketId, com.virgilsecurity.wrapper)
GEN_DESTRUCTOR(VirgilTicketId, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilTicketId_ticketId(asSelf):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilTicketId_ticketId() {

    VirgilTicketId *cSelf = (VirgilTicketId *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cTicketId = cSelf->ticketId();
    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cTicketId, asTicketId);

    AS3_ReturnAS3Var(asTicketId);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilTicketId_setTicketId(asSelf, asTicketId:ByteArray):void"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilTicketId_setTicketId() {
    VirgilTicketId *cSelf = (VirgilTicketId *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cTicketId;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asTicketId, cTicketId);

    cSelf->setTicketId(cTicketId);

    AS3_ReturnAS3Var(undefined);
}
