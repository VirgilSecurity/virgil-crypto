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

#include <virgil/service/data/VirgilUserIdType.h>
using virgil::service::data::VirgilUserIdType;

GEN_DESTRUCTOR(VirgilUserIdType, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_email():int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_email() {
    const VirgilUserIdType& cSelf = VirgilUserIdType::email;
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, &cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_phone():int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_phone() {
    const VirgilUserIdType& cSelf = VirgilUserIdType::phone;
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, &cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_fax():int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_fax() {
    const VirgilUserIdType& cSelf = VirgilUserIdType::fax;
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, &cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_domain():int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_domain() {
    const VirgilUserIdType& cSelf = VirgilUserIdType::domain;
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, &cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_macAddress():int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_macAddress() {
    const VirgilUserIdType& cSelf = VirgilUserIdType::macAddress;
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, &cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_application():int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_application() {
    const VirgilUserIdType& cSelf = VirgilUserIdType::application;
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, &cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_isEmail(asSelf):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_isEmail() {
    VirgilUserIdType *cSelf = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    bool cResult = (int)(cSelf->isEmail());

    AS3_DeclareVar(asResult, Boolean);
    AS3_CopyScalarToVar(asResult, cResult);
    AS3_ReturnAS3Var(asResult);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_isPhone(asSelf):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_isPhone() {
    VirgilUserIdType *cSelf = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    bool cResult = (int)(cSelf->isPhone());

    AS3_DeclareVar(asResult, Boolean);
    AS3_CopyScalarToVar(asResult, cResult);
    AS3_ReturnAS3Var(asResult);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_isFax(asSelf):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_isFax() {
    VirgilUserIdType *cSelf = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    bool cResult = (int)(cSelf->isFax());

    AS3_DeclareVar(asResult, Boolean);
    AS3_CopyScalarToVar(asResult, cResult);
    AS3_ReturnAS3Var(asResult);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_isDomain(asSelf):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_isDomain() {
    VirgilUserIdType *cSelf = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    bool cResult = (int)(cSelf->isDomain());

    AS3_DeclareVar(asResult, Boolean);
    AS3_CopyScalarToVar(asResult, cResult);
    AS3_ReturnAS3Var(asResult);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_isMacAddress(asSelf):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_isMacAddress() {
    VirgilUserIdType *cSelf = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    bool cResult = (int)(cSelf->isMacAddress());

    AS3_DeclareVar(asResult, Boolean);
    AS3_CopyScalarToVar(asResult, cResult);
    AS3_ReturnAS3Var(asResult);
}


__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_isApplication(asSelf):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_isApplication() {
    VirgilUserIdType *cSelf = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    bool cResult = (int)(cSelf->isApplication());

    AS3_DeclareVar(asResult, Boolean);
    AS3_CopyScalarToVar(asResult, cResult);
    AS3_ReturnAS3Var(asResult);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_name(asSelf):String"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_name() {
    VirgilUserIdType *cSelf = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    std::string cName = cSelf->name();
    STD_STRING_TO_AS3_STRING(cName, asName);

    AS3_ReturnAS3Var(asName);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_code(asSelf):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_code() {
    VirgilUserIdType *cSelf = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    int cCode = (int)(cSelf->code());

    AS3_DeclareVar(asCode, int);
    AS3_CopyScalarToVar(asCode, cCode);
    AS3_ReturnAS3Var(asCode);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_equals(asLeft:int, asRight:int):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_equals() {
    VirgilUserIdType *cLeft = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cLeft, asLeft);

    VirgilUserIdType *cRight = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cRight, asRight);

    bool cEqual = operator==(*cLeft, *cRight);

    AS3_DeclareVar(asCode, Boolean);
    AS3_CopyScalarToVar(asCode, cEqual);
    AS3_ReturnAS3Var(asCode);
}
