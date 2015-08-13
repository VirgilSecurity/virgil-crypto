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

#ifndef AS3_VIRGIL_CUSTOM_PARAMS_HPP
#define AS3_VIRGIL_CUSTOM_PARAMS_HPP

#include <virgil/crypto/VirgilCustomParams.h>
using virgil::crypto::VirgilCustomParams;

#include "as3_utils.hpp"

AS3_DECL_FUNC(_wrap_VirgilCustomParameters_isEmpty, "(asSelf:int):Boolean") {
    AS3_TO_C_PTR(VirgilCustomParams, asSelf, cSelf);
    bool cIsEmpty = cSelf->isEmpty();
    AS3_RETURN_C_BOOL(cIsEmpty);
}

AS3_DECL_FUNC(_wrap_VirgilCustomParameters_clear, "(asSelf:int):void") {
    AS3_TO_C_PTR(VirgilCustomParams, asSelf, cSelf);
    cSelf->clear();
    AS3_RETURN_VOID();
}

AS3_DECL_FUNC(_wrap_VirgilCustomParameters_setInteger, "(asSelf:int, asKey:ByteArray, asValue:int):void") {
    AS3_TO_C_PTR(VirgilCustomParams, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asKey, cKey);
    AS3_TO_C_INT(asValue, cValue);
    cSelf->setInteger(cKey, cValue);
    AS3_RETURN_VOID();
}

AS3_DECL_FUNC(_wrap_VirgilCustomParameters_getInteger, "(asSelf:int, asKey:ByteArray):int") {
AS3_THROWABLE_SECTION_START
    AS3_TO_C_PTR(VirgilCustomParams, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asKey, cKey);
    int cValue = cSelf->getInteger(cKey);
    AS3_RETURN_C_INT(cValue);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilCustomParameters_removeInteger, "(asSelf:int, asKey:ByteArray):void") {
    AS3_TO_C_PTR(VirgilCustomParams, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asKey, cKey);
    cSelf->removeInteger(cKey);
    AS3_RETURN_VOID();
}

AS3_DECL_FUNC(_wrap_VirgilCustomParameters_setString, "(asSelf:int, asKey:ByteArray, asValue:ByteArray):void") {
    AS3_TO_C_PTR(VirgilCustomParams, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asKey, cKey);
    AS3_TO_C_BYTE_ARRAY(asValue, cValue);
    cSelf->setString(cKey, cValue);
    AS3_RETURN_VOID();
}

AS3_DECL_FUNC(_wrap_VirgilCustomParameters_getString, "(asSelf:int, asKey:ByteArray):ByteArray") {
AS3_THROWABLE_SECTION_START
    AS3_TO_C_PTR(VirgilCustomParams, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asKey, cKey);
    VirgilByteArray cValue = cSelf->getString(cKey);
    AS3_RETURN_C_BYTE_ARRAY(cValue);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilCustomParameters_removeString, "(asSelf:int, asKey:ByteArray):void") {
    AS3_TO_C_PTR(VirgilCustomParams, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asKey, cKey);
    cSelf->removeString(cKey);
    AS3_RETURN_VOID();
}

AS3_DECL_FUNC(_wrap_VirgilCustomParameters_setData, "(asSelf:int, asKey:ByteArray, asValue:ByteArray):void") {
    AS3_TO_C_PTR(VirgilCustomParams, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asKey, cKey);
    AS3_TO_C_BYTE_ARRAY(asValue, cValue);
    cSelf->setData(cKey, cValue);
    AS3_RETURN_VOID();
}

AS3_DECL_FUNC(_wrap_VirgilCustomParameters_getData, "(asSelf:int, asKey:ByteArray):ByteArray") {
AS3_THROWABLE_SECTION_START
    AS3_TO_C_PTR(VirgilCustomParams, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asKey, cKey);
    VirgilByteArray cValue = cSelf->getData(cKey);
    AS3_RETURN_C_BYTE_ARRAY(cValue);
AS3_THROWABLE_SECTION_END
}

AS3_DECL_FUNC(_wrap_VirgilCustomParameters_removeData, "(asSelf:int, asKey:ByteArray):void") {
    AS3_TO_C_PTR(VirgilCustomParams, asSelf, cSelf);
    AS3_TO_C_BYTE_ARRAY(asKey, cKey);
    cSelf->removeData(cKey);
    AS3_RETURN_VOID();
}

#endif /* AS3_VIRGIL_CUSTOM_PARAMS_HPP */
